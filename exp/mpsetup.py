#!/usr/bin/env python3
"""MPTCP base connection + server-token extraction.

1. Opens a real MPTCP connection (kernel IPPROTO_MPTCP) to the listener.
2. Raw-captures the SYN-ACK's MP_CAPABLE option to get the server key.
3. token = SHA256(server_key)[0:4]  (the server's local token, which the
   server looks up in its token hash when an MP_JOIN SYN carries it).
4. Prints "TOKEN <hex>" and holds the connection open (the token must stay
   registered while the storm runs).

Run in the guest:  sudo python3 /mnt/lab/exp/mpsetup.py 127.0.0.1 9700
"""
import hashlib
import socket
import struct
import sys
import threading
import time

host, port = sys.argv[1], int(sys.argv[2])
IPPROTO_MPTCP = 262
MPTCP_KIND = 30


def find_mpc_key(raw):
    """Extract the 8-byte server key from a SYN-ACK's MP_CAPABLE option."""
    if not raw or len(raw) < 40 or (raw[0] >> 4) != 4:
        return None
    ihl = (raw[0] & 0xF) * 4
    tcp = raw[ihl:ihl + 20]
    if len(tcp) < 14 or tcp[13] != 0x12:      # SYN+ACK
        return None
    off = ihl + 20
    end = min(ihl + 40 + 20, len(raw))        # TCP options region (rough)
    while off < end - 1:
        kind = raw[off]
        if kind == 0:
            break
        if kind == 1:
            off += 1
            continue
        ln = raw[off + 1]
        if ln < 2 or off + ln > len(raw):
            break
        if kind == MPTCP_KIND and ln >= 12:
            # v1 MP_CAPABLE in SYN-ACK: [30][12][ver/flags][key(8)]
            return raw[off + 4:off + 12]
        off += ln
    return None


# raw sniffer: watches the SYN-ACK carrying MP_CAPABLE
got_key = {}
done = threading.Event()


def sniffer(sport):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.settimeout(3.0)
    try:
        while not done.is_set():
            try:
                raw, _ = s.recvfrom(8192)
            except socket.timeout:
                return
            ihl = (raw[0] & 0xF) * 4 if raw else 20
            tcp = raw[ihl:ihl + 20]
            if len(tcp) >= 14 and tcp[13] == 0x12 and \
               (tcp[0] << 8) | tcp[1] == port and \
               (tcp[2] << 8) | tcp[3] == sport:
                key = find_mpc_key(raw)
                if key:
                    got_key["key"] = key
                    done.set()
                    return
    finally:
        s.close()


# 1. real MPTCP connection (kernel does the MP_CAPABLE dance)
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP)
c.settimeout(5.0)
c.bind(("127.0.0.1", 0))                 # fix the port BEFORE connecting
sport = c.getsockname()[1]
threading.Thread(target=sniffer, args=(sport,), daemon=True).start()
c.connect((host, port))
done.wait(timeout=5.0)

key = got_key.get("key")
if not key:
    print("FAILED to capture MP_CAPABLE key from SYN-ACK", file=sys.stderr)
    sys.exit(1)

token = hashlib.sha256(key).digest()[:4]
print(f"TOKEN {token.hex()}  (key {key.hex()}, sport {sport})")
sys.stdout.flush()
with open("/tmp/mptcp_token", "w") as fh:   # for the storm driver
    fh.write(token.hex())

# 2. hold the connection so the server-side token stays registered
c.settimeout(None)
try:
    while True:
        time.sleep(3600)
except KeyboardInterrupt:
    pass
