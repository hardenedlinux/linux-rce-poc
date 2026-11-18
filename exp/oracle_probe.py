#!/usr/bin/env python3
"""Self-contained packet-level RR-marker oracle probe.

Sends SYNs with a marker in the RR option tail and inspects SYN-ACKs.
(Loops the project's marker-reuse detection as a wire-side tool; the
kernel-side kprobe detector in AGENTS.md §4.3 is the authoritative one —
see AGENTS.md G1/G2 for why packet-level detection is limited.)

Self-contained on purpose: no import from the tc4dy toolkit.

Run as root in the guest:
  sudo python3 /mnt/lab/exp/oracle_probe.py <host> <port>
"""
import secrets
import socket
import struct
import time

OPT_EOL = 0
OPT_RR = 7
# Marker slots in the RR option (byte offsets within the 40-byte option):
# slots 1..3 -> option bytes 7..18
RR_MARKER_OFFS = (7, 11, 15)


def _checksum(data):
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def rr_options(token):
    buf = bytearray(40)
    buf[0] = OPT_RR
    buf[1] = 39
    buf[2] = 4
    for off in RR_MARKER_OFFS:
        struct.pack_into("<I", buf, off, token)
    return bytes(buf)


def compose_syn(src, dst, sport, dport, seq, options=b""):
    ihl = 5 + len(options) // 4
    total = ihl * 4 + 20
    ip = bytearray(struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ihl, 0, total, secrets.randbits(16), 0x4000, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst)))
    ip += options
    tcp = bytearray(struct.pack(
        "!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x02, 65535, 0, 0))
    pseudo = bytes(ip[12:20]) + struct.pack("!BBH", 0, 6, len(tcp))
    struct.pack_into("!H", tcp, 16, _checksum(pseudo + bytes(tcp)))
    struct.pack_into("!H", ip, 10, _checksum(bytes(ip)))
    return bytes(ip) + bytes(tcp)


def read_rr_token(raw, sport=None):
    """Read the marker token from an echoed RR option.

    - poison (all 0x6b) -> 0x6B6B6B6B
    - consistent non-zero candidates -> that token (clean or foreign)
    - mixed/absent -> None
    When sport is given, only SYN-ACKs addressed to that port are parsed.
    """
    if not raw or len(raw) < 40 or (raw[0] >> 4) != 4:
        return None
    ihl = (raw[0] & 0xF) * 4
    if ihl < 20 or ihl > 60 or len(raw) < ihl:
        return None
    tcp = raw[ihl:ihl + 20]
    if len(tcp) < 20:
        return None
    if sport is not None:
        dport = struct.unpack_from("!H", tcp, 2)[0]
        if dport != sport or tcp[13] != 0x12:
            return None
    opts = raw[20:ihl]
    off = 0
    while off < len(opts):
        kind = opts[off]
        if kind == OPT_EOL:
            break
        if kind == 1:
            off += 1
            continue
        if off + 1 >= len(opts):
            break
        ln = opts[off + 1]
        if ln < 2 or off + ln > len(opts):
            break
        if kind == OPT_RR and ln >= 39:
            tail = opts[off + 7:off + 19]
            if b"\x6b" * 12 == tail:
                return 0x6B6B6B6B
            cands = []
            for moff in RR_MARKER_OFFS:
                tok = struct.unpack_from("<I", opts, off + moff)[0]
                if tok and tok not in cands:
                    cands.append(tok)
            return cands[0] if len(cands) == 1 else None
        off += ln
    return None


def probe(host, port, rounds=20, timeout=1.0):
    ok_same = foreign = poison = no_reply = 0
    for i in range(rounds):
        token = (0xAABB0000 | i) or 1
        sport = 49100 + i
        pkt = compose_syn("127.0.0.1", host, sport, port, 0x500 + i,
                          rr_options(token))
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.settimeout(timeout)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        try:
            s.sendto(pkt, (host, 0))
            got = None
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    raw, _ = s.recvfrom(4096)
                except socket.timeout:
                    break
                got = read_rr_token(raw, sport=sport)
                if got is not None:
                    break
            if got is None:
                no_reply += 1
            elif got == 0x6B6B6B6B:
                poison += 1
                print(f"[!!] POISON read: sent {token:08x}")
            elif got == token:
                ok_same += 1
            else:
                foreign += 1
                print(f"[!!] MARKER REUSE: sent {token:08x} got {got:08x}")
        finally:
            s.close()
    print(f"same={ok_same}/{rounds} foreign={foreign} poison={poison} "
          f"no_reply={no_reply}")


if __name__ == "__main__":
    import sys
    probe(sys.argv[1], int(sys.argv[2]))
