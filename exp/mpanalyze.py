#!/usr/bin/env python3
"""Full-flow analyzer for the mpstorm3 test.

Captures ALL TCP packets involving port 9700 (both directions) while the
storm runs, and classifies each packet's IPv4 RR-option state:

  ptr          - the RR pointer byte (my SYNs/ACKs always send ptr=4)
  recs         - count of slots containing 127.0.0.1 (recordings)
  markers      - count of slots containing my round marker

Key questions this answers:
  Q1: do any SYN (flags=0x02) packets arrive at 9700 with ptr != 4 or
      recs > 0?  -> feedback loop / sender bug
  Q2: do SYN-ACKs appear with ptr > 8 or recs > 1? -> anomalous object
      state (UAF candidate evidence)
  Q3: any 0x6b poison runs -> direct freed-memory read

Run in guest:  sudo python3 /mnt/lab/exp/mpanalyze.py <sport> <secs>
"""
import socket
import struct
import sys
import time

SPORT = int(sys.argv[1])
DPORT = 9700
RUNTIME = float(sys.argv[2])

MARKER = 0x5AA50000 | SPORT
MARKER_BYTES = struct.pack("<I", MARKER)
LOOPBACK = socket.inet_aton("127.0.0.1")

stats = {
    "syn_in": 0, "syn_in_loopstate": 0,
    "ack_in": 0, "ack_in_loopstate": 0,
    "rst_in": 0, "rst_in_loopstate": 0,
    "synack_out": 0, "synack_out_anom": 0,
    "ack_out": 0, "ack_out_anom": 0,
    "rst_out": 0, "rst_out_anom": 0,
    "poison": 0,
}
samples = []


def classify_rr(raw, n):
    """Return (ptr, recs, markers, optbytes) of the RR option or None."""
    if n < 20 or (raw[0] >> 4) != 4:
        return None
    ihl = (raw[0] & 0xF) * 4
    if ihl < 24 or n < ihl:
        return None
    opts = raw[20:ihl]
    if not opts or opts[0] != 7 or opts[1] < 39:
        return None
    ptr = opts[2]
    recs = markers = 0
    for off in range(3, opts[1], 4):
        slot = opts[off:off + 4]
        if slot == b"\x7f\x00\x00\x01":
            recs += 1
        elif slot == MARKER_BYTES:
            markers += 1
    return ptr, recs, markers, opts


s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
s.settimeout(0.5)

t0 = time.monotonic()
while time.monotonic() - t0 < RUNTIME:
    try:
        raw, _ = s.recvfrom(65535)
    except socket.timeout:
        continue
    n = len(raw)
    if n < 40 or (raw[0] >> 4) != 4:
        continue
    ihl = (raw[0] & 0xF) * 4
    if n < ihl + 20:
        continue
    tcp = raw[ihl:ihl + 20]
    sport = (tcp[0] << 8) | tcp[1]
    dport = (tcp[2] << 8) | tcp[3]
    flags = tcp[13]
    if dport == DPORT and sport == SPORT:
        # inbound to listener (from the "client")
        rr = classify_rr(raw, n)
        loopstate = rr and (rr[0] != 4 or rr[1] > 0)
        if flags == 0x02:
            stats["syn_in"] += 1
            if loopstate:
                stats["syn_in_loopstate"] += 1
                if len(samples) < 8:
                    samples.append(("SYN-IN-LOOPSTATE", raw[:100].hex()))
        elif flags & 0x10 and not flags & 0x02:
            stats["ack_in"] += 1
            if loopstate:
                stats["ack_in_loopstate"] += 1
                if len(samples) < 8:
                    samples.append(("ACK-IN-LOOPSTATE", raw[:100].hex()))
        elif flags & 0x04:
            stats["rst_in"] += 1
            if loopstate:
                stats["rst_in_loopstate"] += 1
    elif sport == DPORT and dport == SPORT:
        # outbound from listener (to the "client")
        rr = classify_rr(raw, n)
        anom = rr and (rr[0] > 8 or rr[1] > 1)
        if flags == 0x12:
            stats["synack_out"] += 1
            if anom:
                stats["synack_out_anom"] += 1
                if len(samples) < 16:
                    samples.append(
                        (f"SYNACK-OUT-ANOM ptr={rr[0]} recs={rr[1]} "
                         f"marks={rr[2]}", raw[:100].hex()))
        elif flags & 0x10 and not flags & 0x02:
            stats["ack_out"] += 1
            if anom:
                stats["ack_out_anom"] += 1
                if len(samples) < 16:
                    samples.append(
                        (f"ACK-OUT-ANOM ptr={rr[0]} recs={rr[1]} "
                         f"marks={rr[2]}", raw[:100].hex()))
        elif flags & 0x04:
            stats["rst_out"] += 1
            if anom:
                stats["rst_out_anom"] += 1
        # poison scan on any outbound packet
        if b"\x6b" * 8 in raw[:100]:
            stats["poison"] += 1
            if len(samples) < 20:
                samples.append(("POISON-RUN", raw[:100].hex()))

print(f"=== analyzer: sport={SPORT} marker={MARKER:08x} "
      f"runtime={RUNTIME}s ===")
for k, v in stats.items():
    print(f"  {k:20s} {v}")
print("--- samples ---")
for tag, hx in samples:
    print(f"[{tag}] {hx}")
