#!/usr/bin/env python3
"""Send ONE MP_JOIN SYN (RR marker IP opts + MP_JOIN TCP opt) and dump
every packet that comes back, fully parsed."""
import hashlib
import socket
import struct
import sys
import time

host, port = sys.argv[1], int(sys.argv[2])
token_hex = sys.argv[3]
IPPROTO_MPTCP = 262


def csum(data):
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


sport = 34567
token = bytes.fromhex(token_hex)
marker = 0xABCD0001

# IP options: RR with marker
ipopts = bytearray(40)
ipopts[0] = 7; ipopts[1] = 39; ipopts[2] = 4
for off in (27, 31, 35):
    struct.pack_into("!I", ipopts, off, marker)

# TCP options: MP_JOIN SYN
mpj = bytes([30, 12, 0x10, 0x00]) + token + bytes([0x11, 0x22, 0x33, 0x44])

ip = bytearray(60 + 20 + 12)
ip[0] = 0x4F
struct.pack_into("!H", ip, 2, 60 + 20 + 12)      # total len
ip[4] = 0xAB; ip[5] = 0xCD                        # id
ip[6] = 0x40                                       # DF
ip[8] = 64; ip[9] = 6
ip[12:16] = socket.inet_aton("127.0.0.1")
ip[16:20] = socket.inet_aton("127.0.0.1")
ip[20:60] = ipopts

tcp = memoryview(ip)[60:]                # view, NOT a copy
struct.pack_into("!HH", tcp, 0, sport, port)
struct.pack_into("!I", tcp, 4, 0x1000)             # seq
tcp[12] = (5 + 12 // 4) << 4
tcp[13] = 0x02
tcp[14:16] = b"\xff\xff"
tcp[20:32] = mpj

# checksums
struct.pack_into("!H", ip, 10, 0)
c = csum(bytes(ip[:60]))
struct.pack_into("!H", ip, 10, c)
ph = bytes(ip[12:20]) + struct.pack("!BBH", 0, 6, 32)
struct.pack_into("!H", tcp, 16, 0)
c = csum(ph + bytes(tcp[:32]))
struct.pack_into("!H", tcp, 16, c)

pkt = bytes(ip)
print(f"sending {len(pkt)} bytes: {pkt.hex()}")

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.sendto(pkt, (host, 0))

s.settimeout(2.0)
deadline = time.monotonic() + 2.0
while time.monotonic() < deadline:
    try:
        raw, _ = s.recvfrom(8192)
    except socket.timeout:
        break
    ihl = (raw[0] & 0xF) * 4
    if len(raw) < ihl + 20:
        continue
    tcp_r = raw[ihl:ihl + 20]
    sp = (tcp_r[0] << 8) | tcp_r[1]
    dp = (tcp_r[2] << 8) | tcp_r[3]
    if sp != port or dp != sport:
        continue
    print(f"reply: len={len(raw)} ihl={ihl} flags={tcp_r[13]:02x}")
    print(f"  full: {raw.hex()}")
    if ihl > 20:
        print(f"  ip opts: {raw[20:ihl].hex()}")
    doff = (tcp_r[12] >> 4) * 4
    if doff > 20:
        print(f"  tcp opts: {raw[ihl+20:ihl+doff].hex()}")
