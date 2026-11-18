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
for name in ('page_offset_base','vmemmap_base','_text'):
    if name in s:
        if name in ('page_offset_base','vmemmap_base'):
            print(name,hex(struct.unpack('<Q',rd(s[name],8))[0]),"sym",hex(s[name]))
        else: print(name,hex(s[name]))
