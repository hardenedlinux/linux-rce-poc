#!/usr/bin/env python3
"""pktcap.py - AF_PACKET tap on lo, prints TCP SYN-ACKs from port 9700
with ihl != 5 (i.e. built from the dangling options object), hex + text."""
import socket, struct, sys, time

iface = sys.argv[1] if len(sys.argv) > 1 else "lo"
runtime = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind((iface, 0))
s.settimeout(0.5)
t0 = time.time()
n = 0
while time.time() - t0 < runtime:
    try:
        data, addr = s.recvfrom(65535)
    except socket.timeout:
        continue
    if len(data) < 40:
        continue
    ip = data[14:] if addr[2] == 1 else data  # lo has a 14-byte fake ethernet? use addr
    # linux cooked/loopback: on lo, AF_PACKET delivers the raw IP packet with a 14-byte
    # fake ethernet header? Determine by version nibble.
    off = 0
    if (data[0] >> 4) != 4 and (data[14] >> 4) == 4:
        off = 14
    ip = data[off:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        continue
    ihl = (ip[0] & 0xf) * 4
    proto = ip[9]
    if proto != 6 or len(ip) < ihl + 20:
        continue
    sport, dport = struct.unpack("!HH", ip[ihl:ihl+4])
    if sport != 9700 and dport != 9700:
        continue
    n += 1
    if ihl != 20 or n <= 3:
        print("pkt n=%d len=%d ihl=%d sport=%d dport=%d" % (n, len(ip), ihl, sport, dport))
        print("  hex:", ip[:min(len(ip), 240)].hex())
    if n >= 2000:
        break
print("total 9700 pkts seen:", n)
