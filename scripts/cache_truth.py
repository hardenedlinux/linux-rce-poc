#!/usr/bin/env python3
"""cache_truth.py - ground-truth the random-kmalloc bucket formula.

Run on the guest as root.  Starts a TCP_SAVE_SYN listener and a plain TCP
listener, sends one SYN to each (one no-IP-option SYN with 40B TCP options,
one SYN with an RR IP option), and diffs the active-object counts of every
kmalloc[-rnd-NN]-96 cache.  Prints the observed cache increments and the
formula's predicted victim/saved_syn indices for the same boot.
"""
import os
import sys
import socket
import struct
import threading
import time

SLAB = "/sys/kernel/slab"
PORTS = (9801, 9802)
held = []


def csum(d):
    if len(d) & 1:
        d += b"\0"
    s = 0
    for i in range(0, len(d), 2):
        s += (d[i] << 8) | d[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def read_counts():
    out = {}
    for line in open("/proc/slabinfo"):
        f = line.split()
        if len(f) < 3:
            continue
        name = f[0]
        if name == "kmalloc-96" or (name.startswith("kmalloc-rnd-") and name.endswith("-96")):
            try:
                out[name] = int(f[1])   # active_objs
            except ValueError:
                pass
    return out


def listener(port, save_syn):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if save_syn:
        s.setsockopt(socket.IPPROTO_TCP, 27, 1)   # TCP_SAVE_SYN
    s.bind(("127.0.0.1", port))
    s.listen(16)
    held.append(s)
    while True:
        try:
            c, _ = s.accept()
            held.append(c)                      # hold accepted too
        except OSError:
            return


def send_syn(dport, ip_opts, tcp_opts):
    sport = 40000 + (dport % 1000)
    seq = 0x12340000 + dport
    ihl = 20 + len(ip_opts)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, (5 + len(tcp_opts) // 4) << 4,
                      0x02, 65535, 0, 0) + tcp_opts
    pseudo = socket.inet_aton("127.0.0.1") + socket.inet_aton("127.0.0.1") + \
             struct.pack("!BBH", 0, 6, len(tcp))
    c = csum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", c) + tcp[18:]
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x40 | (ihl // 4), 0, ihl + len(tcp),
                               0x4242, 0x4000, 64, 6, 0,
                               socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1")))
    ip[20:] = ip_opts
    ic = csum(bytes(ip))
    ip[10:12] = struct.pack("!H", ic)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(bytes(ip) + tcp, ("127.0.0.1", 0))
    s.close()


def formula():
    syms = {}
    for line in open("/proc/kallsyms"):
        p = line.split()
        if len(p) >= 3:
            try:
                syms[p[2]] = int(p[0], 16)
            except ValueError:
                pass
    # seed via /proc/kcore, same as cache_match_fixed.py
    import struct as st
    f = open("/proc/kcore", "rb")
    h = f.read(64)
    off = st.unpack_from("<Q", h, 0x20)[0]
    es = st.unpack_from("<H", h, 0x36)[0]
    en = st.unpack_from("<H", h, 0x38)[0]
    f.seek(off)
    seed = None
    while en:
        ph = f.read(es); en -= 1
        t = st.unpack_from("<I", ph, 0)[0]
        po, pv, pp, pf = st.unpack_from("<QQQQ", ph, 8)
        if t == 1 and pv <= syms["random_kmalloc_seed"] < pv + pf:
            f.seek(po + syms["random_kmalloc_seed"] - pv)
            seed = int.from_bytes(f.read(8), "little"); break
    G = 0x61C8864680B583EB; M = (1 << 64) - 1
    def idx(c):
        return (((c ^ seed) & M) * G & M) >> 60
    return seed, idx(syms["tcp_v4_route_req"] + 0x91), idx(syms["tcp_reqsk_record_syn"] + 0x77)


def main():
    seed, vi, si = formula()
    print(f"seed=0x{seed:016x} predicted victim_idx={vi} saved_idx={si}")
    for p, s in zip(PORTS, (True, False)):
        threading.Thread(target=listener, args=(p, s), daemon=True).start()
    time.sleep(0.5)
    before = read_counts()
    # RR option, len 39, ptr 4 (victim ip_options_rcu)
    rr = bytes([7, 39, 4]) + b"\x00" * 36
    # no IP options, 40B TCP options (saved_syn; MSS+SACK+TS+padding)
    topts = struct.pack("!BBH", 2, 4, 1460) + struct.pack("!BB", 4, 2) + \
            b"\x01\x01" + struct.pack("!BBII", 8, 10, 0x53535353, 0) + b"\x01" * 22
    # victim: normal TCP connect with IP_OPTIONS (kernel builds the SYN)
    v = socket.socket()
    v.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, rr)
    v.connect(("127.0.0.1", 9802))
    held.append(v)
    # saved_syn: raw half-open SYN (no final ACK -> req holds saved_syn)
    send_syn(9801, b"", topts)
    time.sleep(1.0)
    after = read_counts()
    os.system("ss -tn state syn-recv 2>/dev/null | head -20")
    os.system("nstat -az 2>/dev/null | grep -E 'TcpAttemptFails|ListenOverflows|TCPReqQFull|Syncookies' | head")
    os.system("grep -E 'kmalloc(-rnd-[0-9]+)?-96' /proc/slabinfo | head -30")
    os.system("grep -H -E 'tcp_v4_route_req|tcp_reqsk_record_syn' /sys/kernel/slab/kmalloc*96/alloc_calls 2>/dev/null")
    print("cache deltas:")
    for k in sorted(set(before) | set(after)):
        d = after.get(k, 0) - before.get(k, 0)
        if d:
            print(f"  {k}: +{d}")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
