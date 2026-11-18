#!/usr/bin/env python3
"""po_base.py - print this boot's page_offset_base (root).
Reads the kernel variable via /proc/kallsyms + /proc/kcore."""
import struct, sys

def kcore_reader():
    f = open("/proc/kcore", "rb")
    hdr = f.read(64)
    assert hdr[:4] == b"\x7fELF" and hdr[4] == 2
    e_phoff = struct.unpack_from("<Q", hdr, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", hdr, 0x36)[0]
    e_phnum = struct.unpack_from("<H", hdr, 0x38)[0]
    f.seek(e_phoff)
    segs = []
    for i in range(e_phnum):
        ph = f.read(e_phentsize)
        p_type = struct.unpack_from("<I", ph, 0)[0]
        p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<QQQQ", ph, 8)
        if p_type == 1:
            segs.append((p_offset, p_vaddr, p_filesz))
    def read(va, n):
        for off, v, sz in segs:
            if v <= va < v + sz:
                f.seek(off + (va - v))
                return f.read(n)
        return None
    return read

addr = None
for line in open("/proc/kallsyms"):
    p = line.split()
    if len(p) >= 3 and p[2] == "page_offset_base":
        addr = int(p[0], 16)
        break
if addr is None:
    print("no page_offset_base in kallsyms", file=sys.stderr)
    sys.exit(1)
read = kcore_reader()
data = read(addr, 8)
base = struct.unpack("<Q", data)[0]
print(hex(base))
