#!/usr/bin/env python3
"""kcore_read.py - read a kernel VA through /proc/kcore (ELF64 core)."""
import struct, sys

va = int(sys.argv[1], 0)
n = int(sys.argv[2]) if len(sys.argv) > 2 else 32
f = open("/proc/kcore", "rb")
hdr = f.read(64)
assert hdr[:4] == b"\x7fELF" and hdr[4] == 2, "not ELF64"
e_phoff = struct.unpack_from("<Q", hdr, 0x20)[0]
e_phentsize = struct.unpack_from("<H", hdr, 0x36)[0]
e_phnum = struct.unpack_from("<H", hdr, 0x38)[0]
f.seek(e_phoff)
found = False
for i in range(e_phnum):
    ph = f.read(e_phentsize)
    p_type, p_flags = struct.unpack_from("<II", ph, 0)
    p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack_from("<QQQQ", ph, 8)
    if p_type == 1 and p_vaddr <= va < p_vaddr + p_filesz:
        f.seek(p_offset + (va - p_vaddr))
        data = f.read(n)
        print("read %d bytes at VA 0x%x:" % (len(data), va))
        for off in range(0, len(data), 16):
            print("  %04x: %s" % (off, data[off:off+16].hex()))
        found = True
        break
if not found:
    print("VA 0x%x not mapped in kcore" % va)
