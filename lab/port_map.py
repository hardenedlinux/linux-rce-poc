#!/usr/bin/env python3
"""port_map.py <cpu> - read a rec2 trace on stdin, print ports whose dominant
CPU is <cpu>, comma-separated (cap 64)."""
import re
import sys
from collections import Counter, defaultdict

want = int(sys.argv[1]) if len(sys.argv) > 1 else 0
m = defaultdict(Counter)
for line in sys.stdin:
    if 'rec2:' not in line:
        continue
    c = re.search(r'\[(\d+)\]', line)
    p = re.search(r'p12=(\d+)', line)
    if not c or not p:
        continue
    v = int(p.group(1))
    port = ((v & 0xff) << 8) | (v >> 8)
    m[port][int(c.group(1))] += 1
ports = sorted(p for p, c in m.items() if c.most_common(1)[0][0] == want)
print(','.join(str(p) for p in ports[:64]))
print("n=%d/%d" % (len(ports), len(m)), file=sys.stderr)