import os
#!/usr/bin/env python3
"""correlate_trace.py - find UAF reads in a freeopt/rdopt2/kmalloc trace.

Trace lines look like:
  <idle>-0  [003] b.s1. 4205.542686: kmalloc: call_site=... ptr=...
  <idle>-0  [003] b.s1. 4205.5: freeopt: (inet_sock_destruct...) sk=... inet_opt=0x...
  <idle>-0  [003] b.s1. 4205.5: rdopt2: (ip_options_build...) skb=0x... opt=0x... optlen=40

The freed object is ip_options_rcu; ip_options_build receives &opt->opt,
which is base+16.  A read whose base was freed and not reallocated is a
UAF read.
"""
import re
import sys
import collections

line_re = re.compile(
    r"^\s*\S+-\d+\s+\[(\d+)\]\s+\S+\s+([0-9]+\.[0-9]+):\s+"
    r"(kmalloc|freeopt|rdopt2):\s+(.*)$"
)
kv_re = re.compile(r"(\w+)=([^\s]+)")


def ptr(x):
    x = x.strip().rstrip(",")
    try:
        return int(x, 16)
    except ValueError:
        return None


def main(path):
    events = []
    with open(path, errors="replace") as fh:
        for line in fh:
            m = line_re.match(line)
            if not m:
                continue
            cpu = int(m.group(1))
            t = float(m.group(2))
            kind = m.group(3)
            kv = dict(kv_re.findall(m.group(4)))
            if kind == "kmalloc":
                p = ptr(kv.get("ptr", ""))
                if p is None:
                    continue
                events.append((t, cpu, "alloc", p, kv))
            elif kind == "freeopt":
                p = ptr(kv.get("inet_opt", ""))
                if not p:
                    continue
                events.append((t, cpu, "free", p, kv))
            elif kind == "rdopt2":
                o = ptr(kv.get("opt", ""))
                if not o:
                    continue
                events.append((t, cpu, "read", o - 16, kv))

    state = {}
    uaf_cross = []
    uaf_same = []
    read_after_free_total = 0
    optlen_hist = collections.Counter()
    for (t, cpu, kind, base, kv) in events:
        if kind in ("alloc", "free"):
            state[base] = (kind, t, cpu)
        else:
            optlen = int(kv.get("optlen", "0") or 0)
            optlen_hist[optlen] += 1
            st = state.get(base)
            if st and st[0] == "free":
                read_after_free_total += 1
                dt = t - st[1]
                rec = (dt, base, st[2], cpu, optlen, t)
                if st[2] != cpu:
                    uaf_cross.append(rec)
                else:
                    uaf_same.append(rec)

    print(f"events={len(events)} read_after_free={read_after_free_total}")
    print(f"  cross_cpu={len(uaf_cross)} same_cpu={len(uaf_same)}")
    print("optlen histogram:", dict(optlen_hist.most_common(10)))
    for name, arr in (("CROSS-CPU", uaf_cross), ("SAME-CPU", uaf_same)):
        arr.sort()
        for rec in arr[:15]:
            dt, base, fc, rc, ol, t = rec
            print(f"  {name} dt={dt*1e6:.1f}us base={base:#x} free_cpu={fc} "
                  f"read_cpu={rc} optlen={ol}")
    # poison reads regardless of the state machine
    poison = [e for e in events if e[2] == "read"
              and int(e[4].get("optlen", "0") or 0) not in (0, 40)]
    print(f"non-40 optlen reads: {len(poison)}")
    for t, cpu, kind, base, kv in poison[:10]:
        print(f"  optlen={kv.get('optlen')} base={base:#x} cpu={cpu}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else
         os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence", "fragdup.trace"))
