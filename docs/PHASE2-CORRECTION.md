# Phase 2 correction — random-kmalloc bucket constant

The Phase 2 `lab/cache_match.py` used `G = 0x9E3779B97F4A7C15`. That is the
2^64 complement of the kernel's `GOLDEN_RATIO_64` (`0x61C8864680B583EB`,
include/linux/hash.h), which `hash_64()` actually multiplies by. The prior
repo's AGENTS.md §7a records the same correction after empirical slabinfo
checks. The "MATCH boot=11" produced by the old constant is therefore not a
valid pair.

`lab/cache_match.py` is now fixed (backup: `cache_match.py.bak`) and uses the
runtime kallsyms call sites:

```
victim  = tcp_v4_route_req + 0x91
reclaim = tcp_reqsk_record_syn + 0x77
bucket  = ((call_site ^ random_kmalloc_seed) * 0x61C8864680B583EB) >> 60
```

`lab/cache_match_fixed.py` is the standalone corrected checker;
`lab/find-match-fixed.sh` searches boots on the isolated instrumented role
(`:2101`, tap-cve-ins) so the legacy/other-session loops cannot reboot it.
