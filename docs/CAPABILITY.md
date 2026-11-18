# CVE-2026-98432 — Capability Report (2026-11-12, updated 2026-11-19)

Scope: remote exploitation of the Linux IPv4 TCP `ireq_opt`/`inet_opt` UAF
against a stock Ubuntu 24.04 target (`6.8.0-106-generic`, default cmdline,
no `slub_debug`). Authorized local VM lab only. CVE record, patch and
references: [`CVE.md`](CVE.md).

## End goal and current status

**End goal:** a default-settings RCE on Ubuntu 24.04 over both reachable
paths — MPTCP and plain TCP (e.g. `sshd`) — with no target-side root setup,
no kprobes, no custom listeners, no root AF_PACKET ring, no reboot lottery,
and a surviving target.

**Current status:** the MPTCP full chain is demonstrated in the lab, but only
with the target-side instrumentation and service assistance listed below.
Plain TCP is not reached (request-path refcount serialization; 0 genuine hits
in 16M+ attempts). The wire-only KASLR slide is demonstrated; a
wire-derived `G` is demonstrated separately (its ring allocation is still
root). This report is the detailed record of what is proven, what is not,
and why.

## Executive summary

**What is proven**

* Full chain on the stock kernel **in the instrumented lab**: UAF → CPU-local
  reclaim → controlled OOB into `skb_shared_info` → fake `sk_buff` →
  `call_usermodehelper_exec` → **remote root reverse shell**
  (`root@cve-instr:/#`).
* **Wire-only KASLR slide**: an `iomap_dio` neighbour over-read leaks
  `dops` (`ext4_dio_write_ops`); the slide and `EX`/`WK` are derived from
  wire bytes plus the public kernel image, with no `/proc/kallsyms`.
* **Wire-derived controlled page `G`**: a `pg_vec` neighbour over-read
  leaks page-aligned ring addresses with **zero kprobes**; the `pg_vec`
  allocation itself still comes from the root AF_PACKET ring.
* **Zero-kprobe payload fire**: an earlier no-kprobe run reached
  `call_usermodehelper_exec_work` once, then crashed; the raw log is not
  included in this package. This is a partial result, not a stable root.

**What is not proven / what remains**

* The race is only reliable with **46 target-side stretch kprobes** +
  `rdopt2`. Natural alternatives (RPS-IPI flood on the reader CPU, 84k
  virtio-blk IRQs/s on the reader CPU, dense dup sampling) produced **0
  over-reads in ~4.6 ks** of zero-kprobe attempts.
* `G` in the latest root shell still uses an in-VM `page_offset_base`
  (kcore) + pagemap read. A single-boot wire-slide **and** wire-`G` run
  needs a 4-way random-kmalloc match (`victim == saved_syn == iomap_dio ==
  pg_vec`); the 3000-boot hunt completed with **no quad** (`NO_QUAD_IN_3000`).
  The wire-`G` method itself is demonstrated separately via a `pg_vec`
  over-read; combining both wire-derived stages in one boot remains a stretch
  goal.
* The controlled page uses a **root AF_PACKET TX ring** (`CAP_NET_RAW`).
* The target must run the **MPTCP keeper + TCP_SAVE_SYN listeners**
  (service-assisted model).
* RPS/RFS + 4-queue NIC was used; discounted as a lab artifact (hardware
  RSS is the real-world equivalent).

**Honest conclusion:** this is a **stock-kernel lab PoC with a target-side
instrumentation dependency**, not a deployable default-settings production
exploit. `#2` (in-VM address reads) is solved; `#1` (the race amplifier) is
not, and the two alternative routes are blocked (see below).

## Current best chain

1. **Boot hunt**: a `RANDOM_KMALLOC_CACHES` match between the victim
   `save_options` cache and a persistent reclaim bucket. The reliable
   campaign uses `user_key_payload` or `unix_address`; `saved_syn` (and
   `iomap_dio` for the wire slide) are used by the leak-specific hunts.
2. **Addresses**
   * Slide: over-read an `iomap_dio` neighbour; `nb[8:16]` = `dops` =
     `ext4_dio_write_ops + slide`. Resolve with `scripts/wire_slide.py`.
   * `EX`/`WK` = static `call_usermodehelper_exec[_work]` + slide.
   * `G`: `lab/ringone.py` (pagemap PFN + `page_offset_base`) or a wire
     `pg_vec` over-read.
3. **Fake skb** in the pinned ring page: `destructor = EX`,
   `work.func = WK`, `_skb_refdst` = a fake dst with a large refcount so
   `skb_release_head_state` calls `dst_release()` first and the destructor
   gets `wait = UMH_NO_WAIT` (RSI=0).
4. **Fire**: IPOPT4 `saved_syn` spray + fragmented dup-SYN reader
   (source with F ≠ L), reclaiming the freed victim slot with a large
   `optlen`; the OOB copy plants `nr_frags=0`, `tx_flags=0`,
   `frag_list=G+0x10`.
5. The skb free calls the destructor → workqueue → `call_usermodehelper`
   → `/bin/bash -c "… reverse shell …"` → root.

## Evidence

| Evidence | Meaning |
|---|---|
| `evidence/ROOT-wireslide-revshell-1794459232.txt` | **root shell with wire-derived KASLR slide** |
| `evidence/wireslide-root-serial-1794459232.log` | serial for that fire |
| `evidence/WIRE-SLIDE-1794458983.txt` | wire slide derivation |
| `evidence/overread-wire-slide-iomap-1794458983.pcap` | over-read with `dops` |
| `evidence/overread-nokprobe-pgvec-1794369656.pcap` | **zero-kprobe wire `G`** |
| `evidence/ROOT-revshell-1794401462.txt` | earlier remote root reverse shell |
| `evidence/ROOT-shell-1794343072.txt` | SUID root file proof |
| `evidence/double2-root-fire-1794401462.log`, `evidence/ROOT-revshell-*` | serial/log pairs |
| `evidence/payload-*panic*.log` | intermediate crash/geometry evidence |
| `evidence/REPRO-libvirt-20261118.txt` | independent libvirt re-run: root, SUID, alive at 20 s and beyond 5 min |

### Independent re-run (2026-11-18)

A fresh libvirt run booted the same stock 6.8.0-106 image (4 vCPU, 4 GB,
4-queue virtio NIC + RPS, 9p share) and reproduced the chain on the fifth
boot-hunt boot: seed `0x4ab38ffb48e8e4a`, victim bucket `key`, source `.11`,
F=0/L=2. The attacker handler received `uid=0(root)` and `SHELL_OK`,
`/tmp/rootbash` was SUID root, and the target stayed reachable at the 20 s
checkpoint and beyond 5 minutes. The orchestrator used `virsh` instead of
`lab/launch.sh` because the verification host had no passwordless sudo for
tap setup; the exploit sources/binaries and target-side scripts were
unchanged. Evidence: `evidence/REPRO-libvirt-20261118.txt`.

## Dependency matrix

| Item | Needed? | Default? | Status |
|---|---|---|---|
| Stock kernel / no slub_debug | yes (and met) | yes | done |
| Wire-only KASLR slide | yes | — | **done** |
| Wire-derived `G` | yes | — | demonstrated separately (`pg_vec` over-read; ring still root) |
| in-VM `kallsyms` | no longer | no | **removed** |
| in-VM `kcore`/pagemap for `G` | used by the latest root | no | wire `G` demonstrated; combined single-boot run is a stretch goal |
| 46 stretch kprobes + `rdopt2` | **yes** | no | **blocker (#1)** |
| Root `AF_PACKET` ring | yes | no | open (#4) |
| MPTCP/SAVE_SYN listeners | yes | no | open (#5) |
| RPS/RFS + 4-queue | used | no | discounted (RSS equivalent) |

## Negative results (important)

* **Plain TCP / sshd (#5)**: the request-path UAF is **refcount-serialized**
  (`tcp_v4_send_synack` holds a request ref; `tcp_v4_reqsk_destructor` runs
  after the reader). Prior work: **0 genuine hits in 16M+ attempts**
  (`PLAN.md` §5.1, `exp_tcp.c` header). sshd cannot be the target.
* **Data-TX reader** (`ip_queue_xmit` on a JOIN subflow): joins establish
  (`jsyn == jack`), but the stock 6.8 kernel exposes only
  `net.mptcp.scheduler = default` and ships **no `mptcp_sched_roundrobin`**.
  Base-window starvation (`BASE_STARVE`) reduced base data to 3 packets,
  but the joins still carried ~20 packets (`marked=0`, `xflow=0`). The
  reader is not reachable on default 6.8.
* **Natural race amplifiers**: RPS-IPI flood on `L`, 84k virtio-blk
  IRQs/s on `L`, dense dup sampling (`MIX_K=64`, 4 µs) → **0 over-reads**
  in ~4.6 ks. The kprobe `int3` stretch is doing specific work.

## Reproduction (high level)

```sh
# reliable path: boot hunt + configure + F/L + ringone + sprays + probes + fire
USABLE_BUCKETS=key,unix bash lab/campaign.sh 2

# leak-specific hunts (optional):
bash lab/find-match-double.sh 300        # victim == saved_syn
bash lab/find-match-iomap.sh 400         # + iomap_dio (wire slide)
bash lab/find-match-quad.sh 3000         # + pg_vec (wire slide + wire G)

# on a matched boot:
#   configure network/RPS/listeners/token
#   measure F/L, choose a source with F != L
#   slide leak: lab/dio_spray.py <F> /tmp/diofile 8
#               + saved_syn leak + tcpdump "ip[20:2]=<spray_port>"
#               + scripts/wire_leak_parse.py <pcap> <port_hex> 0
#               + scripts/wire_slide.py <leaked dops>
#   G:          lab/ringone.py <page_offset_base> <EX> <WK> <cmd>
#   fire:       mpstorm3_mix4 with SPRAY_IPOPT4=1, PAYLOAD_FRAG=S
#               (probe-stretched 46+rdopt2)
```

## Roadmap

1. **4-way hunt** — completed as `NO_QUAD_IN_3000`; a single-boot
   wire-slide + wire-`G` root shell remains a boot-lottery stretch goal.
2. **Capability report** — this document, updated 2026-11-19.
3. **#4** unprivileged controlled-page primitive (or a stock CAP_NET_RAW
   service) — hard, separate research; this is required for a
   default-settings chain.
4. **#1** natural race amplifier; only revisit if a target kernel/scheduler
   supports the data-TX reader (`mptcp_sched_roundrobin`) or a natural
   amplifier is found.
5. **Plain TCP** — find a trigger/reader that is not serialized by the request
   reference, so ordinary services such as `sshd` become reachable.
6. **Boot-agnostic reclaim + non-destructive payload** — cover all 16
   random-kmalloc buckets and avoid or repair the fake skb's invalid free.

## Update: 4-way hunt result (3000 boots)

The `find-match-quad.sh 3000` campaign completed: **NO_QUAD_IN_3000**.
Observed rates over 3000 boots:

| Match | Rate |
|---|---|
| `victim == saved` | 1/13.6 |
| `victim == iomap` | 1/17.9 |
| `victim == pgvec` | 1/17.2 |
| best triple `v==s==p` | 1/250 |
| mean triple | 1/316 |
| implied `QUAD` | ~1/4000–1/6000 |

No quad in 3000 boots is consistent with chance (~47–60%). A ~12,000-boot
run would give ~90–95% confidence (multi-day). Note the quad only removes
the `page_offset_base`/pagemap read used for `G`; the wire-`G` method is
already demonstrated separately (`overread-nokprobe-pgvec-*.pcap`). The
deliverable therefore stands: **wire-slide root shell** + separately
demonstrated **wire-derived `G`**; the single-boot fully-wire-addressed run remains
a boot-lottery stretch goal.

## Real-world realism gaps (2026-11-17)

The lab methodology is **not** a realistic live-target exploit:

1. **Boot lottery (fatal for a live target).** Each reclaim object
   (`saved_syn`, `user_key_payload`, `unix_address`) is allocated at a
   *different* kmalloc call site than the victim (`ireq_opt`), so
   `RANDOM_KMALLOC_CACHES` puts a given object and the victim in different
   cache buckets on ~15/16 boots; the two reliable buckets give 2/16
   coverage. The lab reboots the target thousands of times to find a
   matching boot (2-way, 3-way, 4-way). A real target has **one fixed boot**;
   you cannot reboot it to win the lottery.
2. **Target panic.** The fake `sk_buff`'s release path can invalid-`kfree` a
   pointer inside the ring page and emit a `free_large_kmalloc` warning; four
   archived fires panic at 335–419 s, while the stop-on-connect/containment
   runs (including the 2026-11-18 re-run) survived beyond 5 minutes. Survival
   is therefore not guaranteed: a real exploit must avoid or repair the
   invalid free, not merely race the shell out before the panic.
3. **Kprobe stretch.** Absent on production (see above).
4. **Root AF_PACKET ring / custom listeners.** Non-default.

### What a live-target exploit actually needs

A. **Boot-agnostic reclaim** — one of:
   * a **multi-bucket spray**: reclaim objects from N distinct kmalloc call
     sites, each with a controllable large byte at +24 and controlled bytes
     at the `skb_shared_info` offsets, covering all 16 random-cache
     buckets (`saved_syn` and `user_key_payload` are two candidates;
     `user_key_payload` puts a controlled `data[0]` at +24 and controls
     `neighbour+82..95` via `data[58..71]`);
   * a **same-call-site** reclaim with a large `optlen` (none found:
     `inet_opt.optlen <= 40`, too short to reach `shinfo` ~146 bytes away);
   * a per-boot **bucket-discovery** leak (requires the race).
B. **Non-destructive payload** — repair or skip the fake skb's `kfree`
   (`skb_free_head`/`kfree_skbmem`) so the target survives.
C. A **natural race** (still unsolved, #1).

Conclusion: the current result proves the vulnerability and the full chain
on a *matching* boot, but it is a lab PoC. A live-target exploit requires
(A), (B) and (C); (A) is the next priority because the boot lottery is the
most fundamental mismatch with real-world exploitation.

## Second reclaim bucket: user_key_payload -> root shell (boot 11)

Boot 11 (`seed=0x53916c81df400919`, `victim == user_preparse == 13`).
`user_key_payload` is `24 + 72 = 96` B, allocated at `user_preparse+0x36` —
a **different random-kmalloc bucket** than `saved_syn`. Layout:
`rcu` 0..15, `datalen` 16..17, `data` 24..95. Template:

    data[0]      = 160    -> object+24 = optlen (covers frag_list at
                             source offset 152, stops before destructor_arg 184)
    data[56..59] = 0      -> neighbour+80..83: shinfo flags/meta_len/nr_frags/tx_flags
    data[64..71] = S      -> neighbour+88..95: frag_list = fake skb base

`exp/keyspray.c` churns KEYCTL_UPDATE on the victim CPU (~65k allocations/s;
193 live keys due to the per-user key quota).  The fire uses the storm with
`spray_sport=0` / huge spray spacing (internal saved-SYN spray disabled), so
the key payloads are the only kmalloc-96 reclaim.

Result: **root reverse shell** (`root@cve-instr:/#`).
Evidence: `evidence/ROOT-keybucket-revshell-*.txt`,
`evidence/keybucket-root-serial-*.log`.

### Why this matters

The boot lottery is now **two buckets** (`saved_syn`, `user_key_payload`).
The same fully-controlled 96-byte-buffer reclaim can be replicated from more
call sites (`ip_sf_socklist`/IP_MSFILTER, `ipv6_txoptions`, `tcp_md5sig_key`,
`unix_address`, `simple_xattr`, bpf map value, io_uring register arrays, …).
Covering all 16 buckets would remove the per-boot dependency entirely: one
live target, one shot, no reboot. The race still needs the kprobe stretch
(#1), and the fake-skb release can still panic later (#B); stop-on-connect
and containment reduced but did not eliminate that risk.

## Third reclaim bucket: unix_address -> root shell (boot 3)

Boot 3 (`seed=0xecba01de4f27ee97`, `victim == unix_create_addr == 1`).
`struct unix_address` is `8 + len`; an abstract `AF_UNIX` bind with
`addrlen=88` gives 96 B.  Allocation site `unix_create_addr+0x29`
(a distinct random-kmalloc bucket).  Layout: refcnt 0..3, len 4..7,
name 8..95 (family 8..9, sun_path 10..95).  Template:

    sun_path[14]      -> object+24 = optlen (160)
    sun_path[72/73]   -> object+82/83 = nr_frags/tx_flags (0)
    sun_path[78..85]  -> object+88..95 = frag_list = S

`exp/unixspray.c` binds 500 abstract sockets, then churns bind/close
(4 instances, ~10k/s total, pinned to the victim CPU).  Result:
**root reverse shell**.

### Bucket coverage so far (proven)

| # | Object | Allocation site | Root shell |
|---|---|---|---|
| 1 | saved_syn | tcp_reqsk_record_syn | yes |
| 2 | user_key_payload | user_preparse+0x36 | yes |
| 3 | unix_address | unix_create_addr+0x29 | yes |

Additional reachable candidates (each one bucket unless noted):
`sock_kmalloc+0x42` (`ip_sf_socklist`/IP_MSFILTER, one bucket for all
sock_kmalloc users), `io_uring` registered buffers/files, `ipv6_txoptions`
(check whether it uses sock_kmalloc), plus a systematic `kmalloc(96)`
call-site search.  Covering all 16 buckets removes the per-boot dependency:
one live target, one shot, no reboot.

## Combined multi-bucket fire -> root shell (boot 11)

Boot 11 (`seed=0xb77e57b23e3f5c83`, `victim=6 saved=2 key=6 unix=11`).
All three sprays were started on the victim CPU F at once:

* `saved_syn` (storm `SAVED_SYN_SPRAY=1 SPRAY_IPOPT4=1 PAYLOAD_FRAG=S`,
  192.x @ the F port),
* `user_key_payload` (keyspray, 193 keys),
* `unix_address` (4 x unixspray, 500 sockets each).

The **key** bucket matched and reclaimed; the saved/unix sprays lived in
other random caches and were harmless.  Result: **root reverse shell**.

This is the boot-agnostic workflow: **no per-type boot hunt** — spray all
implemented buckets on the victim CPU, fire once.  Coverage is
`(#buckets)/16` per boot (3/16 ≈ 19% now).  Adding buckets
(`sock_kmalloc`/`ip_sf_socklist`, `io_uring` registered buffers/files,
`ipv6_txoptions`, plus a systematic `kmalloc(96)` call-site search) raises
the coverage toward 16/16, which removes the per-boot dependency entirely:
one live target, one shot, no reboot.

Evidence: `evidence/ROOT-allbuckets-revshell-*.txt`,
`evidence/allbuckets-root-serial-*.log`.

## Non-destructive root: stop-on-connect (boot 2)

Boot 2 (`seed=0xd9cd9d90239df730`, `victim == user_preparse == 0`, ANY:key).
Key spray + unix spray on CPU0; main `.1` F=0/L=2; internal saved-SYN spray
disabled.  A Python reverse-shell handler (`lab/shell_handler.py`) accepts
the payload's shell, **kills the attacker storm on connect**, then probes:

    uid=0(root) gid=0(root) groups=0(root)
    -rwsr-xr-x 1 root root ... /tmp/rootbash
    euid=0(root)

The target was **alive after this fire** (no panic).  The earlier panics came
from *later* bad-neighbour over-reads (a subsequent SYN-ACK whose shinfo
`frag_list` pointed at a foreign/free slot); stopping the storm on the good
event prevents those, and this run is a **non-destructive root shell** on the
stock kernel.  Other archived fires still panicked at 335–419 s, so this is
not a general guarantee (see “Real-world realism gaps”).

Evidence: `evidence/ROOT-nondestructive-*.txt`,
`evidence/nondestructive-serial-*.log`.

## 4-spray combined fire: root + target ALIVE (boot 2)

Boot 2 (`seed=0xaeb24c5fd0401999`, `victim=6 saved=4 key=6 unix=6
sfkmalloc=9`, ANY:key,unix).  Sprays on the victim CPU: keyspray and
unixspray (4x).  Result: root shell, storm killed on connect, target
**ALIVE**, SUID root persists.

### Bucket coverage (fixed, persistent objects only)

| # | Object | Allocation site | Controlled bytes |
|---|---|---|---|
| 1 | saved_syn | tcp_reqsk_record_syn | TCP options |
| 2 | user_key_payload | user_preparse+0x36 | data[] |
| 3 | unix_address | unix_create_addr+0x29 | sun_path[] |

3/16 ≈ 19% in principle; the *measured* reliable coverage is **2/16 =
12.5%** (`key`, `unix`) because the `saved_syn` bucket needs the two-stream
IPOPT4 configuration (see the measured campaign section).  More fixed
buckets (systematic `kmalloc(0x60)` call-site search) raise coverage toward
16/16.

### Retracted: AF_ALG key is not a reclaim bucket

`alg_setsockopt` (af_alg.ko) calls `sock_kmalloc(optlen)`, copies the user
key, runs `type->setkey()`, then **`sock_kzfree_s(sk, key, optlen)`** in the
same syscall (disassembly: `call sock_kmalloc` at `alg_setsockopt+0x16b`,
`call sock_kzfree_s` at `+0x1c6`).  `kfree_sensitive` zeroes the object, so
the AF_ALG key is a **transient, zeroed** allocation: it cannot hold a fake
skb across the read window.  Fires on boots whose victim bucket equalled
`sock_kmalloc+0x42` (`sfkmalloc`) failed and panicked the target (campaign
trials 3-4), consistent with a slot that is reclaimed and immediately
zeroed.  The earlier "4 buckets" claim counted a spray that never actually
reclaimed.

Persistent `sock_kmalloc` users are layout-blocked: `ip_sf_socklist`
(IP_MSFILTER) needs 22 sources but default `igmp_max_msf=10`; IPv6
`ipv6_sf_list` (mld_max_msf=64) puts `sf_count` (a small integer) at
object+24, where the fake neighbour needs `optlen=160`.

## Measured reliability campaign (stock 6.8.0-106, default cmdline)

Each trial: reboot the stock twin, hunt a boot whose victim
(`tcp_v4_route_req+0x91`) random-kmalloc bucket equals a persistent reclaim
object's bucket, then measure F (CPU that frees the `inet_opt`, kprobe on
`inet_sock_destruct`) and L (CPU that runs `ip_options_build`), pick a
source IP with **F != L**, build `G` with `ringone.py`, spray on F, arm the
46 `ip_build_and_send_pkt` stretch probes + `rdopt2`, and fire the MPTCP
storm.  The payload now carries containment: on success it kills the
target-side 9800/9801 listeners (`fuser -k`) and the sprays **before**
opening the shell, and `shell_handler.py` kills the attacker storm on
connect.  `find-match-any.sh` uses `USABLE_BUCKETS` to choose the hunt set.

### Run A - reliable buckets only (key/unix, 6 trials)

| trial | boots to match | bucket | F/L | root | alive 5 s | alive 20 s | SUID | TTR |
|---|---|---|---|---|---|---|---|---|
| 1 | 1 | key | 002/000 | 1 | 1 | 1 | 1 | 30 s |
| 2 | 6 | key | 000/001 | 1 | 1 | 1 | 1 | 25 s |
| 3 | 16 | key | 000/002 | 1 | 1 | 1 | 1 | 34 s |
| 4 | 11 | key | 001/002 | 1 | 1 | 1 | 1 | 42 s |
| 5 | 13 | unix | 000/002 | 1 | 1 | 1 | 1 | 9 s |
| 6 | 4 | key | 000/001 | 1 | 1 | 1 | 1 | 25 s |

**6/6 root.  6/6 alive at 5 s and at 20 s.  SUID root present 6/6.**
TTR 9-42 s, median 29.5 s.  Boots-to-match 1-16, mean 8.5.
Evidence: `evidence/campaign-run2-keyunix-*.{csv,log}`.

### Run B - no bucket filter (8 trials), showing the saved_syn failure

| trial | boots | bucket | spray | root | alive 20 s | TTR | note |
|---|---|---|---|---|---|---|---|
| 1 | 2 | unix | key+unix | 1 | 1 | 20 s | |
| 2 | 9 | saved | none | 0 | 1 | 175 s | no spray source mapped to F |
| 3 | 4 | saved+key | saved+key | 1 | 1 | 3 s | reclaimed by key |
| 4 | 26 | key | key+unix | 1 | 1 | 14 s | |
| 5 | 10 | saved | saved | 0 | 0 | 171 s | panic |
| 6 | 2 | saved | saved | 0 | 0 | 172 s | panic |
| 7 | 6 | saved | saved | 0 | 0 | 171 s | panic |
| 8 | 1 | saved | saved | 0 | 0 | 171 s | panic |

Reliable buckets in Run B: 3/3 root, 3/3 alive at 20 s.
`saved`-only: **0/4, target died in all four.**  The internal IPOPT4 spray
was aimed correctly at F (verified with a `tcp_reqsk_record_syn` kprobe that
maps each spray source IP to its receive CPU), so the failure is the object
layout, not the CPU: `PHASE4-RINGPAYLOAD.md` requires a **two-stream**
configuration (a 107.x pre-spray plus a 192.x IPOPT4 victim stream) so that
the reclaimed neighbour carries `nr_frags=0`; the campaign's single spray
leaves TCP-option padding that sets `nr_frags != 0` and the target panics in
`skb_release_data`.
Evidence: `evidence/campaign-run1-allbuckets-*.{csv,log}`.

### Quantified result

* Reliable coverage: **2/16 = 12.5% per boot** (`user_key_payload`,
  `unix_address`); `saved_syn` adds a third bucket only with the two-stream
  IPOPT4 setup.
* Match acquisition: 1-26 boots, mean 8.0 across all 14 trials (a boot costs
  ~20-25 s), i.e. roughly 3 minutes of rebooting per successful attempt.
* Given a reliable-bucket match: **9/9 root**, **9/9 alive at 5 s and 20 s**,
  SUID root persists, TTR 9-42 s (median 25 s).
* End-to-end in the lab: ~8 boots (~3-4 min) per root, one shot, no target
  vmlinux read, wire-derived KASLR slide available separately.
* Unchanged dependencies that keep this short of "default settings": the 46
  stretch kprobes + `rdopt2`, the root AF_PACKET ring (`ringone`), and the
  custom MPTCP/`TCP_SAVE_SYN` listeners.  The race amplifier (#1) remains the
  blocker; the bucket lottery is now measured, not assumed.

## saved_syn: layout verified, reclaim structurally unstable

The `saved_syn` bucket was analysed end-to-end with live measurements:

* **The object layout is correct.** A `tcp_reqsk_record_syn+0x77` kprobe
  captured the allocation pointer (`obj=%ax`) and `/proc/kcore` read the
  object: `struct saved_syn { u32 mac_hdrlen; u32 network_hdrlen;
  u32 tcp_hdrlen; u8 data[]; }`, data at +12, the 24-byte IP header (with
  4-byte options) at +12, so the source-IP byte 0 sits at **+24 = 0xc0 ->
  fake optlen 192**; TCP options at +56, so `PAYLOAD_FRAG` lands exactly at
  **+88..95** and +82/83 = 0.  Size 96 B is confirmed by the kmalloc
  tracepoint (`bytes_req=96`).  Evidence:
  `evidence/saved_syn-object-layout-*.txt`.
* **The RSS CPU depends on the source IP *and* the source port.**  A
  `tcp_reqsk_record_syn+0x77 p12=+12(%r13):u16` kprobe plus one 2 s spray
  maps every port to its receive CPU in a single run (e.g. 54200->3,
  54201->1, 54213->0).  Consequently `SPRAY_VARYPORT` is harmful: it
  scatters the allocations over all CPUs and the victim slot on F is rarely
  reclaimed.  `SPRAY_PORTS` can aim a 64-port set at F.
* **Half-open objects live ~1 RTT** because our kernel RSTs the SYN-ACK.  A
  *selective* 1 ms egress delay (iptables MARK + tc prio/netem) extends the
  lifetime; a blanket delay also breaks the main race (`freeopt` drops from
  ~1900/s to ~0 because the ACKs that close the victim sockets are delayed
  too).
* **The aimed spray starves the victim path.**  Counted with per-instance
  kprobes (`rdopt2` filtered `optlen>60` = real over-read, `freeopt` =
  `inet_sock_destruct` with `inet_opt != 0`):

  | saved spray on F | freeopt | real over-reads |
  |---|---|---|
  | none (measurement) | 5766 / 3 s | 0 |
  | 2.5k pps | ~68 / 5 s | 3 in one run, 0 on repeats |
  | 5k-20k pps | 0 / 5 s | 0 |

  The raw-SYN spray runs in softirq on exactly the CPU F that must run the
  victim socket's destruction; at any useful rate it starves that path, and
  at survivable rates the reclaim almost never wins.

Result: **0/6 saved-only campaign fires rooted**; the two run-3 fires stayed
alive (no over-read in the trace), while the four run-1 saved-only fires
panicked (Run B).  The older one-off `saved` root predates this and is not
reproducible.  Reliable coverage therefore remains **key + unix = 2/16**,
and the `saved_syn` bucket should be treated as a negative result,
not a usable third bucket.  Evidence:
`evidence/campaign-run3-saved-*.{csv,log}`.

### Other bucket candidates checked and rejected

* `big_key` key type: not registered on stock 24.04 (`add_key` -> ENODEV).
* `io_uring` registered-file tags: stored as a page-pointer table
  (`struct io_rsrc_data { u64 **tags; }`), not a flat 96-byte user array.
* `ip_sf_socklist` / `ipv6_sf_list`: `sock_kmalloc` bucket already covered;
  layouts blocked (`sf_count`/`igmp_max_msf`).
* `watch_filter`: `type` is validated to < `WATCH_TYPE__NR` at +24, so
  optlen cannot be set.
* `msg_msg`/`simple_xattr`: the user data starts at +48/+32 and the size
  field at +24 is the message/xattr length, so a 96-byte slot cannot carry
  `optlen >= 152`.

## Hunt 1 result: the free/read ordering is structurally racy

`docs/HUNT1-ORDERING.md` closes the "remove the 46 stretch kprobes" hunt:

* The reader (`tcp_v4_send_synack` -> `ip_build_and_send_pkt`) loads
  `ireq->ireq_opt` and first reads `opt->optlen` **~20 instructions later
  (5-10 ns)**; the target binary shows the dereference at
  `0xffffffff8202019b` and the first use at `0xffffffff81fe7b3f`.
* The object's ownership transfers to the child socket in
  `tcp_v4_syn_recv_sock`, and the child's `inet_sock_destruct` frees it with a
  **plain `kfree`** (the `rcu_read_lock()` in the reader does not protect it).
  Measured transfer -> kfree latency (771 pointer-matched pairs):
  **min 1 us, p50 8 us, p90 17 us, p99 30 us, max 54 us**
  (`evidence/hunt1-free-latency-*.txt`, `evidence/hunt1-latency-trace-*.trace`).
* A natural UAF therefore needs the reader to be delayed by ~1-20 us between
  the dereference and the first use. A hardirq would have to land in a ~10 ns
  window (~1e-6/read); Phase 1 measured 0 UAF in >1M reads. Softirq is not
  preemptible. The 46 `int3` probes supply exactly the missing ~40 us.
* The other two `ip_options_build` call sites (`__ip_queue_xmit`,
  `__ip_make_skb`) have naturally long windows but the object cannot be freed
  concurrently (skb holds `skb->sk`; `lock_sock()` is held).

Conclusion: the instrumentation dependency is structural for this CVE, not a
shortcut. Removing it needs a different free/read pairing, not a better
amplifier. The next hunt is #3 (an unprivileged controlled page).

## Hunt 3 result: an unprivileged replacement for the root ring is blocked

`docs/HUNT3-WIRE-G.md` closes the "replace the root AF_PACKET ring with an
unprivileged 96-byte object" hunt. The wire-derived `G` address leak itself is
demonstrated separately via a `pg_vec` over-read, but that allocation still
comes from the root ring:

* The over-read's length is `*(u8 *)(object + 24)` and it copies from
  `object + 16`. A useful leak object therefore needs a large +24 byte and a
  pointer inside the copied window, in a 96-byte slot.
* `io_mapped_ubuf` (io_uring registered buffer, 4 pages = 96 B, allocated at
  the *fixed* `kvmalloc_node+0x24` bucket, unprivileged) has
  **+24 = acct_pages = 4** -> the leak copies 4 bytes.  It does carry the four
  `struct page *` of the user buffer at +32..+80, but they are unreachable.
  Measured live via `/proc/kcore`: `evidence/hunt3-iomapped-ubuf-*.txt`.
* A 2-slot `struct pipe_buffer` array (80 B -> kmalloc-96) has
  +24 = `flags` (0x10) and leaks only `+16 = ops` (a text pointer) — good for
  a wire slide, useless as `G`.
* Even a leaked `struct page *` is not a direct-map address:
  `page_offset_base`, `vmalloc_base` and `vmemmap_base` are randomized
  independently (`arch/x86/mm/kaslr.c`).  Measured on one boot:
  direct-map object `0xffff8c8481fcec60`, vmemmap pointer
  `0xfffff4c544021140`.  One leaked page pointer leaves two unknowns; a wrong
  guess used as a fake-skb pointer panics the target.
* No leak exposes `page_offset_base`/`vmemmap_base` themselves (they are
  image-mapping globals, not slab-stored pointers).

Dependency status after Hunts 1 and 3: **#1 structural, #2 structural,
#3 structural for an unprivileged replacement, #4 (2/16 coverage)
structural.**  The remaining route to a default-settings RCE is a different
vulnerability/primitive, not more work on this chain.

## Open-source release: reproduction confirmed and environment documented

**Fresh end-to-end run (2026-11-18).** Two-VM lab, target = stock Ubuntu 24.04.4
`6.8.0-106-generic` booted with the stock cmdline (`NO_SLUB=1`):

```
trial,boot,seed,match,spray,src,F,L,S,root,alive5,alive20,suid,ttr_s
1,5,0xda78b74fa99cd1e9,key,"",11,002,001,0xffff8a1a07991010,1,1,1,1,42
```

Attacker-side handler: `CONNECTED (192.168.89.2)`, `uid=0(root)`, `SHELL_OK`,
`/tmp/rootbash` SUID root. Evidence: `evidence/REPRO-root-*.txt`.

**Documentation added for publication:**

* `README.md` — end goal, status at a glance, what works and what does not,
  CVE-at-a-glance, progress and the roadmap to a default-settings RCE.
* `docs/CVE.md` — CVE record, root cause, upstream `kfree_rcu` fix, affected
  and fixed versions, severity and references.
* `docs/LAB-SETUP.md` — the two-VM architecture (attacker + target + host
  orchestrator), the explicit “stock kernel, non-default lab” section, host
  requirements, the VM images/kernel packages that are **not** shipped and how
  to build them, the QEMU socket vs 4-queue tap topologies, management/lab
  networking, SSH ports, the 9p share, the boot order, the exact reproduction
  commands and the manual in-guest preflight/post-fire checklist (§6.1).
* `docs/SETTINGS.md` — the verified stock defaults (cmdline, KASLR, sysctls,
  `RANDOM_KMALLOC_CACHES`, `SLAB_FREELIST_HARDENED`, `HARDENED_USERCOPY`,
  kprobe/ftrace config, network) versus every lab customization (tracefs
  stretch probes, the two listeners, the root AF_PACKET ring, the sprays, RPS
  tuning, attacker IP aliases, containment), plus which gate each one serves.

These documents state the same honest boundary: the exploit preserves all
stock mitigations but requires the target-side customizations; it is not a
default-settings remote exploit.
