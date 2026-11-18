# CVE-2026-98432 — Remote root shell in two modes (MPTCP / plain TCP)

> Historical plan: the implementation and measured status have moved on. Use
> `README.md` (“Status at a glance”) and `docs/CAPABILITY.md` for current
> results. Some internal documents/artifacts referenced below are not shipped.

Status: **historical plan (2026-11-09); current status is in README.md and docs/CAPABILITY.md**
Lab root: `labs/cve-2026-98432/`
Primary prior art: the external `cve_2026_98432-poc` lab repository.
Public context: Anthropic Frontier Red Team (2026-10-27), kernel CVE record, upstream fix `e3f33b0a1d89`

---

## 0. Scope, assumptions, success criteria

### 0.1 Authorized use

All work is against local QEMU/KVM guests that we own. No external hosts, no
internet-facing targets, no persistence/rootkit work. The exploit is developed
and validated in an isolated lab with snapshots and packet captures.

### 0.2 What "Ubuntu VM default settings" means here

The **validation target** is a stock Ubuntu 24.04 cloud image, kernel
`6.8.0-106-generic` (vulnerable; Ubuntu's fix is pending in `6.8.0-149`), booted
normally and *not* modified in any of these ways:

| Must be default / untouched | Value on the stock guest |
|---|---|
| Kernel cmdline | no `slub_debug`, no `init_on_free`, no `nokaslr` |
| KASLR | on |
| SMEP / SMAP / KPTI | on (`-cpu host`) |
| `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` | `y` |
| `CONFIG_INIT_ON_FREE_DEFAULT_ON` | not set |
| `CONFIG_RANDOM_KMALLOC_CACHES` | `y` |
| `net.mptcp.enabled` | `1` |
| `net.ipv4.tcp_migrate_req` | `0` |
| `net.ipv4.tcp_syncookies` | `1` |
| RFS (`rps_sock_flow_entries`) | `0` |
| Target-side root helpers | none |
| Target-side kprobes / tracefs / gdb | none |
| Target-side `/proc/kcore`, `/proc/kallsyms`, pagemap | not used by the exploit |

A second, **instrumented twin** guest (same kernel, `slub_debug=P`, tracefs
kprobes, QEMU gdbstub) is allowed for *measurement and ground truth only*. Any
result that matters is re-run on the stock target. The instrumented twin is
never cited as the final exploit environment.

### 0.3 The two modes

* **Mode M (MPTCP):** the target runs an MPTCP listener
  (`socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)`; e.g. Go 1.24+ or our lab
  listener). The service sends data on accepted connections.
* **Mode T (plain TCP / "any specific port"):** the target runs an ordinary
  IPv4 TCP listener (sshd on :22, an echo/stream service, etc.). No MPTCP
  socket, no `tcp_migrate_req`, no BPF reuseport program.

### 0.4 Success criteria

1. From the attacker VM, with no credentials and no target-side pre-setup, the
   stock target executes an attacker-chosen command **as uid 0**.
2. Proof: `/tmp/PWNED` written by a root usermode helper/command with
   `uid=0(root)`, plus a SUID root shell (`/tmp/rootbash -p`) or equivalent.
3. The run is reproducible from a clean snapshot; the lost-race path does not
   panic the target.
4. Evidence: exploit log, target serial/dmesg, packet capture, timings,
   success rate over N runs.
5. Mode M must succeed under §0.2. Mode T must either succeed under §0.2 or be
   closed with a source-level proof of infeasibility + the best available
   variant (see §5).

---

## 1. What the prior work established (honest baseline)

From the prior `cve_2026_98432-poc` lab (AGENTS.md, STATUS.md, evidence/):

| Capability | Status |
|---|---|
| UAF trigger on debug boot (`slub_debug=P`), MPTCP dispose + dup-SYN reader | **DONE** |
| Kernel-side UAF observation (poison reads) | **DONE** |
| Controlled-content reclaim, local/root (`tc` ematch, prctl, attr, kmsg) | **DONE** |
| OOB 4-byte write into `skb_shared_info` (srr/rr/ts) | **DONE** |
| Arbitrary kernel call (`frag_list` -> fake skb -> `destructor`) | **DONE (debug lab)** |
| Local root shell via usermode helper | **DONE (root-assisted, debug boot only)** |
| Real MP_JOIN handshake, remote streaming subflow | **DONE** |
| Plain-TCP request-path UAF | **RETRACTED** (refcount-serialized; 0/16M+) |
| Remote/default-boot reclaim | **PARTIAL (2026-11-10)**: remote cross-CPU UAF read reproduced (RPS + IP fragmentation); on a `RANDOM_KMALLOC_CACHES`-matched boot the `saved_syn` reclaim landed and its 192-byte `optlen` overflowed `skb_shared_info`, panicking in `skb_release_data` through `tcp_v4_send_synack -> ip_build_and_send_pkt`. The overflow is real but uncontrolled; the controlled fake-skb/leak stage remains. See `docs/PHASE2.md`. |
| Remote KASLR/heap leak | **NOT ACHIEVED** |
| Remote MPTCP root | **NOT ACHIEVED** |

Two claims in the prior tree must be treated as *hypotheses*, not facts:
the "listener close" plain-TCP migration path actually needs
`tcp_migrate_req=1` or a BPF reuseport program (`reuseport_migrate_sock()`
returns failure otherwise), and the remote plain-TCP result is retracted.

---

## 2. Technical thesis (what to build)

### 2.1 Root cause

`tcp_v4_syn_recv_sock()` assigns `newinet->inet_opt = ireq->ireq_opt` (no
copy). When the child is destroyed, `inet_sock_destruct()` does a plain
`kfree(inet_opt)`; `tcp_v4_reqsk_destructor()` does the same for the request
path. A concurrent reader (`ip_build_and_send_pkt()` from a retransmitted SYN,
or `__ip_queue_xmit()` from a data TX on an established subflow) dereferences
the freed `struct ip_options_rcu` under `rcu_read_lock()`, which does not wait
for a plain `kfree()`.

The race is only useful if the free can happen on a **different CPU** than the
reader while the reader has the pointer. The demonstrated trigger (Anthropic)
is the MPTCP dispose path: one softirq creates and destroys the child, so the
free needs no application action. For plain TCP the child normally survives in
the accept queue until the app closes it, which is far too late (see §5).

### 2.2 The primitive the prior tree under-used: TOCTOU on `opt->optlen`

`ip_build_and_send_pkt()` reads the length field twice:

```c
skb_push(skb, sizeof(struct iphdr) + (opt ? opt->opt.optlen : 0));   /* read #1 */
...
if (opt && opt->opt.optlen) {                                        /* read #2 */
        iph->ihl += opt->opt.optlen >> 2;                            /* read #3 */
        ip_options_build(skb, &opt->opt, daddr, rt);                 /* read #4, memcpy */
}
```

If the object is reclaimed between read #1 and read #4 with a **larger**
`optlen`, the skb only reserved the small headroom but `ip_options_build()`
does `memcpy(iph + 20, opt->__data, optlen)` with the large length. That is a
forward heap overflow from the IP options area into the rest of the skb head,
including `skb_shared_info`. This matches the public description
("overflow a buffer and overwrite a callback pointer"); it is strictly more
powerful than the prior tree's three 4-byte IP-address writes because it gives
arbitrary *bytes* and a full 8-byte pointer.

Measured geometry on 6.8.0-106 (40-byte TCP header, `MAX_TCP_HEADER=320`):

```
iph        = skb->head + 220
shinfo     = skb->head + 384     (distance 164)
source     = iph + 20 = head + 240
overflow L reaches:  head+240+L
```

| target field | offset in shinfo | required L (approx) |
|---|---|---|
| `flags` / `tx_flags` | 0 / 3 | 144 / 147 |
| `frag_list` | 8 | 152 |
| `dataref` | 32 | 176 |
| `destructor_arg` | 40 | 184 |
| `frags[0..]` | 48+ | 192+ |

The overflow source is the fake object's `__data` (object+32) and the adjacent
kmalloc-96 slots. The fake object is only 96 bytes, so L > 64 necessarily reads
across neighbouring slots; the exploit must **spray controlled kmalloc-96
objects** so the bytes at object+32 .. object+32+L are attacker-chosen. The
same-callsite `tcp_v4_save_options()` objects (IP options from our SYNs) are
the obvious network-reachable, controlled-content spray.

### 2.3 Two callback routes from the overflow

* **Route A — `destructor_arg` / zerocopy callback.** Set
  `shinfo->flags |= SKBFL_ZEROCOPY_ENABLE` and
  `shinfo->destructor_arg = P`. On skb free, `skb_zcopy_clear()` calls
  `uarg->callback(skb, uarg, success)` where `uarg == P`; `rdi` is the skb,
  `rsi` is our pointer. A fake `struct ubuf_info` at `P` can point the callback
  at a gadget or at a kernel function; `rsi` is a useful second controlled
  pointer for a JOP/stack pivot.
* **Route B — `frag_list` / fake skb destructor.** Set `shinfo->frag_list = P`;
  the free path walks `P` as a `struct sk_buff` and calls
  `((struct sk_buff *)P)->destructor(P)` at +96. The prior tree already has a
  working fake-skb layout ending in `call_usermodehelper_exec` (no ROP) for
  the local lab; this is the cleanest payload if a fake skb can be staged at a
  known kernel address.

Both routes require (a) a kernel address for the staged payload and (b) KASLR.
That is Stage 1.

### 2.4 Stage 1 leak (KASLR + heap)

Use the same TOCTOU/reclaim, but with a fake `optlen` between 45 and the
headroom limit, and capture the SYN-ACK with `AF_PACKET` **before** the
attacker's IP stack validates it. The over-read copies adjacent kmalloc-96
memory into the SYN-ACK's IP options. Any kernel pointer in those bytes defeats
KASLR. Two sources of pointers:

1. **`fib_nh_exception` (new lead, to be verified).** ICMP redirect / frag-needed
   creates a `kzalloc(sizeof(struct fib_nh_exception))` in kmalloc-96
   (`update_or_create_fnhe()`), with attacker-influenced fields:
   * `fnhe_daddr` (+12) = our source IP,
   * `fnhe_pmtu` (+16) = ICMP MTU,
   * `fnhe_gw` (+24) = redirect gateway -> **`optlen`, `srr`, `rr`, `ts` bytes**,
   * `fnhe_expires` (+28/+32) -> `flags` (timable),
   * `fnhe_rth_input` (+40), `fnhe_rth_output` (+48) = **kernel heap pointers**.
   This is a network-reachable, hold-type kmalloc-96 object whose content maps
   directly onto `struct ip_options_rcu` and leaks valid pointers. It is the
   most promising replacement for the local-only sprays, but the call-site hash
   bucket must match `tcp_v4_save_options` (1/16 per boot) and redirect
   acceptance depends on the route/gateway setup. Verify on the instrumented
   twin, then on stock.
2. **Same-callsite IP-option spray.** Spray many `ireq_opt` objects with
   markers; the over-read of a neighbouring slot reveals foreign content. The
   prior tree's poison-echo proves the channel; on stock the freed object keeps
   its old 40-byte content, so a *controlled* over-read needs a foreign
   large-`optlen` object (hence the reclaim primitive is still the critical
   path).

### 2.5 The reclaim problem and RANDOM_KMALLOC_CACHES

`tcp_v4_save_options()` allocates from
`bucket = hash_64((call_site ^ random_kmalloc_seed), 4) >> 60`.
Only allocations from a call site in the *same bucket* can reuse the freed
slot. The plan is:

1. Build a static catalog of every `__kmalloc`/`kmemdup`/`sock_kmalloc` call
   site in the target vmlinux, with function+offset and bucket (the prior tree
   has the method; extend it to network-reachable sites).
2. Rank candidates by: reachable from a packet we can send, controlled content
   bytes, hold vs churn, and size class 96.
3. Probe candidates blindly on stock (no bucket read): allocate with a marker,
   trigger the UAF read, look for the marker/leak on the wire. A hit identifies
   both the bucket match and the primitive.
4. Deduplicate with the same-callsite spray (guaranteed bucket) where the
   content constraints are acceptable.

Known candidate classes (to verify, not assumed):
`fib_nh_exception`, `dst_metrics` (PMTU cow), `ip_options_rcu` (same callsite),
`saved_syn` (`TCP_SAVE_SYN`, off by default), CIPSO cache, TCP-AO buffers
(off by default), IPsec AH/ESP buffers (off by default). The catalog tells us
which ones are in reach at all.

### 2.6 Stage 2 execution

Given (KASLR, payload address, reclaim primitive), the exploit:

1. Sprays the payload (fake skb/subprocess_info or fake ubuf_info + JOP chain)
   into kmalloc-96 via IP options (or the matching primitive).
2. Wins the race with the TOCTOU fake object whose `optlen` covers the chosen
   shinfo field (152-256).
3. Lets the skb free path invoke the callback.
4. The callback either lands directly on `call_usermodehelper_exec` with
   `UMH_NO_WAIT` (softirq-safe) or starts a short JOP chain that neutralises
   `rsi`/`rdi`/`rdx` and ends in the usermode helper / a shell command.
5. The helper writes `/tmp/PWNED`, installs a SUID root shell, and exits; the
   target stays alive (or is documented as crashing after root is achieved).

The prior tree's fake-skb layout (`rce_prep.c`) is the reference for Route B.
Route A (`ubuf_info.callback`) needs a JOP/stack-pivot search on the exact
Ubuntu kernel; the prior tree did not find `mov rsp, rsi`, so this is a real
research item (try `xchg`, `push rsi; ret`, `leave; ret` with a fake stack in
the payload, or a call-oriented chain).

---

## 3. Lab architecture

```
labs/cve-2026-98432/
  PLAN.md                  this file
  README.md                lab usage
  lab/
    cache/                 stock Ubuntu 24.04 cloud image (gitignored)
    kernel/                vmlinuz/initrd/config 6.8.0-106 (copied)
    ssh/                   lab key
    harness/               overlays, seeds, serial logs (gitignored)
    launch-target.sh       stock boot (no slub_debug)
    launch-instrumented.sh debug twin (slub_debug=P + gdbstub)
    launch-attacker.sh     attacker VM on the socket link
    snapshot-*.sh          clean-snapshot create/restore
  exp/                     attacker-side C/Python
    exp_mptcp.c            MP_JOIN + subflow data reader + dispose trigger
    exp_tcp.c              plain-TCP harness (kept as detector)
    race_oracle.c          marker/leak parser, AF_PACKET capture
    reclaim_catalog.py     call-site -> bucket analysis
    stage/                 payload builders
  target/                  optional target services (MPTCP / TCP test service)
  scripts/                 setup, run, evidence collection
  evidence/                logs/pcaps for every claim
  docs/                    measurements, capability matrix, final report
```

* **Target VM:** stock boot; SSH on `:2223` only for setup/observation before
  an exploit run (test harness, not part of the exploit). A clean snapshot is
  restored before every validation run.
* **Instrumented twin:** same kernel with `slub_debug=P`, tracefs kprobes,
  kmem tracepoints, `-s` gdbstub, `/proc/kcore`/`kallsyms` ground truth. Used
  for race/reclaim measurement and to verify leaked values. Never the final
  target.
* **Attacker VM:** raw sockets, `CAP_NET_RAW`, AF_PACKET capture, IP aliases
  (for spoofed source addresses / the high-half trick), `iptables` RST block.
  Optionally a third **observer** VM so a malformed SYN-ACK cannot disturb the
  attacker's own stack.
* **Network:** rootless QEMU socket link (`-netdev socket`) by default. A
  tap/multi-queue link (host root) is an optional measurement rig to study
  RSS/RFS; it is not required for the default-settings claim.
* **Artifacts:** copy the base image + kernel + key from the prior lab; do
  **not** copy the dirty 1.3 GB overlay. Create fresh overlays; snapshot after
  first boot.
* **Ground truth:** the instrumented twin reads `page_offset_base`, the KASLR
  slide, the random kmalloc seed, the exact freed object address, and the
  `ip_options_build` optlen/value; compare with the stock leak. This is the
  only way to know whether a stock run really leaked what we think.

---

## 4. Phased execution plan

Each phase has a **gate**; do not build the next stage on an unverified gate.

### Phase 0 — Lab bring-up and baselines (0.5–1 day)

Tasks
- Stop the hung prior-lab VM; copy base image, kernel, key.
- Create fresh target/attacker overlays; boot stock target; verify §0.2 values.
- Boot the instrumented twin; verify kprobes, gdbstub, `slub_debug=P`.
- Build the prior tree's tools; run the MP_JOIN handshake against a stock
  MPTCP listener from the attacker; confirm `data`/`marked` counters.
- Start a plain TCP stream listener on the stock target; confirm normal
  traffic and RST behavior.
- Establish snapshots and an evidence-collection script.

Gate G0
- `uname -r` = 6.8.0-106; no `slub_debug` on the target; KASLR/SMEP/SMAP/KPTI
  on; `tcp_migrate_req=0`; MPTCP enabled.
- Attacker can complete a real MP_JOIN and stream on the join subflow.
- Clean snapshot restore works.

### Phase 1 — Default-settings UAF and TOCTOU confirmation (2–4 days)

Tasks
- Port the MPTCP dispose storm + MP_JOIN reader to the new lab.
- On the instrumented twin, add kprobes:
  `ip_build_and_send_pkt` (entry/offsets, optlen reads),
  `ip_options_build` (optlen, data bytes),
  `tcp_v4_save_options`, `inet_sock_destruct`, `tcp_v4_reqsk_destructor`,
  `update_or_create_fnhe`, `skb_zcopy_clear`, `skb_release_data`.
- Measure the natural race (no stretch kprobes) with the dispose path and the
  subflow data-TX/RST path: hits per million packets, window size, CPU pairs.
- Prove the double-read window: instrument the two `optlen` reads and show a
  reclaim with a different `optlen` between them.
- Verify whether the malformed SYN-ACK can be captured by AF_PACKET on the
  attacker without panicking the attacker (use the observer if not).

Gate G1
- A genuine UAF read on the **stock** target (content mismatch, not just a
  normal read), replicated at least 3 times.
- A measured reclaim-induced TOCTOU (read #1 != read #4) on the instrumented
  twin, with the exact field offsets.

### Phase 2 — Remote reclaim primitive (1–2 weeks; critical path)

Tasks
- Extend `reclaim_catalog.py`: enumerate all kmalloc-96 call sites in the
  target vmlinux, resolve function+offset, compute bucket, tag network
  reachability and content control from source.
- Implement and test the `fib_nh_exception` trigger:
  * ICMP redirect (needs the attacker to be the target's gateway/onlink),
  * ICMP frag-needed (PMTU) to set `fnhe_pmtu`,
  * multiple `daddr` values to create/hold many fnhes.
  Measure allocation/free with kmem tracepoints on the twin; verify the
  `optlen/srr/rr/ts` bytes and leaked `rth_*` pointers.
- Implement the same-callsite IP-option spray with markers and varied
  `__data` (this is the guaranteed-bucket baseline).
- Build a blind probe: spray candidate, trigger the UAF, detect the marker or
  an abnormal `optlen` on the wire. Track per-candidate hit rate.
- Test hold-vs-churn: the prior tree measured that churn loses to the storm's
  own `save_options` on stock; prefer hold allocations on the freeing CPU.
- Test CPU placement: with one RX queue all packets are processed on one CPU;
  the free and the reclaim allocation must be on that CPU; the reader is on
  the target app's CPU.

Gate G2 (make-or-break)
- A **controlled-content** object is observed at the freed address in a UAF
  read on the **stock** target (marker or attacker-chosen bytes), at least
  once in a bounded run, and the same primitive reproduces.
- If G2 fails after the candidate catalog is exhausted, the honest conclusion
  is that the default-stock remote chain is blocked at reclaim; document it
  with the measurement and pivot to the closest supported configuration.

### Phase 3 — Stage 1 leak (1 week)

Tasks
- Turn the TOCTOU into a read: read #1 small, reclaim with a fake object whose
  `optlen` is large but within the `skb_push` headroom (<= ~196), capture the
  SYN-ACK options via AF_PACKET on the attacker/observer.
- Use `fib_nh_exception` bytes (rth pointers) and/or sprayed markers to find a
  kernel pointer; parse text pointers, direct-map pointers, and slab pointers.
- Compute KASLR slide / `page_offset_base`; compare with the twin's ground
  truth (and the prior lab's `po_base.py` result).
- Handle the malformed-`ihl` problem: choose `optlen` 44..196, capture before
  RX validation, redirect the packet with srr/faddr if needed, and ensure a
  lost leak cannot panic the target.
- Measure leak time-to-first-pointer; target the public ~48-minute scale but
  optimize with the fnhe primitive (fewer attempts expected).

Gate G3
- A kernel text pointer (or a pointer from which the text slide is derivable)
  and a direct-map/heap pointer are recovered from a **stock** target over the
  wire, replicated 3 times.
- The leaked values match the instrumented twin's ground truth for the same
  boot parameters.

### Phase 4 — Stage 2 control flow (2–4 weeks; highest risk)

Tasks
- Build the payload staging: a repeating kmalloc-96 pattern (IP options or the
  matching primitive) that contains the fake `ubuf_info`/fake skb, strings,
  argv/envp, and any JOP chain. Derive its address from G3 + slab grooming.
- Implement the overflow: fake object `optlen` such that the memcpy covers
  `frag_list` (L≈152) or `destructor_arg` (L≈184) and the surrounding fields
  (`flags`, `tx_flags`, `dataref`, `users`, `fclone` as needed).
- Route B first: fake skb -> `destructor = call_usermodehelper_exec` with a
  fake `subprocess_info` (prior tree layout) and `UMH_NO_WAIT`; verify in the
  instrumented twin (task/softirq context), then stock.
- Route A if B is unstable: fake `ubuf_info.callback`; hunt pivots
  (`mov rsp,rsi`, `xchg rsp,rsi`, `push rsi; ...`, call-oriented chains) in the
  exact vmlinux; or use a callback whose arguments already fit a useful kernel
  function.
- Make the payload softirq-safe: no sleeping, no `UMH_WAIT_EXEC` in IRQ
  context; use `UMH_NO_WAIT` and let the kworker do the exec.
- Crash containment: ensure a lost race or a bad reclaim does not panic the
  target; if a panic is unavoidable, document it and keep the root proof.

Gate G4
- `/tmp/PWNED` with `uid=0(root)` and a SUID root shell on the **stock**
  target, from a clean snapshot, no target-side setup.
- Replicated at least 3 times; success rate and mean time recorded.

### Phase 5 — Mode T (plain TCP / any port) (parallel, 1–2 weeks)

See §5. Tasks:
- Formally test the plain-TCP main path: child free only via app close /
  accept-queue eviction / migration; measure the window; prove or disprove
  with source + experiment.
- Test the child-teardown timing with a service that accepts and immediately
  closes (worst-case service-assisted scenario).
- Test TFO, syncookies, `tcp_abort_on_overflow`, reuseport groups, and listener
  close, with the instrumented twin; record which paths actually free on a
  different CPU while a reader is live.
- If a default path exists, port the Phase 2-4 chain.
- If not, produce a source-level infeasibility note and a variant matrix:
  * service-assisted (target service closes/evicts),
  * `tcp_migrate_req=1` (non-default),
  * BPF reuseport (non-default),
  * plain TCP with a service that transmits and closes (measure).

Gate G5
- Either a working Mode T chain under §0.2, or a definitive negative with
  experiments and source references, plus the best supported variant. The
  user decides whether the variant counts.

### Phase 6 — Reliability, evidence, report (1 week)

- Stress runs: N=50+ on stock; measure success rate, time, panics.
- Add retries/backoff, snapshot restore, and a single-command reproducer.
- Produce `docs/CAPABILITY.md`, `docs/MEASUREMENTS.md`, `docs/REPORT.md`,
  pcap/log evidence, and a final demo script.
- Re-verify from a fresh snapshot with no leftover state.

---

## 5. Mode T analysis and decision tree (plain TCP / any port)

### 5.1 Why it is hard (source-level)

* **Request path:** `tcp_v4_send_synack()` reads `ireq->ireq_opt` only while
  holding a request ref; `tcp_v4_reqsk_destructor()` runs at refcount 0, after
  the reader. RST/ICMP/timer frees cannot race the reader. The prior tree's
  16M+ attempts and source proof agree.
* **Child path:** the child socket is inserted into the accept queue; an RST
  only marks it dead. `inet_sock_destruct()` runs when the last reference
  (the app fd/accept queue) is dropped. A plain service's `close()` is far
  slower than the reader's load->copy window; the reader also holds a file/sk
  reference during `send()`.
* **Migration path:** `reuseport_migrate_sock()` requires
  `net.ipv4.tcp_migrate_req=1` or a `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE`
  program. `reqsk_timer_handler`'s "listener closed" migration is gated by the
  same check. Both are non-default.
* **MPTCP dispose** is the only default path where a child is created and
  destroyed in one softirq, enabling a cross-CPU free without app action.

### 5.2 What we will test anyway

1. A lab service that accepts and immediately closes (SO_LINGER 0) while a
   retransmitted SYN reader is in flight: measure the free/read gap.
2. A service with a transmit thread and a close thread; measure whether the
   fd/sk ref serialization really prevents the free during `ip_queue_xmit`.
3. TFO (`net.ipv4.tcp_fastopen`) and SYN-cookie child teardown paths; check
   whether any kernel-side teardown occurs after the `ireq_opt` transfer.
4. Reuseport groups (multiple workers) with worker close/restart; check for
   `inet_reqsk_clone()` without the sysctl/BPF.
5. Accept-queue overflow with `tcp_abort_on_overflow=1` (non-default) as a
   variant.

### 5.3 Decision

* If a **default** plain-TCP free/read pair is found: port the chain; Mode T
  is real.
* If not: report a negative with the experiments and offer:
  * **T-service**: a target service that closes/evicts children (still default
    kernel settings; the service behavior is part of the scenario), or
  * **T-migrate**: `tcp_migrate_req=1` / BPF reuseport (non-default).
  The user decides whether either satisfies "any specific TCP port".

---

## 6. Risks and mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| No default-boot reclaim primitive (G2 fails) | Medium-high | Exhaust the network-reachable catalog; use `fib_nh_exception`; if still no, publish the negative and pivot |
| Race too slow without kprobe stretch | High | Optimize the trigger geometry (CPU pairs, spacing, multi-flow); use the TOCTOU/route-lookup window; accept long runtimes |
| Random kmalloc bucket mismatch | High per boot | Candidate catalog + blind probing; retry boots; same-callsite spray is guaranteed bucket |
| KASLR/leak instability | Medium | `fib_nh_exception` pointer leak; observer VM/AF_PACKET; multiple leak sources |
| Callback in softirq cannot sleep | High | `UMH_NO_WAIT`; softirq-safe JOP; avoid `commit_creds` in IRQ |
| Target panic on a bad reclaim/overflow | Medium | Crash containment; task-context free if possible; snapshot restore; document |
| Disk space (12 GB free) | Low-medium | Base image + two sparse overlays + logs; prune pcaps; use zstd |
| Time | High | Gates; stop at a documented negative rather than overrun |

---

## 7. Deliverables and rough timeline

| Deliverable | When |
|---|---|
| Lab (stock + instrumented + attacker, snapshots, scripts) | Phase 0, ~1 day |
| Default-boot UAF + TOCTOU measurement | Phase 1, ~2–4 days |
| Reclaim primitive matrix + G2 result | Phase 2, ~1–2 weeks |
| Wire leak + KASLR/heap ground truth | Phase 3, ~1 week |
| Mode M root shell on stock | Phase 4, ~2–4 weeks |
| Mode T result (working or negative + variants) | Phase 5, parallel |
| Reproducer + evidence + report | Phase 6, ~1 week |

Total: ~5–8 weeks of focused work for Mode M, with Mode T as a parallel
feasibility track. The public PoC took ~53 minutes per successful run; our
target is the same order, not seconds.

---

## 8. Immediate next steps (upon approval)

1. Stop the hung prior-lab VM (`bash lab/stop.sh`, then kill the QEMU if
   needed).
2. Copy to `labs/cve-2026-98432/lab/`:
   * `cache/ubuntu-24.04-server-cloudimg-amd64.img`
   * `kernel/vmlinuz-6.8.0-106-generic`, `initrd...`, `config...`
   * `ssh/id_ed25519*`, `seed.img` (or regenerate)
3. Create fresh overlays and boot the stock target; record the §0.2 baseline.
4. Copy the useful prior tools (`exp_mptcp.c`, `mpstorm3.c`, `rce_prep.c`,
   `po_base.py`, `mptcp_stream_listener.py`, `mptcp_rfs_listener.py`) into
   `exp/` and `target/`; keep the originals as reference.
5. Run Phase 0/G0 and write the baseline table.
6. Start Phase 1 instrumentation on the twin.

---

## 9. Open questions (please confirm before Phase 0 starts)

1. **Mode T scope.** Under strict default settings, the plain-TCP main path is
   blocked by refcount/app-close serialization. Is a **service-assisted** target
   (we run a TCP service that closes/evicts accepted sockets), or the
   `tcp_migrate_req=1`/BPF-reuseport variant, acceptable for Mode T? Or must it
   be a stock sshd/any server with no service behavior assumptions?
2. **Lab location.** Is `labs/cve-2026-98432/` acceptable, with the large
   images/overlays gitignored? (Alternative: a separate worktree.)
3. **Kernel.** Reuse the exact `6.8.0-106-generic` from the prior lab
   (recommended, matches the prior evidence and is vulnerable), or update to a
   current Ubuntu cloud image that may already be patched?
4. **Priority.** Start Phase 0–1 now, or review/adjust this plan first?

---

## References

* Anthropic Frontier Red Team, "Discovering and exploiting vulnerabilities in
  critical, real-world software with Claude", 2026-10-27.
* CVE-2026-98432 record (kernel.org CNA); upstream fix `e3f33b0a1d89`
  ("ipv4: free inet_opt and ireq_opt after an RCU grace period").
* Prior lab: external `cve_2026_98432-poc` repository (not shipped; its
  `AGENTS.md` and `evidence/` are the relevant references).
* Kernel source reference: Ubuntu noble kernel tree.
  (`net/ipv4/ip_output.c`, `net/ipv4/ip_options.c`,
  `net/ipv4/tcp_ipv4.c`, `net/ipv4/af_inet.c`, `net/mptcp/subflow.c`,
  `net/ipv4/route.c`, `include/net/inet_sock.h`,
  `include/linux/skbuff.h`).
