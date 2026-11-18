# CVE-2026-98432 — Linux IPv4/TCP use-after-free lab

Two-VM lab (attacker + stock Ubuntu 24.04 target) for CVE-2026-98432, the
Linux IPv4/TCP `ireq_opt`/`inet_opt` use-after-free on
`6.8.0-106-generic`.

## CVE at a glance

**CVE-2026-98432** is a remote, unauthenticated use-after-free race in the
Linux IPv4 TCP handshake. `tcp_v4_syn_recv_sock()` transfers `ireq->ireq_opt`
to the child socket, while a retransmitted SYN can still build a SYN-ACK from
the request socket; `inet_sock_destruct()` and `tcp_v4_reqsk_destructor()`
then free the options with a plain `kfree()` instead of `kfree_rcu()`. The
upstream fix is `e3f33b0a1d89` (“ipv4: free inet_opt and ireq_opt after an RCU
grace period”).

The public research was published by Anthropic’s Frontier Red Team on
2026-10-27 and demonstrated remote root against an MPTCP listener. The
Ubuntu 24.04.4 `6.8.0-106-generic` image used here is vulnerable; Ubuntu
24.04 is fixed in `6.8.0-149.149` (released in mid-November 2026), so check
the vendor tracker for your running kernel. Severity is reported as 9.8 by
the kernel CNA and as Important (8.1) by Red Hat; vendor scores differ.

Full details, patch snippet, affected/fixed versions and references are in
[`docs/CVE.md`](docs/CVE.md).

## End goal

Full remote code execution against a **default-settings Ubuntu 24.04.4
(`6.8.0-106-generic`) target**, over both of the CVE's reachable paths:

1. **MPTCP** — a reachable MPTCP listener/service.
2. **Plain TCP** — e.g. `sshd` or another ordinary TCP service, with no
   special service behavior.

“Default settings” here means: stock kernel cmdline, KASLR, SMEP/SMAP,
`RANDOM_KMALLOC_CACHES`, `SLAB_FREELIST_HARDENED` and `HARDENED_USERCOPY`
enabled; no target-side root setup; no kprobes, custom listeners or root
AF_PACKET ring; no reboot-to-win cache lottery; and the target stays alive
after exploitation.

**This is the goal, not the current state.** The shipped result is a
stock-kernel lab PoC with target-side instrumentation and a service-assisted
setup; it is not a default-settings exploit. The rest of this README records
what is actually proven and what remains.

## Status at a glance

| Path / primitive | Status |
|---|---|
| MPTCP trigger + full chain to `call_usermodehelper` | **works in the lab** (instrumented, service-assisted) |
| MPTCP on a default-settings target | **not achieved** |
| Plain TCP / `sshd` trigger | **not achieved** — request path is refcount-serialized; 0 genuine hits in 16M+ prior attempts |
| Wire-only KASLR slide | **achieved** (`iomap_dio` over-read, no `/proc/kallsyms`) |
| Wire-derived controlled page `G` | **demonstrated separately** (`pg_vec` over-read, zero kprobes; ring allocation still root) |
| Zero-kprobe payload fire | reached UMH **once**, then crashed; not a stable root (raw log not included) |
| Non-destructive root | **achieved in some runs**; later panics observed in others |
| Independent reproduction | **yes** — 2026-11-18 libvirt run: root, SUID, alive at 20 s and ~5 min |
| Boot-agnostic reclaim | **not achieved** — reliable buckets cover 2/16 per boot |
| Unprivileged controlled page | **not achieved** — candidate routes structurally blocked |

Evidence for the headline claim: `evidence/REPRO-root-*.txt` and
`evidence/REPRO-libvirt-20261118.txt`.

## What works today

### MPTCP full chain (lab only)

On a stock Ubuntu 24.04.4 `6.8.0-106-generic` boot, the lab obtains a remote
root reverse shell:

```
UAF -> CPU-local reclaim -> controlled OOB into skb_shared_info
    -> fake sk_buff -> call_usermodehelper_exec -> /bin/bash reverse shell
```

Verified result:

```
seed 0xda78b74fa99cd1e9, bucket key, src .11, F=2 L=1
root=1  alive5=1  alive20=1  suid=1  ttr=42s
handler: CONNECTED (192.168.89.2) -> uid=0(root) -> SHELL_OK
```

A second, independent libvirt run reproduced it on seed
`0x4ab38ffb48e8e4a` with `root=1`, SUID `/tmp/rootbash`, and the target
still reachable beyond 5 minutes.

The successful chain currently needs **all** of the following:

* a boot whose random-kmalloc bucket matches a persistent reclaim object
  (`user_key_payload` or `unix_address`; **2/16** boots, ~8 boots per match);
* 46 tracefs stretch probes on `ip_build_and_send_pkt` + `rdopt2`;
* a root `CAP_NET_RAW` AF_PACKET ring (`lab/ringone.py`) for the controlled
  page `G`;
* the MPTCP keeper `:9800` and `TCP_SAVE_SYN` listener `:9801`;
* target-side `keyspray`/`unixspray` and the attacker-side storm/handler.

Those are target-side, non-default enablers. The stock mitigations are not
disabled: KASLR, SMEP/SMAP, `RANDOM_KMALLOC_CACHES`,
`SLAB_FREELIST_HARDENED` and `HARDENED_USERCOPY` stay on.

### Address discovery

* **Wire-only KASLR slide:** an `iomap_dio` neighbour over-read leaks
  `ext4_dio_write_ops`; the slide and `EX`/`WK` are derived from wire bytes
  plus the public kernel image, with no `/proc/kallsyms`.
* **Wire-derived `G`:** a `pg_vec` neighbour over-read leaks page-aligned
  ring addresses with zero kprobes. The ring allocation still comes from the
  root `CAP_NET_RAW` AF_PACKET path; replacing that with an unprivileged
  object is blocked (`docs/HUNT3-WIRE-G.md`). The latest root shell used the
  in-VM `page_offset_base`/pagemap path; combining wire slide and wire `G` in
  one boot remains a boot-lottery stretch goal.

### Reproduction

The automated campaign and the manual in-guest verification checklist are in
[`docs/LAB-SETUP.md`](docs/LAB-SETUP.md) §5–§6.1. The operator checklist is
[`AGENTS.md`](AGENTS.md).

## What does not work yet

### Plain TCP / `sshd`

The plain-TCP request path is refcount-serialized: `tcp_v4_send_synack` holds
a request reference and `tcp_v4_reqsk_destructor` runs after the reader. Prior
work recorded **0 genuine hits in 16M+ attempts**; `sshd` cannot be the target
of this chain as written. The data-TX/JOIN reader is also unavailable on the
stock 6.8 kernel because no `mptcp_sched_roundrobin` module is shipped.

### Default-settings MPTCP

The lab chain is not a default-settings exploit because of five independent
gaps:

1. **Race amplifier.** The natural reader window is ~5–10 ns while the free
   lands 1–54 µs later; the 46 `int3` probes are what make the race reliable.
   Natural alternatives (RPS-IPI flood, virtio-blk IRQs, dense duplicate
   sampling) produced **0 over-reads in ~4.6 ks**.
2. **Known controlled page.** The controlled page uses a root AF_PACKET ring;
   an unprivileged 96-byte-object route is structurally blocked (see
   [`docs/HUNT3-WIRE-G.md`](docs/HUNT3-WIRE-G.md)).
3. **Service-assisted target.** The MPTCP keeper and `TCP_SAVE_SYN` listener
   are extra target-side services, not default Ubuntu behavior.
4. **Boot lottery.** `RANDOM_KMALLOC_CACHES` puts a given reclaim object and
   the victim in different buckets on ~15/16 boots; the two reliable buckets
   give 2/16 coverage. A live target has one fixed boot; the lab reboots to
   win.
5. **Post-root survival.** The fake-skb release can produce a
   `free_large_kmalloc` warning and later panics; some archived fires panic
   at 335–419 s, while other runs (including the 2026-11-18 re-run) survived
   beyond 5 minutes. “`alive20=1`” is a 20 s checkpoint, not a guarantee.

### Other negative results

* **4-way wire hunt:** `find-match-quad.sh 3000` finished with
  `NO_QUAD_IN_3000`; a single-boot wire-slide + wire-`G` root remains a
  stretch goal.
* **`saved_syn` bucket:** layout verified, but the aimed raw-SYN spray
  starves the target's free path; it is not a reliable reclaim bucket
  (`0/6` fires).
* **AF_ALG / unprivileged BPF / perf:** the stock image disables or blocks
  these paths; see [`docs/SETTINGS.md`](docs/SETTINGS.md).

## What is needed for the end goal

The remaining work is research, not a packaging step:

1. **Boot-agnostic reclaim** — cover all 16 random kmalloc buckets (a
   multi-bucket spray, a same-call-site reclaim with a large `optlen`, or a
   per-boot bucket-discovery leak).
2. **Non-destructive payload** — avoid or repair the fake skb's invalid
   `kfree` so the target cannot panic.
3. **Natural race amplifier** — a stock mechanism that spans the
   dereference-to-free gap without kprobes.
4. **Unprivileged controlled page** — a stock object that gives a known
   direct-map address without `CAP_NET_RAW` or root.
5. **Plain-TCP trigger/reader** — a path that is not serialized by the
   request reference, so ordinary services such as `sshd` become reachable.
6. **Remove the service-assisted assumptions** — no custom MPTCP keeper or
   `TCP_SAVE_SYN` listener on the target.

The current chain is a strong proof of the UAF and of the full kernel-to-root
control-flow path, but it does not yet satisfy any of the default-settings
requirements above.

## Progress

| Date | Milestone |
|---|---|
| 2026-11-09 | Stock target baseline; trigger and leak measurements (`docs/BASELINE.md`, `docs/PHASE1.md`) |
| 2026-11-10/11 | Repeated remote UAF read; reclaim geometry (`docs/PHASE2.md`, `docs/PHASE3-RECLAIM.md`) |
| 2026-11-12 | Controlled fake skb -> UMH -> root shell; wire-only KASLR slide (`docs/PHASE4-RINGPAYLOAD.md`) |
| 2026-11-17 | Key/unix reclaim buckets; 6/6 reliable-bucket campaign; `saved_syn` negative result (`docs/CAPABILITY.md`) |
| 2026-11-18 | Independent libvirt reproduction; documentation and manual verification added (`evidence/REPRO-libvirt-20261118.txt`) |
| 2026-11-18 | 4-way wire hunt completed: `NO_QUAD_IN_3000` (stretch goal) |

The detailed capability report is [`docs/CAPABILITY.md`](docs/CAPABILITY.md).
The structural arguments live in
[`docs/HUNT1-ORDERING.md`](docs/HUNT1-ORDERING.md) and
[`docs/HUNT3-WIRE-G.md`](docs/HUNT3-WIRE-G.md).

## Start here

| Document | Contents |
|---|---|
| [`AGENTS.md`](AGENTS.md) | build, boot, reproduce and operator checklist |
| [`docs/LAB-SETUP.md`](docs/LAB-SETUP.md) | two VMs, host requirements, images/kernels (not shipped), tap/socket link, ports, 9p, manual verification (§6.1) |
| [`docs/CVE.md`](docs/CVE.md) | CVE record, root cause, fix, severity, affected/fixed versions, references |
| [`docs/SETTINGS.md`](docs/SETTINGS.md) | verified stock defaults vs. every lab customization |
| [`docs/CAPABILITY.md`](docs/CAPABILITY.md) | proof chain, measured campaign, reliability, limitations |
| [`docs/HUNT1-ORDERING.md`](docs/HUNT1-ORDERING.md), [`docs/HUNT3-WIRE-G.md`](docs/HUNT3-WIRE-G.md) | why the kprobe and root-ring dependencies are structural |
| [`evidence/REPRO-libvirt-20261118.txt`](evidence/REPRO-libvirt-20261118.txt) | independent libvirt re-run |
| [`PLAN.md`](PLAN.md), `docs/PHASE*.md`, `docs/BASELINE.md`, `docs/MULTIQUEUE.md` | historical development record (not current status) |

## Repository layout

```
AGENTS.md            operator / reproduction guide
README.md            this overview
PLAN.md              historical plan and threat model
docs/                capability report, lab setup, settings, hunt notes, phase history
exp/                 C exploit sources (storm, sprays, trigger/leak helpers)
exp/bin/             prebuilt static x86-64 spray binaries
lab/                 launch/stop, campaign, boot hunts, ringone, handler, SSH helpers
lab/bin/             prebuilt storm binaries
target/              target-side MPTCP keeper and TCP_SAVE_SYN listener
scripts/             parsers and wire-slide helpers
evidence/            root/fire logs, campaign CSVs, serial captures, pcaps
lab/harness/         cloud-init templates (large images/seeds are not shipped)
```

## Open-source and relocation

Large artifacts (VM images, kernels, SSH keys, caches) are not shipped; see
`.gitignore` and [`docs/LAB-SETUP.md`](docs/LAB-SETUP.md) §3 for how to
recreate them. The cloud-init templates in `lab/harness/`, the prebuilt
sprays in `exp/bin/` and the evidence files are part of the open-source tree.

The harness is relocatable: every host-side path is derived from the script's
own location. Absolute paths in the exploit code are guest-side paths
(`/tmp`, `/proc`, `/sys`, `/mnt/lab`) and are intentional; no author-machine
path is hard-coded.

## Safety

Authorized local-lab work only. The exploit arms kprobes, opens listeners and
kills its own sprays/listeners on the target; do not run it on shared or
production hosts. The target-side enablers in `docs/SETTINGS.md` are required
for the current result.
