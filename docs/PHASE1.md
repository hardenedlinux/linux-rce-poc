# Phase 1 — default-settings trigger measurements (2026-11-09)

> Historical note: this phase used the socket-link lab (`192.168.88.0/24`,
> SSH `:2223`). See `docs/LAB-SETUP.md` for the current tap addressing.

Measurement-only work on the instrumented twin. The stock target is untouched;
the twin is the prior lab's known-good `slub_debug=P` overlay.

## Lab state

* Stock target: fresh Ubuntu 24.04 overlay, kernel `6.8.0-106-generic`,
  direct boot with no `slub_debug`, SSH `:2223`, lab NIC `192.168.88.2`.
* Instrumented twin: prior `cve_2026_98432-poc` overlay, same kernel booted
  with `slub_debug=P`, SSH `:2223`, lab NIC `192.168.88.2`.
* Attacker: fresh Ubuntu overlay, SSH `:2224`, lab NIC `192.168.88.1`.
* Link: QEMU socket (rootless), single RX/TX queue per virtio NIC.
* Twins are switched by stopping one and booting the other; both use the same
  `lab0`/`ens4` MAC and address. The attacker's RST block to `:9700` is active.

## Remote MP_JOIN / streaming control (stock target)

`exp_mptcp` from the attacker against `target/mptcp_stream_listener.py`:

```
[t+ 10s] jsyn=1257 jack=1253 rst=670 data=236 base=426 marked=84
[t+ 20s] jsyn=2565 jack=2564 rst=1367 data=466 base=881 marked=135
```

Real MP_JOIN handshake, subflows establish, the target streams with the RR
marker visible. This validates the remote trigger plumbing.

## Probes

`scripts/twin-probes.sh` (content oracle):

```
p:build  ip_build_and_send_pkt  optlen = +24(%r8)
p:rdopt  ip_options_build       optlen = +8(%si), s1 = +23(%si)
p:free   inet_sock_destruct
p:reqfree tcp_v4_reqsk_destructor
filters: build opt != 0 && optlen != 40; rdopt optlen != 40
```

`scripts/twin-correlate.sh` (pointer oracle, definitive even when the content
looks like a normal 40-byte option):

```
p:freeopt inet_sock_destruct  inet_opt = +784(%di)   # BTF: inet_sock.inet_opt
p:rdopt2  ip_options_build    opt = %si               # base = opt - 16
kmem:kmalloc filter bytes_req == 72                   # save_options / 72B reuse
```

A `rdopt2` whose base was last seen in `freeopt` (and not reallocated) is a
UAF read. `freeopt` is the object-bearing free; `inet_sock_destruct` also runs
for many sockets whose `inet_opt` is NULL, so an unfiltered free count is
misleading.

## Results

### A. MPTCP dispose path (dup MP_JOIN SYN + plain ACK)

Raw MPTCP listener (no accept), single queue; `DISPOSE=1`, 20–25 s:

```
jsyn=247 jack=199
build=6682  rdopt=6941  free(all)=6685  reqfree=6679
content anomalies (optlen != 40): 0
```

Pointer correlation (10 s, RFS listener pinned CPU 3, `SO_INCOMING_CPU=3`):

```
freeopt (inet_opt != 0) = 2
rdopt2 = 5609
alloc72 = 5376
UAF candidates (read after free, not reallocated) = 0
```

The option-bearing dispose free rate is tiny with this tool (the prior local
`mpstorm3` storm produced tens of thousands); most ACKs do not reach the
delete path or the child remains referenced. No UAF read.

### B. Data-TX / RST path (streaming listener, MP_JOIN subflow)

`exp_mptcp` with `KILL_DELAY_MS=20`, 25 s:

```
jsyn=3063 jack=3060 rst=1680 data=2032 marked=1050
build=390199  rdopt=439341  free(all)=205110  reqfree=204955
content anomalies (optlen != 40): 0
```

Pointer correlation (10 s):

```
freeopt (inet_opt != 0) = 297
rdopt2 = 146016
alloc72 = 129775
UAF candidates (read after free, not reallocated) = 0
reused reads (read after alloc) = 129083
```

Every read of an option object had a preceding 72-byte allocation; the 297
option-bearing `inet_sock_destruct` frees were never followed by a read before
reallocation. No UAF, even at pointer granularity.

## Interpretation

On a remote target with a single RX queue, both packets of the race are
processed in the same softirq context:

* The dup SYN reader (`tcp_v4_send_synack` -> `ip_build_and_send_pkt`) and the
  final-ACK dispose free (`subflow_syn_recv_sock` -> `tcp_done` ->
  `inet_sock_destruct`) arrive on the same 4-tuple and therefore the same RSS
  queue / CPU. The free happens after the reader; no overlap.
* RFS does not help: the flow entry is per 4-tuple and steers both packets to
  the same CPU. The original MP_JOIN SYN creates the entry before the dup SYN
  and ACK, so all of them share it.
* The data-TX reader is on the application CPU, but the subflow's `inet_opt`
  is not freed while the msk still uses the subflow; the free observed at RST
  is not followed by a reader.
* The prior local lab's cross-CPU race came from **loopback**, where each
  packet is processed in the *sender's* context (the storm thread on CPU 1 and
  the capture/dispose thread on CPU 0). That geometry does not exist for
  packets arriving on one remote NIC queue.

This is the same wall the prior repo documented for the migration/child paths,
now confirmed for the remote dispose path with pointer-level evidence.

## What would change the result

1. **True multi-queue RSS/RFS target**: a tap/vhost NIC with multiple queue
   pairs and per-queue RFS, so the request/child contexts can be on different
   CPUs. Requires host root (`/dev/net/tun`, CAP_NET_ADMIN) or a host bridge.
2. **A free on a different context** than the packet's softirq (workqueue,
   timer pinned to another CPU, or application `close()` racing the reader),
   which the current CVE paths do not provide on a stock single-queue target.
3. **A higher-rate remote dispose storm** matching the local `mpstorm3`
   (single tuple, tight dup SYNs + ACKs). The current `exp_mptcp` dispose mode
   is too slow and leaves most children referenced; this affects the *rate*,
   not the fundamental same-CPU serialization, but it is required before any
   reclaim/leak work can be measured.

## Practical conclusion

Under the strict default target used here (stock Ubuntu, single RX queue, no
target-side tuning), the remote free/read pair is serialized. The next
technical fork is a host-root multi-queue lab (measurement topology, not a
guest setting) or a different free context. Mode T (plain TCP) remains
architecturally blocked for the same reason plus the child/app-close ordering.

## C. Service-assisted send/close (MPTCP listener, plain-TCP RR client)

The kernel rejects `IP_OPTIONS` on an `IPPROTO_MPTCP` socket (`ENOPROTOOPT`),
so the client used the listener's **fallback** path: a plain TCP socket with
an IPv4 RR option, 12 parallel clients for 12 s against
`target/mptcp_sender_listener.py` (accept, send, close after 50-150 ms).

Pointer correlation:

```
freeopt (inet_opt != 0) = 1425
rdopt2                  = 1,072,348
alloc72                 = 1437
UAF candidates (read after free, not reallocated) = 0
reused reads (read after alloc)                    = 1,071,736
```

This is the highest-rate geometry tested: >1M `ip_options_build` reads and
1.4k option-bearing child frees in 12 s. Every read was of a currently
allocated object; the close/send ordering (file/sk references) prevents the
free from overlapping the reader. No UAF.

## Consolidated result

| Path | Reads | Option-bearing frees | UAF reads |
|---|---:|---:|---:|
| MPTCP dispose (dup SYN + ACK) | 7k | ~2 | 0 |
| MPTCP data TX + RST | 439k | 297 | 0 |
| Service send/close (fallback TCP RR) | 1,072k | 1,425 | 0 |

Under the strict default single-queue target, none of the three remote paths
produces a free/read overlap. The only verified UAF is the prior **local**
loopback dispose (different sender CPUs). The public Anthropic chain's target
configuration is not public; reproducing it may require a multi-queue NIC /
RFS timing that this rootless socket-link lab cannot provide, or a target-side
service behavior beyond the stock defaults.

## D. Multi-queue tap topology

The host bridge `br-cve` + multi-queue taps are live.  QEMU attached the tap
with 4 queue pairs (`numqueues 4`); the guest sees `rx-0..rx-3`/`tx-0..tx-3`
and the MSI-X queues are spread across CPUs:

```
virtio3-req.0 CPU0, req.1 CPU1, req.2 CPU2, req.3 CPU3
```

The stock target and attacker boot over the tap; the minimal-seed twin with
`slub_debug=P` also boots over the tap once cloud-init's old config stages are
masked.  RFS is enabled (`rps_sock_flow_entries=32768`, per-queue
`rps_flow_cnt=32768`, `rps_cpus=f`).

MPTCP dispose correlation on the multi-queue link (raw RFS listener pinned
CPU3, `DISPOSE=1`, 10 s):

```
freeopt (inet_opt != 0) = 22
rdopt2                  = 5284
alloc72                 = 5147
UAF candidates (read after free, not reallocated) = 0
```

The queue IRQ spread does not change the result: the dup SYN and the dispose
ACK are the same 4-tuple and stay on the same RSS queue/CPU; RFS's flow entry
is per 4-tuple, so both packets share it.  Multi-queue distributes *different*
flows across CPUs, not the two packets of one request/child race.

**Conclusion:** the multi-queue topology is working and ready for the
migration-path test, but it does not by itself break the same-flow
free/read serialization.  The remaining CVE trigger that can put the clone
free and the reader in different contexts is the request-socket migration
path (`net.ipv4.tcp_migrate_req=1` or a `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE`
program), which is non-default.

## E. Request-socket migration path (non-default)

Authorized non-default test: `net.ipv4.tcp_migrate_req=1` + a two-socket
`SO_REUSEPORT` listener on `:9800` whose worker A closes/rebinds every 8 s.
`exp_migrate` ran 30 s from the attacker (2048 creators, 4.3M RSTs, 80k dup
SYNs, 51k SYN-ACKs).

Pointer correlation (request destructor frees vs `ip_options_build` reads):

```
reqfree (inet_opt != 0) = 366,648
rdopt2                  = 510,777
alloc72                 = 371,703
UAF candidates (read after free, not reallocated) = 0
reused reads (read after alloc)                   = 433,321
```

Wire-level oracle: `xflow=0 churnhit=0`.

Source-level explanation: `reqsk_migrate_reset(oreq)` runs before
`reqsk_put(oreq)` in the timer-migration success path and NULLs the original
`ireq_opt` (the union aliases `ipv6_opt`), so the original destructor does not
free the shared object. The clone keeps a valid pointer. A UAF would require
a concurrent free of the original between clone creation and
`reqsk_migrate_reset`; the 4.3M-RST flood did not produce one in this run.
On this kernel the migration clone is not a shortcut to the shared-option
free.

## Consolidated trigger matrix (pointer-level, no UAF anywhere remote)

| Trigger | Target config | Reads | Option frees | UAF |
|---|---|---:|---:|---:|
| MPTCP dispose, single queue | default + MPTCP listener | 7k | 2 | 0 |
| MPTCP dispose, 4 queues + RFS | default + MPTCP listener | 5.3k | 22 | 0 |
| MPTCP data TX + RST | default + streaming MPTCP | 439k | 297 | 0 |
| Service send/close | default + MPTCP fallback | 1,072k | 1,425 | 0 |
| reqsk migration | `tcp_migrate_req=1` + reuseport | 511k | 366k | 0 |

The only verified UAF remains the prior **local loopback** dispose lab, where
the two packets are processed in different sender contexts. Every remote
single-flow geometry tested here keeps the free and the reader serialized.
