# Settings: stock defaults vs. lab customizations

Measured on the lab target (`cve-instr`, Ubuntu 24.04.4,
`6.8.0-106-generic #106` built 2026-03-06) and the attacker VM.

## 1. Stock defaults (untouched)

### Kernel and boot

```
Linux 6.8.0-106-generic #106-Ubuntu SMP PREEMPT_DYNAMIC
cmdline: root=UUID=6d08... ro console=tty0 console=ttyS0
```

No `slub_debug`, no `nokaslr`, no `mitigations=off`, no `nosmep/nosmap`, no
`oops=panic`. The twin used for the exploit is the same kernel booted with the
stock cmdline (`NO_SLUB=1`).

### CPU mitigations (as reported by the kernel)

| Item | State |
|---|---|
| `randomize_va_space` | **2** (KASLR on) |
| Spectre v1 / v2 | mitigated (usercopy/swapgs barriers; eIBRS + IBPB) |
| Speculative Store Bypass | disabled via prctl |
| MDS/L1TF/MMIO/Retbleed/... | not affected on this CPU |
| SMEP / SMAP | enabled (kernel config, no cmdline opt-out) |

### Sysctls

| Sysctl | Value |
|---|---|
| `kernel.kptr_restrict` | 1 |
| `kernel.dmesg_restrict` | 1 |
| `kernel.unprivileged_bpf_disabled` | **2** |
| `kernel.perf_event_paranoid` | **4** |
| `kernel.apparmor_restrict_unprivileged_userns` | **1** |
| `kernel.io_uring_disabled` | 0 |
| `kernel.modules_disabled` | 0 |
| `net.core.optmem_max` | 131072 |
| `net.ipv4.tcp_max_syn_backlog` | 256 |
| `net.ipv4.ip_forward` | 0 |
| `net.ipv4.conf.all.rp_filter` | 2 |
| `net.core.rps_sock_flow_entries` | 0 (no RPS) |

### Kernel hardening config (relevant)

```
CONFIG_RANDOM_KMALLOC_CACHES=y      # the 2/16 per-boot bucket lottery
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
CONFIG_BPF_LSM=y
CONFIG_KPROBES=y  CONFIG_KPROBE_EVENTS=y  CONFIG_FTRACE=y
CONFIG_MPTCP=y    CONFIG_TLS=m            CONFIG_IO_URING=y
# CONFIG_STATIC_USERMODEHELPER is not set
```

`debugfs` and `tracefs` are mounted by default (`/sys/kernel/debug`,
`/sys/kernel/tracing`) but are root-only.

### Network

* virtio-net with 4 combined queues (from QEMU `mq=on,queues=4`).
* `ens4` is **down** until the harness configures it; no RPS, no aliases.
* Minimal module set; `kvm`, `9pnet_virtio` etc. only.

## 2. Lab customizations (non-default)

### Target side — required for the exploit

| Customization | Command / file | Privilege |
|---|---|---|
| tracefs stretch probes | 46 `p:oN ip_build_and_send_pkt+N` + `p:rdopt2 ip_options_build` with `optlen>60` filter | **root** on target |
| MPTCP keeper listener | `:9800` `target/mptcp_raw_listener.py` | root |
| TCP_SAVE_SYN listener | `:9801` `target/tcp_save_syn_listener.py` | root |
| Controlled page `G` | `lab/ringone.py`: AF_PACKET TX ring (12×4K), `/proc/self/pagemap` PFNs, `/proc/kcore` `page_offset_base`, vmsplice pin | **root** (CAP_NET_RAW) |
| Reclaim sprays | `exp/keyspray`, `exp/unixspray` | unprivileged (`ubuntu`) |
| Post-root containment | payload runs `fuser -k 9800/tcp 9801/tcp`, `pkill keyspray/unixspray` | root (via UMH) |
| SUID persistence | `cp /bin/bash /tmp/rootbash; chmod 4755` | root |

### Target side — lab tuning (not exploit semantics)

| Customization | Value | Default |
|---|---|---|
| `ens4` up + address | `192.168.89.2/24` | down |
| RPS global table | `net.core.rps_sock_flow_entries=32768` | 0 |
| RPS per-queue flow count | `rps_flow_cnt=32768` (rx-0..3) | 0 |
| RPS CPU mask | `rps_cpus=f` (all 4 CPUs) | 0 |
| combined queues | `ethtool -L ens4 combined 4` | already 4 with the lab NIC |

### Attacker side

| Customization | Purpose |
|---|---|
| `192.168.89.1/24` + `192.168.89.11-30/24` aliases | source-IP steering of RSS queues |
| `/tmp/mpsetup89.py` | MPTCP base connection + server-token extraction |
| `lab/bin/mpstorm3_mix4` | raw SYN/ACK storm + internal saved_syn spray |
| `lab/shell_handler.py` | reverse-shell listener; kills the storm on connect |
| `tc netem 1ms` + `iptables MARK` (saved-bucket trials only) | delay only RSTs, extend saved_syn lifetime |

### Measurement-only

* F/L probes (`p:freeopt inet_sock_destruct`, `p:rdopt2 ip_options_build`).
* `lab/campaign.sh`, `lab/find-match-any.sh`, `lab/any_match.py` (boot hunt).
* 9p share (`/mnt/lab`), serial logs, QEMU monitor sockets.

## 3. Which gate each customization serves

| Gate | Customization |
|---|---|
| G1 race window (deref→use 5–10 ns vs 1–54 µs free) | 46 stretch probes + `rdopt2` |
| G2 trigger/reader | MPTCP :9800 + TCP_SAVE_SYN :9801 |
| G3 known controlled page | `ringone.py` (root ring + pagemap + kcore) |
| G4 reclaim bucket (2/16) | `keyspray` / `unixspray` at the matching call site |
| cross-CPU geometry | 4-queue tap + RPS + attacker IP aliases |
| post-root survival | stop-on-connect handler + containment payload |

## 4. Honest statement

The exploit runs on a stock Ubuntu 24.04.4 kernel and preserves its mitigations
(KASLR, SMEP/SMAP, `RANDOM_KMALLOC_CACHES`, `SLAB_FREELIST_HARDENED`,
`HARDENED_USERCOPY`), but it **requires the target-side customizations in
§2**: tracefs kprobes, two custom listeners, and a root `CAP_NET_RAW` ring.
It is therefore a *stock-kernel, service-assisted, instrumented* PoC — not a
default-settings remote exploit. The reliability section in
`docs/CAPABILITY.md` quantifies the remaining 2/16 bucket lottery.
