# Phase 0 baseline — stock target + attacker (2026-11-09)

> Historical note: this Phase 0 baseline used the socket link (`192.168.88.0/24`,
> SSH `:2223`). The current tap campaign uses `192.168.89.0/24` and the
> ports in `docs/LAB-SETUP.md`; see that document for the live setup.

## Lab

* Host: KVM, 4 vCPU guests, QEMU socket link (rootless).
* Target: fresh Ubuntu 24.04 cloud overlay, direct boot of
  `vmlinuz-6.8.0-106-generic`, no `slub_debug`.
* Attacker: fresh Ubuntu 24.04 overlay on the other end of the socket link.
* Link: `lab0` target `192.168.88.2/24`, attacker `192.168.88.1/24`.
  Management: target SSH `localhost:2223`, attacker SSH `localhost:2224`.
* Single RX/TX queue per virtio NIC (QEMU socket backend), RFS off.

## Target defaults verified

```
uname -r                6.8.0-106-generic
/proc/cmdline           root=UUID=... ro console=tty0 console=ttyS0
net.mptcp.enabled       1
tcp_migrate_req         0
tcp_syncookies          1
tcp_fastopen            1
rps_sock_flow_entries   0
nproc / RAM             4 / 3.8 GiB
rootfs                  6.8G, ~5.1G free (growpart worked)
```

Kernel config (from `/boot/config-6.8.0-106-generic`):

```
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_RANDOM_KMALLOC_CACHES=y
CONFIG_MPTCP=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set
# CONFIG_SLUB_DEBUG_ON is not set
```

Runtime hardening / restrictions:

```
_text (root kallsyms)    ffffffffa7400000  (KASLR on; not the 0xffffffff81000000 base)
kptr_restrict            1
dmesg_restrict           1
perf_event_paranoid      4
unprivileged_bpf_disabled 2
/sys/kernel/debug/tracing  permission denied to the unprivileged user
```

Services: sshd `:22`, systemd-resolved `:53`; no MPTCP listener by default.
`ss -Mltn` only lists the MPTCP listener once we start one.

## Remote MP_JOIN handshake (attacker -> stock target)

Command (attacker, root for `CAP_NET_RAW`):

```
iptables -I OUTPUT -p tcp --dport 9700 --tcp-flags RST RST -j DROP
/tmp/exp_mptcp 192.168.88.2 9700 20
```

Target service: `target/mptcp_stream_listener.py` (IPPROTO_MPTCP, :9700),
which accepts and streams 1460-byte writes.

Observed:

```
[*] base MPC SYN-ACK: server key ...
[*] base MP_CAPABLE: client key ...
[*] slot=0 MP_JOIN SYN-ACK: nonce=... thmac=...
[hmac] ...
[t+ 10s] jsyn=1257 jack=1253 rst=670 data=236 base=426 marked=84 xflow=0 churnhit=0 foreign=0 churn=146816
[t+ 20s] jsyn=2565 jack=2564 rst=1367 data=466 base=881 marked=135 xflow=0 churnhit=0 foreign=0 churn=293376
```

`jsyn`/`jack` > 0: real MP_JOIN SYNs are answered and acknowledged.
`data`/`marked` > 0: the target streams data on the joined subflows with our
RR marker visible. `xflow=0`: no cross-flow marker observed in this short run
(expected; the teardown race/reclaim is still open).

Target counters after the run:

```
MPTcpExtMPJoinSynRx        2512
MPTcpExtMPCapableSYNRX       25
MPTcpExtMPCapableACKRX       25
```

## Lab fixes made during bring-up

* The management NIC (`-net nic`) and the lab NIC had the same MAC
  (`52:54:00:12:34:56`), so `systemd-networkd-wait-online` hung and SSH never
  came up. Fixed with distinct management MACs (`52:54:00:aa:00:0N`) and a
  netplan file matching the lab NIC by MAC (`lab0`).
* Fresh overlays are created by `lab/make-seeds.sh <role>`; this is also the
  clean-snapshot mechanism (stop the VM, re-run, boot).
