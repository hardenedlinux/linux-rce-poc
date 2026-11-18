# Phase 4 — controlled-page leak + ring-page payload (tri-match boot)

> Historical phase (2026-11-12); current status is in `README.md` and
> `CAPABILITY.md`.

## The tri-match

`lab/find-match-tri.sh` boots the stock twin until

    victim_idx == saved_idx == alloc_pg_vec_idx

(kmalloc-96).  Found on boot 23 of one run: seed
`0x6ffd2cc6684a4624`, all three bucket 3.  `alloc_pg_vec.isra.0+0x2c`
allocates `block_nr*8` bytes; with `block_nr=12` that is 96 B.

## The controlled-page leak (works)

`lab/ringspray2.py <cpu> <n>` creates AF_PACKET PACKET_TX_RING rings
(12x4K blocks) on the victim CPU.  The `pg_vec` array is a kmalloc-96
object in the victim cache; its entries are `__get_free_pages()` addresses
of the ring blocks, which userspace mmaps.  When a `pg_vec` is the UAF
neighbour, the over-read SYN-ACK leaks those **page-aligned kernel
addresses** (no kcore/pagemap):

    evidence/ringpage-leak.pcap
    pkt2 nb: 0xffff8ac02645d000 0xffff8ac02645c000
    pkt3 nb: 0xffff8ac0270f2000 0xffff8ac0283af000
    later:   0xffff8ac01c1fd000 0xffff8ac01c1fe000 ...

## Payload recipe

1. `ringspray2.py` polls `/tmp/fakecfg` = `G EX WK cmd`.  On change it builds
   the prior-art fake `sk_buff`+`subprocess_info` page blob with P=G
   (`work.entry` self-pointers absolute `P+0x18`, destructor at `P+0x70`,
   `head=P+0x100`, `end=0x100`, `fclone_ref=5`, shinfo.dataref=2 at
   `P+0x220`, strings/argv/envp at `P+0x400..`) and writes it into every 4K
   block of every ring.
2. `G` is the leaked ring page; fake skb S = `G+0x10`; `frag_list=S`.
3. Pre-spray neighbour saved_syns in `SPRAY_IPOPT4` mode (96-byte slot) with
   `PAYLOAD_FRAG=G+0x10`: neighbour+82/83 -> o[26]/o[27] = nr_frags/tx_flags
   = 0, neighbour+88..95 -> o[32..39] = frag_list = G+0x10.
4. Victim reclaim with source `192.0.0.0` (saved_syn optlen=192) on the
   victim CPU F, main flow source e.g. `192.168.89.21`, fragmented dup
   readers on L.  The OOB copy overwrites shinfo, the skb free calls
   `sk_buff->destructor = call_usermodehelper_exec` with the fake
   subprocess_info, and the helper runs as root.

Symbols are resolved from the boot slide: on seed 0x6ffd2cc6 the twin had
`_text=0xffffffffaea00000`, `call_usermodehelper_exec=0xffffffffaeb2d4b0`,
`call_usermodehelper_exec_work=0xffffffffaeb2d920`.

## Current blocker

The tri-match boot is still up, but after the ring restarts/token churn the
target throughput collapsed (`synacks` 0.6-1.1M/120s -> 0.19M/220s; readers
~800/s) and the over-read became too rare to catch a fresh G from the
current (updatable) rings.  The earlier runs did catch 2-7 over-reads per
120 s, so this is host-load/timing, not a primitive failure.

Next: wait for the host load to drop (the parallel session shares the box),
then run the leak until a page-aligned G is captured, write `/tmp/fakecfg`,
pre-spray the `PAYLOAD_FRAG` neighbour and fire the victim reclaim.

Caveat unchanged: the reader probe/stretch is still what makes the race
reliable; the strict no-kprobe final target remains open.

## First payload firing — near miss (nr_frags)

The 47-probe stretch made the leak reliable (127 over-read packets, 184
page-aligned ring addresses in 60 s).  With `G=0xffff8ac01c1e3000` the
updater wrote the fake skb page.  The 192.x victim reclaim (92-byte
saved_syn) fired the OOB, but the neighbour happened to be another 92-byte
saved_syn whose TCP-option NOP padding supplied `nr_frags=1`; the real skb's
`skb_release_data` iterated frags with a NULL page and panicked
(`CR2=0x8`, `skb_release_data+0x10e`) **before** the `frag_list`/destructor
path.  Evidence: `evidence/payload-nrfrags-panic-*.log`.

Fix: use `SPRAY_IPOPT4=1` for the **192.x victim stream as well**.  The
4-byte-IP-option saved_syn is exactly 96 B, so:
* its `optlen` (= source IP byte 0 = 192) still drives the 192-byte copy;
* both the victim and its neighbour are the same payload object, and the
  neighbour's controlled options set `nr_frags=0`, `tx_flags=0`,
  `frag_list=G+0x10` (slot+88..95 = TCP options 32..39, no padding).

The panic lost the tri-match boot; re-run `lab/find-match-tri.sh`, then fire
stage 2 with `SPRAY_IPOPT4=1 SPRAY_SRC=192.0.0.0 PAYLOAD_FRAG=G+0x10`.

## The heap-state conflict (second firing)

The 47-probe stretch leaked reliably (7 packets, 6 pg_vec neighbours, 12
page-aligned G on the tri-match boot, G=0xffff8de025708000).  The corrected
IPOPT4 victim stream still panicked at `skb_release_data+0x10e`
(`nr_frags>0`, CR2=0x8): the victim's neighbour was a **pg_vec**, not the
IPOPT4 saved_syn.  Evidence: `evidence/payload-pgvec-nrfrags-panic-*.log`.

Why this is structural:
* leak: dense `pg_vec` objects in the kmalloc-96 cache => the UAF neighbour
  is a `pg_vec`, leaking ring-page addresses;
* payload: the neighbour must be a saved_syn with controlled
  `nr_frags=0/tx_flags=0/frag_list=G+0x10`;
* with a `pg_vec` neighbour, `frag_list` at neighbour+88 is an 8-byte
  pointer (good) but `nr_frags` at neighbour+82 is byte 6 of the previous
  ring pointer (always non-zero); the 6-byte shinfo spacing (+2 vs +8)
  makes a clean pair impossible for the 8-byte-stride pg_vec.

So the leak and the payload need **different heap states**.  Options:
1. pin the G ring page (page ref) and free the other rings before firing
   (test `vmsplice`/GUP on the PFNMAP ring mapping);
2. keep only the ring owning G and free the rest (needs ring identity via
   pagemap/kcore -- a target-side helper);
3. displace the pg_vecs in the victim's active slab with a much heavier
   IPOPT4 pre-spray (cheapest next experiment);
4. a controlled-page primitive that does not occupy the victim's cache.

## Next plan (prime -> fire)

1. Dense rings + 47 probes -> leak G (pg_vec neighbour).
2. Updater writes the fake skb page at G.
3. **Prime** the victim CPU's active kmalloc-96 slab with IPOPT4 payload
   saved_syns (unprobed, heavy, short) so the creator's next
   ip_options_rcu lands in an IPOPT4-dense slab; the unprobed over-read
   rate is low, so a stray pg_vec panic during priming is unlikely.
4. Arm the 47 probes and fire the IPOPT4 192.x victim stream; the first
   over-read should now have a saved_syn neighbour with
   nr_frags=0/tx_flags=0/frag_list=G+0x10 -> destructor ->
   call_usermodehelper_exec -> root helper.
Fallbacks: pin the G page and free the rings (test vmsplice/GUP on the
PFNMAP ring mapping), or identify the G ring via pagemap/kcore (helper).

## Pin/free ordering (third firing)

The vmsplice pin is proven (48 KiB pinned; socket+mmap closed; pipe read
returns the page content).  In the firing the pre-spray/victim started
~6 s after `/tmp/pinfree`, but pinning 1600 rings had not finished (no
`pinned N/N` line), so pg_vecs were still present and the victim neighbour
was again a pg_vec -> nr_frags panic.  Fix: after touching `/tmp/pinfree`,
**poll `/tmp/ringsP.log` until `pinned`** (up to ~120 s), verify N/N and the
updater process alive, and only then run the pre-spray + victim.
Evidence: `evidence/payload-pinrace-panic-*.log`.

## Fourth firing (pin succeeded; old saved_syn neighbours)

The vmsplice pin completed for both ring processes (`pinned 1600/1600;
pg_vecs freed`) before the pre-spray/fire.  The fire still went down.  The
remaining 92-byte neighbours are the **leak stream's own saved_syns** (the
107.x spray, standard TCP options, `o[26]`=NOP), which live ~63 s and still
populate the cache when the payload fires; their neighbour bytes give
`nr_frags=1`.

Fix for the next attempt: after the pin, **flush the TCP_SAVE_SYN/MPTCP
listener state** (restart :9801/:9800 and get a fresh token) so the old
92-byte saved_syn reqs are dropped, then pre-spray only IPOPT4 payload
objects and fire.

## ROOT — remote chain fired

The refined sequence succeeded:
1. 47-probe leak, `G=0xffff8ba621e18000` (F=3/L=1, 8 pg_vec neighbours).
2. updater wrote the fake skb page with P=G.
3. `vmsplice` pinned all 1600 rings (`pinned 1600/1600; pg_vecs freed`),
   freeing the pg_vec arrays while keeping the G page alive.
4. listeners restarted (flush old 92-byte saved_syns) + fresh token.
5. IPOPT4 pre-spray + IPOPT4 192.x victim fire.
6. helper command ran as root: `/home/ubuntu/PWNED` = uid=0(root),
   `/home/ubuntu/rootbash` = SUID root.  The kernel panicked after the
   helper; the persistent files prove the root escalation.

Root shell: `/home/ubuntu/rootbash -p -c id` -> uid=0(root).

## Wire-only KASLR slide (validated)

`scripts/wire_slide.py <leaked_ptr>` uses the public kernel image
(`vmlinux-to-elf` of `vmlinuz-6.8.0-106-generic`) to turn a leaked pointer
into the KASLR slide:
* for each 2 MiB-aligned slide, `static = leaked - slide`;
* report candidates where `static` is a text symbol start or points at a
  printable string in `.rodata`.

Validated on the captured leak `0xffffffff8fa27a28`: the true candidate is
`slide=0x0CE00000`, `static=0xffffffff82c27a28` = the `devlink` string in
`.rodata`.  Then `call_usermodehelper_exec = static_exec + slide` etc., with
the static addresses from the same image.  This removes `/proc/kallsyms`
from the payload path.

## Next validation: no-kprobe, wire-only

Requirements unchanged for the reclaim/ring cache: a tri-match boot.  With
no stretch probes the measured over-read/reuse rate is ~1 per 10 min; the
leak (`.rodata` slide + `pg_vec` ring page) and the payload need long
runs.  The remaining default-settings gaps are still RPS (gap 2, possibly a
QEMU-tap artifact) and the CAP_NET_RAW ring service (gap 4).

## No-kprobe fire reached call_usermodehelper (breakthrough)

On boot 43 (tri-match, seed 0xb77a090f265cbe97) the **entire fire ran with
zero kprobes** (`kprobe_events` empty):
* `G` came from a no-kprobe over-read: `0xffff8e41ad472000` (pg_vec
  neighbour, page-aligned).
* fake skb staged with `P=G`, `destructor = call_usermodehelper_exec`,
  `work.func = call_usermodehelper_exec_work`;
* 1600 rings pinned, pg_vec arrays freed, listeners flushed, IPOPT4
  pre-spray + fire for 900 s.

The payload **fired**: the serial shows

    Workqueue: events_unbound call_usermodehelper_exec_work
    RIP: 0010:0x0
    Call Trace:
     call_usermodehelper_exec_work+0x59/0xd0
     process_one_work+0x181/0x3a0

So the UAF -> OOB -> fake skb -> destructor -> workqueue chain works with
**no target-side kprobes**.  The crash is not the exploit: the destructor
`call_usermodehelper_exec(skb, RSI)` receives a garbage `wait` from the
leftover RSI of the skb-free path (`skb_release_head_state` passes only
RDI=skb).  With `wait != UMH_NO_WAIT`, `call_usermodehelper_exec` sets
`complete = &done` on its stack, may not wait for a non-enumerated value,
and the work later calls `complete(&done)` on a dead stack -> RIP=0.

### Deterministic fix: force wait = UMH_NO_WAIT

`skb_release_head_state` first does `dst_release(skb->_skb_refdst)` when
`_skb_refdst` is non-NULL with low bit 0, and `dst_release` returns with
`esi = 0`.  So the blob now sets

    skb->_skb_refdst (skb+0x58) = P + 0x900      (fake dst, low bit 0)
    *(u32 *)(P + 0x940)         = 0x40000000     (fake dst __refcnt)

`skb_release_head_state` then calls `dst_release` (RSI=0), clears
`_skb_refdst`, and calls `destructor(skb)` with RSI=0 -> `wait =
UMH_NO_WAIT` -> `call_usermodehelper_exec` queues the work and returns;
the work takes the async branch (`user_mode_thread`), so there is no
`complete()` and no `kfree(sub_info)`.  Implemented in `lab/ringspray3.py`.

Evidence: `evidence/nokprobe-fire-umh-crash-*.log`.

## Firing 2: bad neighbour crashed in skb_release_data

On boot 112 (tri-match, seed 0x7ccfd31b21112ea7) the probe fire reached
`skb_release_data+0x10e` -> NULL at `frags[0].bv_page+8`.  The OOB copy
mapped `nr_frags` from a **leftover standard 92-byte saved_syn** (20-byte
IP header) from the leak, not from a 96-byte IPOPT4 payload object.  In a
standard saved_syn the TCP option area starts 4 bytes earlier, so the
shinfo `nr_frags` byte maps to `o[30]` = 1 (NOP) -> the frags loop runs
with a bogus `bv_page` and panics *before* `frag_list` (the fake skb) is
processed, so the destructor never runs.

Fix: run the **leak spray in SPRAY_IPOPT4 layout too** (96-byte saved_syn,
`o[26]=o[27]=0`, `o[32..39]=0`, no PAYLOAD_FRAG).  Then every saved_syn
neighbour is either
* a fire payload object (`o[26]=o[27]=0`, `o[32..39]=G+0x10`) -> fires, or
* a leak object / freed slot (`nr_frags=0`, `frag_list=0`) -> harmless.
Only the IPOPT4 96-byte geometry is used, so a bad neighbour can no longer
panic before the destructor.

Evidence: `evidence/nokprobe-fire-fragloop-crash-*.log`.

## REMOTE ROOT REVERSE SHELL (double-match boot 2)

Boot 2 of the 2-way hunt: `seed=0x51073f4627212719`,
`victim=saved_syn=15` (only the reclaim-cache match is needed once `G` is
obtained deterministically).

Addresses (in-VM ground truth for this validation):
`_text=0xffffffffb8400000`, `EX=call_usermodehelper_exec=0xffffffffb852d4b0`,
`WK=call_usermodehelper_exec_work=0xffffffffb852d920`,
`page_offset_base=0xffff8daec0000000`.

Deterministic controlled page:
`lab/ringone.py` created one PACKET_TX_RING, read the real PFN from
`/proc/self/pagemap`, computed `page = page_offset_base + PFN*4096 =
0xffff8dafc45bb000`, wrote the fake skb at `S = page+0x10 =
0xffff8dafc45bb010`, pinned 48 KiB with `vmsplice` and freed the pg_vec.

Fire: `MIXED_FRAG=1`, source `.27` (**F=3/L=2**), IPOPT4 saved_syn spray
(107.x pre-spray, 192.x fire), `PAYLOAD_FRAG=S`, 46 `ip_build_and_send_pkt`
stretch probes + `rdopt2`.

Result: the helper executed and the target opened a **reverse shell to the
attacker**:

    Connection received on 192.168.89.2 53616
    root@cve-instr:/#

The target panicked after the shell (post-helper `kfree_skb_list_reason`
on the fake `head`), but the root shell was already established.
Evidence: `evidence/ROOT-revshell-*.txt`, `evidence/double2-root-fire-*.log`.

### Two offset bugs found and fixed

1. `skb_release_head_state` calls `destructor(skb)` with RDI only; the
   second argument of `call_usermodehelper_exec` (the wait mode) is the
   leftover RSI of the free path.  Setting `skb->_skb_refdst` to a non-NULL,
   low-bit-0 fake dst makes it call `dst_release()` first, which returns
   with `esi=0` -> `UMH_NO_WAIT` deterministically.
2. The blob builder's offsets are relative to the **page base** `P`
   (`head=P+0x100`, shinfo `P+0x200`, dataref `P+0x220`, fake-dst refcount
   `P+0x940`), while the fake skb base is `S=P+0x10`.  `ringone.py` must
   pass `P=page` and expose `S=page+0x10`; passing `P=S` shifted every
   self-reference by 0x10 and made the fake-dst refcount land in the wrong
   place (slow path -> crash).

### Still not default-settings

The root shell used:
* RPS (`rps_cpus=f`) for the cross-CPU split (possible QEMU-tap artifact),
* 46 target-side stretch kprobes + `rdopt2`,
* in-VM address reads (`kallsyms`, `kcore/page_offset_base`, `pagemap`),
* a root `AF_PACKET` TX-ring (CAP_NET_RAW) for the controlled page.

Zero-kprobe partial results already captured: wire-only `pg_vec` `G`
(`evidence/overread-nokprobe-pgvec-*.pcap`) and a zero-kprobe payload
firing that reached `call_usermodehelper_exec_work`
(`evidence/nokprobe-fire-umh-crash-*.log`).

## WIRE-ONLY KASLR SLIDE -> ROOT SHELL (boot 277, IOMAP3)

Found a 3-way random-kmalloc match `victim == saved_syn == iomap_dio = 7`
(seed 0xd399719a028f9b0).  `iomap_dio` is exactly 96 B and its cache hash
input is the fixed site `iomap_dio_rw+0x11`; O_DIRECT **writes** set
`dops = &ext4_dio_write_ops` at offset 8.

* `lab/dio_spray.py` churned O_DIRECT writes on the victim CPU
  (~183k writes/s, each allocating an iomap_dio).
* A probe-stretched saved_syn over-read leaked an **iomap_dio neighbour**:
  `nb[8:16] = 0xffffffff89e57ce0`.
* `scripts/wire_slide.py` resolved it to static
  `0xffffffff82657ce0 = ext4_dio_write_ops`, i.e. **slide = 0x07800000**,
  with no `/proc/kallsyms`/`/proc/kcore`/pagemap read.
* Derived `_text=0xffffffff88800000`,
  `EX=0xffffffff8892d4b0`, `WK=0xffffffff8892d920`; these matched the
  boot's kallsyms exactly (cross-check only).
* `lab/ringone.py` supplied `G` (`page_offset_base=0xffff8e2300000000`,
  `S=0xffff8e2402bc3010`), then the fire used the **wire-derived EX/WK**
  and returned a **root reverse shell** to the attacker.

Evidence: `evidence/WIRE-SLIDE-*.txt`, `evidence/ROOT-wireslide-revshell-*.txt`,
`evidence/overread-wire-slide-iomap-*.pcap`.

Remaining: the race still used the 46 stretch kprobes (#1); `G` still
used an in-VM `page_offset_base` read (wire-only `pg_vec` G is already
demonstrated, but a single-boot wire-slide+wire-G run needs a 4-way
cache match).
