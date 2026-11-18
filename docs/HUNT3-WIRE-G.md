# Hunt 3 — wire `G` without `CAP_NET_RAW`

> Note: a wire-derived `G` via a `pg_vec` over-read is demonstrated separately
> (`docs/PHASE4-RINGPAYLOAD.md`); that allocation still comes from the root
> AF_PACKET ring. This document asks whether an unprivileged 96-byte object can
> replace the root ring.

Objective: replace the root AF_PACKET ring (`ringone.py`) — the only way we
currently obtain a controlled page at a known kernel address — with an
unprivileged 96-byte object that leaks a page/direct-map pointer through the
UAF over-read.

Result: **structurally blocked.** Two concrete candidates were measured; the
page→direct-map conversion is the harder wall behind them.

## What the leak can do

`ip_options_build(skb, &opt->opt, ...)` copies

```
len   = *(u8 *)(object + 24)          // "optlen"
src   = object + 16                   // struct ip_options inside ip_options_rcu
```

into the SYN-ACK's IP-option area. So a leaked object is only useful if

1. byte **+24 is >= ~96** (leak length), and
2. it contains a pointer to something interesting within `+16 .. +16+len`.

Both conditions must hold in a **96-byte** slot, i.e. the object must be
allocated in kmalloc-96 and its random-kmalloc bucket must equal the victim's
(1/16 per boot, like every other spray).

## Candidate A — `io_mapped_ubuf` (io_uring registered buffer)

Source: `io_sqe_buffer_register` ->
`kvmalloc(struct_size(imu, bvec, nr_pages))`; 4 pages -> **96 B**, allocation
site `kvmalloc_node+0x24` (a *fixed* bucket, unprivileged, io_uring enabled).

Live object (16 KB page-aligned buffer, 4 pages), read via `/proc/kcore`:

```
+0   ubuf       = user VA
+8   ubuf_end
+16  nr_bvecs   = 4
+24  acct_pages = 4          <-- the leak length is 4
+32  bvec[0].page = 0xfffff4c544021140   (vmemmap)
+48  bvec[1].page
+64  bvec[2].page
+80  bvec[3].page
```

`acct_pages` is the number of *newly charged* pages: it is `<= nr_pages`, and
for a 96-byte object `nr_pages == 4`. The huge-page coalescing path sets it to
`page_size(hpage) >> PAGE_SHIFT` (512 for a 2 MB folio, 262144 for 1 GB), but
then `nr_pages = 1` and the object is 48 B (kmalloc-64), not 96.

**Verdict: optlen = 4, leaks nothing.** Evidence:
`evidence/hunt3-iomapped-ubuf-*.txt`.

## Candidate B — `struct pipe_buffer` array

A pipe resized to 2 pages (`F_SETPIPE_SZ`, 2 slots) allocates
`2 * sizeof(struct pipe_buffer) = 80 B` -> kmalloc-96. Layout:

```
+0  page (struct page *)     [slot 0]  -- outside the leak (starts at +16)
+8  offset, len
+16 ops = &anon_pipe_buf_ops [text pointer]  <- leaked
+24 flags = 0x10 (CAN_MERGE) <-- leak length = 16
+32 private
+40 page (slot 1)            -- beyond +16+16
```

**Verdict: leaks `ops` (a text pointer, i.e. the KASLR slide) but no page
pointer.** Useful as an alternative wire slide, not as `G`.

## The real wall: `struct page *` is not a direct-map address

Even with a page pointer, the fake skb needs the page's **direct-map** alias:

```
virt = page_offset_base + pfn * 4096
page = vmemmap_base     + pfn * 64
```

On x86-64 `kernel_randomize_memory()` places `page_offset_base`,
`vmalloc_base` and `vmemmap_base` at **independent** random offsets
(`arch/x86/mm/kaslr.c`). Measured on the same boot as the dump above:

```
direct-map slab object : 0xffff8c8481fcec60   (default base 0xffff888000000000)
vmemmap page pointer   : 0xfffff4c544021140   (default base 0xffffea0000000000)
```

So one leaked `struct page *` leaves two unknowns (`page_offset_base`,
`vmemmap_base`) and one equation; the *text* slide (which we can obtain from
the wire) does not determine the memory-randomization offsets. Brute force is
not viable: PUD-aligned bases with ~28 TB of entropy, and each wrong guess used
as a fake-skb pointer panics the target.

No leak in the chain exposes `page_offset_base` or `vmemmap_base` themselves
(they are globals in the kernel image mapping, not pointers stored in slab
objects).

## Conclusion

* The root `AF_PACKET` ring cannot be replaced by an unprivileged kmalloc-96
  object: no such object both reaches a page/direct-map pointer and has a
  usable `optlen` byte, and the page→direct-map conversion needs two
  independently randomized bases that nothing in the leak exposes.
* Dependency #3 is therefore **structural** for this CVE, like #1 (Hunt 1).
* Remaining dependency status: #1 structural, #2 structural (stock readers are
  refcount/lock-protected), #3 structural, #4 (2/16 coverage) structural.
* The only paths to a genuinely default-settings RCE are (a) a different
  vulnerability with a synchronous UAF in a non-randomized cache, or (b) an
  unprivileged primitive that reveals `page_offset_base`. This CVE does not
  provide either.
