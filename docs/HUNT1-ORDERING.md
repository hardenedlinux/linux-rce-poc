# Hunt 1 — can the free/read pair be naturally ordered?

Objective: find a stock ordering in which the option object is freed before the
reader uses it, so the 46 `ip_build_and_send_pkt` stretch probes (and `rdopt2`)
can be dropped.

Result: **no.** The pair is a genuine race whose natural window is ~5–10 ns,
while the free lands 1–54 µs after the ownership transfer. The kprobe trap is
the only in-kernel mechanism that spans that gap. This document is the
source + binary + measurement proof.

## 1. Lifetime model (6.8.0-106, source-verified)

```
alloc    tcp_v4_route_req (initial SYN with IP options)
         -> struct ip_options_rcu *O ; owner = request_sock->ireq_opt
transfer tcp_v4_syn_recv_sock:
             inet_opt = rcu_dereference(ireq->ireq_opt);
             RCU_INIT_POINTER(newinet->inet_opt, inet_opt);   // child owns O
             ...
             *own_req = inet_ehash_nolisten(...);
             if (likely(*own_req)) { tcp_move_syn(...); ireq->ireq_opt = NULL; }
             else                  { newinet->inet_opt = NULL; }   // child gives up
failure  put_and_exit: newinet->inet_opt = NULL; tcp_done(newsk);  // no double free
free     inet_sock_destruct: kfree(rcu_dereference_protected(inet->inet_opt, 1))
reader   tcp_v4_send_synack:
             rcu_read_lock();
             ip_build_and_send_pkt(skb, sk, ..., rcu_dereference(ireq->ireq_opt), tos);
             rcu_read_unlock();
```

Two facts matter:

1. **`inet_sock_destruct` uses a plain `kfree`, not `kfree_rcu`.** The
   `rcu_read_lock()` around the SYN-ACK build does **not** keep the object
   alive. The only thing that does is ownership/refcounts.
2. **The request reference does not protect the option.** The reader holds a
   reference on the `request_sock`, but the option's owner becomes the *child*
   socket, which can be destroyed on another CPU.

Ownership is otherwise consistent: every path (`*own_req` success, the
`else` branch, `put_and_exit`) either transfers or clears exactly one of the
two pointers, so there is no deterministic double-owner/free — the only bug is
the concurrent reader.

## 2. Why the pair can race without the listener lock

A duplicate SYN reaches `tcp_v4_rcv()` and, when it matches an existing
request, `tcp_check_req()` is called **without the listener socket lock**
(`net/ipv4/tcp_ipv4.c:2274`); the request refcount and the ehash bucket lock
are the only serialization. The in-sequence ACK path, on another CPU, runs
`syn_recv_sock()` (transfer + `ireq_opt = NULL`) and then tears the child down
(`tcp_child_process` -> `tcp_done` -> `sock_put` -> `inet_sock_destruct` ->
`kfree(O)`).

So a reader that loaded `ireq->ireq_opt` **before** the NULLing can still hold
`O` when the ACK CPU frees it.

## 3. The natural window (target binary)

`tcp_v4_send_synack+0x9d`:

```
ffffffff8202018d  call __rcu_read_lock
ffffffff8202019b  mov  0xf0(%rbx),%r8        <- deref ireq->ireq_opt
ffffffff820201a2  mov  %r12,%rsi
ffffffff820201a5  mov  %r13,%rdi
ffffffff820201a8  call ip_build_and_send_pkt
```

`ip_build_and_send_pkt` prologue + first use:

```
ffffffff81fe7b00  call __fentry__
ffffffff81fe7b05 ... 16 instructions (pushes, inet_sk, skb_rtable, test/je)
ffffffff81fe7b3f  movzbl 0x18(%r8),%esi      <- FIRST use: opt->opt.optlen
```

From the dereference to the first read: 3 instructions + call + ~16 prologue
instructions — **~5–10 ns**.

## 4. Measured free latency

Pointer-matched kprobes on a live stock boot:

```
p:trans   tcp_v4_syn_recv_sock+0xca  opt=+0xf0(%r12):x64
p:freeopt inet_sock_destruct         inet_opt=+784(%di):x64
```

Correlating the same object address through transfer -> kfree (771 pairs):

```
min 1.0 us   p50 8.0 us   p90 17.0 us   p99 30.0 us   max 54.0 us
```

Evidence: `evidence/hunt1-free-latency-*.txt`,
`evidence/hunt1-latency-trace-*.trace`.

## 5. Why no natural event closes the gap

For a UAF the reader must load `O` before `ireq->ireq_opt = NULL` (a window of
order 1 us after the transfer) and use it after `kfree(O)` (1–54 us after the
transfer) — i.e. the reader's deref->use interval must be at least ~1–20 us.

* A hardirq must land inside a ~5–10 ns window *and* delay by the remaining
  1–54 us. Even at 10 kHz IRQ rate that is ~1e-6 per read; Phase 1 measured
  **0 UAF in >1M `ip_options_build` reads** across five geometries.
* Softirq context is not preemptible on non-RT (`PREEMPT_DYNAMIC` voluntary).
* There is no us-scale call between the deref and the first use — the first
  use is the `skb_push()` argument.

The 46 `int3` probes (first at `+5`, before the `skb_push`) provide the ~40 us
delay; the measurement shows this covers p99 of the free latency exactly.

## 6. Do the other readers help? (source enumeration)

`ip_options_build` has exactly three call sites:

| reader | deref->use gap | can the object be freed concurrently? |
|---|---|---|
| `ip_build_and_send_pkt` (SYN-ACK) | ~5–10 ns | yes — the request/child transfer race (above) |
| `__ip_queue_xmit` (TCP TX) | long (route lookup) | **no** — the skb holds `skb->sk`, so `inet_sock_destruct` cannot run |
| `__ip_make_skb` (UDP) | long (skb alloc may sleep) | **no** — `lock_sock()` is held; `setsockopt(IP_OPTIONS)`/`close()` are serialized |

The two readers with a naturally long gap are exactly the two whose object
cannot be freed concurrently. The only concurrently-freeable reader has a ns
gap. That is the structural trap.

## 7. Conclusion

* The kprobe stretch cannot be replaced by a stock mechanism for this pairing.
  The dependency is **structural**, not an engineering shortcut.
* Removing instrumentation therefore requires a *different* free/read pairing
  (a new primitive), not a better amplifier. The stock reader enumeration above
  closes the obvious candidates, consistent with the Phase 1 measurements.
* The next hunt was **#3 (an unprivileged controlled page)**: the pg_vec leak
  needs `CAP_NET_RAW`, so the question was whether an unprivileged 96-byte
  object carrying `struct page *` pointers could be made the UAF neighbour.
  HUNT3 tested that route and found it structurally blocked; the wire-derived
  `G` address leak itself is demonstrated separately, but its allocation still
  comes from the root ring.
* Coverage (`2/16`) remains a hard wall independent of this result.
