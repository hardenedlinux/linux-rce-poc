#!/bin/bash
# twin-correlate.sh start|stop|dump
# Measurement-only pointer correlation on the instrumented twin (root).
#
#   freeopt: inet_sock_destruct(sk): inet_opt = *(sk + 784)
#   rdopt2 : ip_options_build(skb, opt): opt = &inet_opt->opt (base = opt - 16)
#   alloc  : kmem:kmalloc bytes_req == 72 (save_options / other 72B objects)
#
# A rdopt2 whose base was last seen in freeopt (not alloc) is a UAF read.
set -u
T=/sys/kernel/debug/tracing
cmd=${1:-start}
case "$cmd" in
start)
  mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
  echo 0 > "$T/tracing_on" 2>/dev/null || true
  echo 0 > "$T/events/kprobes/enable" 2>/dev/null || true
  echo 0 > "$T/events/kmem/kmalloc/enable" 2>/dev/null || true
  echo > "$T/kprobe_events" 2>/dev/null || true
  echo 32768 > "$T/buffer_size_kb" 2>/dev/null || true
  echo 'p:freeopt inet_sock_destruct sk=%di:x64 inet_opt=+784(%di):x64' >> "$T/kprobe_events"
  echo 'p:rdopt2 ip_options_build skb=%di:x64 opt=%si:x64 optlen=+8(%si):u8 s1=+23(%si):u32' >> "$T/kprobe_events"
  echo 'bytes_req == 72 || bytes_req == 92' > "$T/events/kmem/kmalloc/filter" 2>/dev/null || true
  echo 1 > "$T/events/kmem/kmalloc/enable" 2>/dev/null || true
  echo 1 > "$T/events/kprobes/enable"
  echo 1 > "$T/tracing_on"
  echo "[+] correlation probes armed"
  ;;
stop)
  echo 0 > "$T/tracing_on" 2>/dev/null || true
  echo 0 > "$T/events/kprobes/enable" 2>/dev/null || true
  echo 0 > "$T/events/kmem/kmalloc/enable" 2>/dev/null || true
  echo "[+] stopped"
  ;;
dump)
  EV=/mnt/lab/evidence
  out=$EV/corr-$(date +%s).trace
  sudo cp "$T/trace" "$out"
  chmod 644 "$out" 2>/dev/null || true
  echo "[+] trace: $out ($(wc -l < "$out") lines)"
  echo "freeopt: $(grep -c 'freeopt:' "$out" || true)  rdopt2: $(grep -c 'rdopt2:' "$out" || true)  alloc72: $(grep -c 'kmalloc:' "$out" || true)"
  ;;
*)
  echo "usage: $0 start|stop|dump"; exit 2 ;;
esac
