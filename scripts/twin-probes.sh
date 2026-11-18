#!/bin/bash
# twin-probes.sh start|stop|dump|reset
# Measurement-only kprobes on the instrumented twin.  Run as root in the guest.
set -u
T=/sys/kernel/debug/tracing
cmd=${1:-start}
case "$cmd" in
start)
  mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
  echo 0 > "$T/tracing_on" 2>/dev/null || true
  echo 0 > "$T/events/kprobes/enable" 2>/dev/null || true
  echo > "$T/kprobe_events" 2>/dev/null || true
  # read #1 of opt->opt.optlen in ip_build_and_send_pkt (opt is 5th arg, %r8)
  echo 'p:build ip_build_and_send_pkt skb=%di:x64 opt=%r8:x64 optlen=+24(%r8):u8' >> "$T/kprobe_events"
  # final read / memcpy in ip_options_build (opt is 2nd arg, %rsi)
  echo 'p:rdopt ip_options_build skb=%di:x64 opt=%si:x64 optlen=+8(%si):u8 srr=+9(%si):u8 rr=+10(%si):u8 ts=+11(%si):u8 flags=+12(%si):u8 s1=+23(%si):u32 s3=+31(%si):u32' >> "$T/kprobe_events"
  echo 'p:free inet_sock_destruct sk=%di:x64' >> "$T/kprobe_events"
  echo 'p:reqfree tcp_v4_reqsk_destructor req=%di:x64' >> "$T/kprobe_events"
  echo 'opt != 0 && optlen != 40' > "$T/events/kprobes/build/filter"
  echo 'optlen != 40' > "$T/events/kprobes/rdopt/filter"
  echo 1 > "$T/events/kprobes/enable"
  echo 1 > "$T/tracing_on"
  echo "[+] probes armed"
  ;;
stop)
  echo 0 > "$T/tracing_on" 2>/dev/null || true
  echo 0 > "$T/events/kprobes/enable" 2>/dev/null || true
  echo "[+] probes stopped"
  ;;
dump)
  echo "--- event counts ---"
  echo "build:  $(grep -c 'build:' "$T/trace" 2>/dev/null || true)"
  echo "rdopt:  $(grep -c 'rdopt:' "$T/trace" 2>/dev/null || true)"
  echo "free:   $(grep -c 'free:' "$T/trace" 2>/dev/null || true)"
  echo "reqfree:$(grep -c 'reqfree:' "$T/trace" 2>/dev/null || true)"
  echo "--- rdopt anomaly signatures ---"
  grep 'rdopt:' "$T/trace" 2>/dev/null | sed 's/.*) //' | sort | uniq -c | sort -rn | head -20
  echo "--- build anomaly signatures ---"
  grep 'build:' "$T/trace" 2>/dev/null | sed 's/.*) //' | sort | uniq -c | sort -rn | head -20
  ;;
reset)
  echo 0 > "$T/tracing_on" 2>/dev/null || true
  echo 0 > "$T/events/kprobes/enable" 2>/dev/null || true
  echo > "$T/kprobe_events" 2>/dev/null || true
  echo > "$T/trace" 2>/dev/null || true
  echo "[+] probes reset"
  ;;
*)
  echo "usage: $0 start|stop|dump|reset"; exit 2 ;;
esac
