#!/bin/bash
# find-match-target.sh [max_boots] - boot the stock target until the victim
# save_options site and saved_syn site share a real random-kmalloc bucket.
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MAX=${1:-300}
SSH="ssh -i $LAB/lab/ssh/id_ed25519 -p 2102 -o StrictHostKeyChecking=no \
     -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
     -o ConnectionAttempts=1 -o ControlMaster=no -o ControlPath=none \
     -o LogLevel=ERROR ubuntu@localhost"
for i in $(seq 1 "$MAX"); do
  echo "=== target boot $i $(date +%T) ==="
  bash "$LAB/lab/stop.sh" target >/dev/null 2>&1
  sleep 2
  env -u EXTRA_APPEND LAB_NET=tap NO_WAIT=1 bash "$LAB/lab/launch.sh" target >/dev/null 2>&1
  ok=0
  for j in $(seq 1 45); do
    if timeout 8 $SSH 'echo ok' >/dev/null 2>&1; then ok=1; break; fi
    sleep 5
  done
  if [ "$ok" != 1 ]; then echo "target boot $i: ssh timeout"; continue; fi
  r=$(timeout 20 $SSH 'sudo python3 -' < "$LAB/lab/cache_match_fixed.py" 2>&1)
  echo "target boot $i: $r"
  if echo "$r" | grep -q ' MATCH$'; then
    echo "FOUND_TARGET_MATCH boot=$i"
    echo "$i" > /tmp/cve-match-target
    exit 0
  fi
done
echo "NO_TARGET_MATCH_IN_$MAX"
exit 1
