#!/bin/bash
# find-match-double.sh [max_boots] - find a stock twin boot where the victim
# save_options cache == saved_syn cache (the only cache match the payload
# needs; G is obtained deterministically with lab/ringone.py).
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MAX=${1:-500}
SSH="ssh -i $LAB/lab/ssh/id_ed25519 -p 2101 -o StrictHostKeyChecking=no \
     -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
     -o ConnectionAttempts=1 -o ControlMaster=no -o ControlPath=none \
     -o LogLevel=ERROR ubuntu@localhost"
for i in $(seq 1 "$MAX"); do
  echo "=== dbl boot $i $(date +%T) ==="
  bash "$LAB/lab/stop.sh" instrumented >/dev/null 2>&1
  sleep 2
  NO_SLUB=1 EXTRA_APPEND='' NO_GDB=1 LAB_NET=tap NO_WAIT=1 bash "$LAB/lab/launch.sh" instrumented >/dev/null 2>&1
  ok=0
  for j in $(seq 1 30); do
    if timeout 8 $SSH 'echo ok' >/dev/null 2>&1; then ok=1; break; fi
    sleep 4
  done
  if [ "$ok" != 1 ]; then echo "boot $i: ssh timeout"; continue; fi
  r=$(timeout 20 $SSH 'sudo python3 -' < "$LAB/lab/double_match.py" 2>&1)
  echo "boot $i: $r"
  if echo "$r" | grep -q DOUBLE; then
    echo "FOUND_DOUBLE boot=$i"
    echo "$i" > /tmp/cve-double
    exit 0
  fi
done
echo "NO_DOUBLE_IN_$MAX"
exit 1
