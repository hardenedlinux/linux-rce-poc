#!/bin/bash
# find-match-iomap.sh [max_boots] - find a stock twin boot where
# victim save_options cache == saved_syn cache == iomap_dio cache.
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MAX=${1:-500}
SSH="ssh -i $LAB/lab/ssh/id_ed25519 -p 2101 -o StrictHostKeyChecking=no \
     -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
     -o ConnectionAttempts=1 -o ControlMaster=no -o ControlPath=none \
     -o LogLevel=ERROR ubuntu@localhost"
for i in $(seq 1 "$MAX"); do
  echo "=== iomap boot $i $(date +%T) ==="
  bash "$LAB/lab/stop.sh" instrumented >/dev/null 2>&1
  sleep 2
  NO_SLUB=1 EXTRA_APPEND='' NO_GDB=1 LAB_NET=tap NO_WAIT=1 bash "$LAB/lab/launch.sh" instrumented >/dev/null 2>&1
  ok=0
  for j in $(seq 1 30); do
    if timeout 8 $SSH 'echo ok' >/dev/null 2>&1; then ok=1; break; fi
    sleep 4
  done
  if [ "$ok" != 1 ]; then echo "boot $i: ssh timeout"; continue; fi
  r=$(timeout 20 $SSH 'sudo python3 -' < "$LAB/lab/iomap_match.py" 2>&1)
  echo "boot $i: $r"
  if echo "$r" | grep -q IOMAP3; then
    echo "FOUND_IOMAP3 boot=$i"
    echo "$i" > /tmp/cve-iomap
    exit 0
  fi
done
echo "NO_IOMAP3_IN_$MAX"
exit 1
