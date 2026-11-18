#!/bin/bash
# find-match-boot.sh [role] [max] - reboot the twin until the victim
# save_options callsite and the saved_syn callsite share a kmalloc-rnd-XX-96
# cache.  Uses the role-aware lab/ssh.sh (instrumented -> :2101).
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROLE=${1:-instrumented}
MAX=${2:-40}
MASKS="no_hash_pointers systemd.mask=systemd-journald.service systemd.mask=rsyslog.service systemd.mask=snapd.service systemd.mask=snapd.socket systemd.mask=snapd.seeded.service systemd.mask=unattended-upgrades.service systemd.mask=apt-daily.service systemd.mask=apt-daily-upgrade.service systemd.mask=cloud-config.service systemd.mask=cloud-final.service systemd.mask=systemd-networkd-wait-online.service"
SSH=("$LAB/lab/ssh.sh" "$ROLE")
for i in $(seq 1 "$MAX"); do
  echo "=== boot $i $(date +%T) role=$ROLE ==="
  bash "$LAB/lab/stop.sh" "$ROLE" >/dev/null 2>&1
  sleep 2
  EXTRA_APPEND="$MASKS" LAB_NET=tap NO_WAIT=1 NO_GDB=1 bash "$LAB/lab/launch.sh" "$ROLE" >/dev/null 2>&1
  ok=0
  for j in $(seq 1 50); do
    rm -f /tmp/cve-lab-ssh-2101.sock /tmp/cve-lab-ssh-2201.sock
    if timeout 8 "${SSH[@]}" true >/dev/null 2>&1; then ok=1; break; fi
    sleep 3
  done
  if [ "$ok" != 1 ]; then echo "boot $i: ssh timeout"; continue; fi
  sleep 3
  timeout 15 "${SSH[@]}" 'cat > /tmp/cache_match.py' < "$LAB/lab/cache_match.py" 2>/dev/null
  r=$(timeout 20 "${SSH[@]}" 'sudo python3 /tmp/cache_match.py' 2>&1)
  echo "boot $i: $r"
  if echo "$r" | grep -q ' MATCH$'; then
    echo "FOUND_MATCH boot=$i"
    echo "$i" > /tmp/cve-match-boot
    exit 0
  fi
done
echo "NO_MATCH_IN_$MAX"
exit 1
