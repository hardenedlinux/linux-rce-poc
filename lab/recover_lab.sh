#!/bin/bash
# recover_lab.sh - restart attacker + stock target (instrumented removed)
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$LAB"
# Recover from an interrupted session: stop any lab roles still running.
bash "$LAB/lab/stop.sh" all >/dev/null 2>&1 || true
sleep 2
EXTRA_APPEND="systemd.mask=systemd-journald.service systemd.mask=rsyslog.service systemd.mask=snapd.service systemd.mask=snapd.socket systemd.mask=snapd.seeded.service systemd.mask=unattended-upgrades.service systemd.mask=apt-daily.service systemd.mask=apt-daily-upgrade.service" \
  LAB_NET=tap NO_WAIT=1 NO_GDB=1 bash lab/launch.sh attacker >/dev/null 2>&1
for i in $(seq 1 40); do
  rm -f /tmp/cve-lab-ssh-2224.sock
  if timeout 8 ./lab/ssh.sh attacker true >/dev/null 2>&1; then break; fi
  sleep 5
done
./lab/ssh.sh attacker 'sudo swapoff -a 2>/dev/null; sudo journalctl --vacuum-size=5M 2>/dev/null; sudo rm -rf /var/log/journal/* 2>/dev/null; sudo find /var/log -type f -size +5M -delete 2>/dev/null' >/dev/null 2>&1 || true
bash lab/labnet.sh attacker >/dev/null 2>&1 || true
./lab/ssh.sh attacker 'cat > /tmp/mpstorm3_leak && chmod 755 /tmp/mpstorm3_leak' < lab/bin/mpstorm3
sed 's/c.bind(("127.0.0.1", 0))/c.bind(("0.0.0.0", 0))/' exp/mpsetup.py > /tmp/mpsetup_remote.py
./lab/ssh.sh attacker 'cat > /tmp/mpsetup_remote.py' < /tmp/mpsetup_remote.py
./lab/ssh.sh attacker 'cat > /tmp/frag_probe.py' < exp/frag_probe.py
./lab/ssh.sh attacker 'cat > /tmp/saved_syn_probe.py' < exp/saved_syn_probe.py
echo ATTACKER_READY
EXTRA_APPEND="no_hash_pointers systemd.mask=systemd-journald.service systemd.mask=rsyslog.service systemd.mask=snapd.service systemd.mask=snapd.socket systemd.mask=snapd.seeded.service systemd.mask=unattended-upgrades.service systemd.mask=apt-daily.service systemd.mask=apt-daily-upgrade.service systemd.mask=cloud-config.service systemd.mask=cloud-final.service systemd.mask=systemd-networkd-wait-online.service" \
  LAB_NET=tap NO_WAIT=1 NO_GDB=1 bash lab/launch.sh target >/dev/null 2>&1
for i in $(seq 1 40); do
  rm -f /tmp/cve-lab-ssh-2102.sock
  if timeout 8 ./lab/ssh.sh target true >/dev/null 2>&1; then break; fi
  sleep 5
done
./lab/ssh.sh target 'sudo swapoff -a 2>/dev/null; sudo journalctl --vacuum-size=5M 2>/dev/null; sudo rm -rf /var/log/journal/* 2>/dev/null; sudo find /var/log -type f -size +5M -delete 2>/dev/null' >/dev/null 2>&1 || true
echo TARGET_READY
./lab/ssh.sh target 'cat > /tmp/cache_match.py' < lab/cache_match.py
./lab/ssh.sh target 'sudo python3 /tmp/cache_match.py'
df -h /home | tail -1
