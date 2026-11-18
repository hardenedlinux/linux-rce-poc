#!/bin/bash
# setup_target_run.sh - configure the already-running stock target and get a token
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$LAB"
bash lab/labnet.sh target >/dev/null 2>&1 || true
./lab/ssh.sh target 'cat > /tmp/raw.py' < target/mptcp_raw_listener.py
./lab/ssh.sh target 'cat > /tmp/save.py' < target/tcp_save_syn_listener.py
./lab/ssh.sh target 'cat > /tmp/start_raw.sh' < lab/start_raw.sh
./lab/ssh.sh target 'cat > /tmp/setup_raw.sh' < lab/setup_raw.sh
./lab/ssh.sh target 'cat > /tmp/cache_match.py' < lab/cache_match.py
./lab/ssh.sh target 'sudo swapoff -a 2>/dev/null; sudo ip link set ens4 up; sudo ip addr replace 192.168.89.2/24 dev ens4; sudo sh /tmp/setup_raw.sh; sudo fuser -k 9801/tcp 2>/dev/null; sleep 0.3; sudo env PORT=9801 BACKLOG=32768 setsid nohup python3 /tmp/save.py >/tmp/save.log 2>&1 </dev/null & sleep 1; ss -ltn | grep -E "9800|9801"'
echo "=== token ==="
./lab/ssh.sh attacker 'rm -f /tmp/mpD.log; sudo sh -c "setsid nohup python3 /tmp/mpsetup_remote.py 192.168.89.2 9800 >/tmp/mpD.log 2>&1 </dev/null &"; sleep 4; sudo cat /tmp/mpD.log'
echo "=== match ==="
./lab/ssh.sh target 'sudo python3 /tmp/cache_match.py'
