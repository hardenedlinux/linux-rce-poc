#!/bin/sh
# setup_raw.sh - run as root in the instrumented guest after boot.
ip link set ens4 up
ip addr replace 192.168.89.2/24 dev ens4
sysctl -w net.core.rps_sock_flow_entries=32768 >/dev/null 2>&1
for f in /sys/class/net/ens4/queues/rx-*/rps_cpus; do echo f > "$f" 2>/dev/null; done
for f in /sys/class/net/ens4/queues/rx-*/rps_flow_cnt; do echo 32768 > "$f" 2>/dev/null; done
sysctl -w net.core.somaxconn=32768 net.ipv4.tcp_max_syn_backlog=32768 >/dev/null 2>&1
sh /tmp/start_raw.sh
