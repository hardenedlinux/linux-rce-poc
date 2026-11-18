#!/bin/sh
# start-listeners.sh - run on the guest as root (9p share at /mnt/lab).
fuser -k 9800/tcp 2>/dev/null
fuser -k 9801/tcp 2>/dev/null
sleep 0.3
rm -f /tmp/raw9800.log /tmp/save9801.log
PORT=9800 BACKLOG=4096 setsid nohup python3 /mnt/lab/target/mptcp_raw_listener.py >/tmp/raw9800.log 2>&1 </dev/null &
PORT=9801 BACKLOG=262144 setsid nohup python3 /mnt/lab/target/tcp_save_syn_listener.py >/tmp/save9801.log 2>&1 </dev/null &
sleep 1
ss -ltn | grep -E '9800|9801'
cat /tmp/raw9800.log /tmp/save9801.log
