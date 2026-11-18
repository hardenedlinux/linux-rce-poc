#!/bin/sh
fuser -k 9800/tcp 2>/dev/null
sleep 0.3
env PORT=9800 BACKLOG=32768 setsid nohup python3 /tmp/raw.py >/tmp/raw.log 2>&1 </dev/null &
sleep 1
ss -ltn | grep 9800
