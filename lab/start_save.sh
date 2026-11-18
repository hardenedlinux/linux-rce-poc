#!/bin/sh
fuser -k 9801/tcp 2>/dev/null
sleep 0.3
BACKLOG=32768 PORT=9801 setsid nohup python3 /tmp/save.py >/tmp/save.log 2>&1 </dev/null &
sleep 1
ss -ltn | grep 9801
