#!/usr/bin/env python3
# MPTCP client with an IPv4 RR option on the SYN, for the service-assisted
# send/close race test.  Usage: mptcp_client.py <ip> <port> [seconds]
import os, socket, struct, sys, time
ip = sys.argv[1]
port = int(sys.argv[2])
dur = float(sys.argv[3]) if len(sys.argv) > 3 else 0.2
# RR option: type 7, len 39, ptr 4, then address slots.  The kernel compiles
# it and puts it on the SYN; the server's child inherits ireq_opt.
rr = bytes([7, 39, 4]) + b"\x00" * 36
end = time.time() + dur
while time.time() < end:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, rr)
        s.settimeout(2.0)
        s.connect((ip, port))
        while True:
            d = s.recv(65536)
            if not d:
                break
        s.close()
    except OSError:
        time.sleep(0.005)
