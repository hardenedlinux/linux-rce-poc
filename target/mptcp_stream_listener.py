import socket, threading, time
# Stable MPTCP streaming listener for MP_JOIN handshake testing.
# Unlike mptcp_sender_listener.py it never closes the accepted msk, so the
# join subflows stay alive and the MPTCP scheduler can move data onto them.
def serve(c, a):
    print("accept", a, flush=True)
    try:
        while True:
            if c.send(b"A" * 1460) <= 0:
                break
            time.sleep(0.0005)
    except OSError as e:
        print("closed", a, e, flush=True)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9700))
s.listen(256)
print("MPTCP stable streaming listener on :9700", flush=True)
while True:
    try:
        c, a = s.accept()
    except OSError:
        continue
    threading.Thread(target=serve, args=(c, a), daemon=True).start()
