import os, socket, threading, time
# MPTCP base-connection keeper + MP_JOIN target.
# The app accepts and HOLDS connections so the base msk (and its token) is
# not evicted from the SYN/accept queue by the MP_JOIN flood.  Subflow
# MP_JOIN children are kernel-side and do not create accept entries.
port = int(os.environ.get("PORT", "9800"))
backlog = int(os.environ.get("BACKLOG", "32768"))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)  # IPPROTO_MPTCP
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(backlog)
print(f"MPTCP keeper listener on :{port} backlog={backlog}", flush=True)

held = []

def hold(c):
    try:
        while True:
            if not c.recv(4096):
                break
    except OSError:
        pass

while True:
    try:
        c, a = s.accept()
        held.append(c)
        print(f"accepted {a} total={len(held)}", flush=True)
        threading.Thread(target=hold, args=(c,), daemon=True).start()
    except OSError:
        time.sleep(0.1)
