import os, socket, struct, time
# Raw MPTCP listener with RFS steering: pin the process to CPU 3 and set
# SO_INCOMING_CPU so RFS moves the msk's ACK processing to CPU 3 while the
# pre-msk dup SYN can still be processed on the hash CPU.
CPU = int(os.environ.get("PIN_CPU", "3"))
PORT = int(os.environ.get("PORT", "9700"))
BACKLOG = int(os.environ.get("BACKLOG", "64"))
try:
    os.sched_setaffinity(0, {CPU})
except OSError as e:
    print("setaffinity:", e, flush=True)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_INCOMING_CPU, struct.pack("i", CPU))
except OSError as e:
    print("SO_INCOMING_CPU:", e, flush=True)
s.bind(("0.0.0.0", PORT))
s.listen(BACKLOG)
print(f"MPTCP raw RFS listener on :{PORT} cpu={CPU} backlog={BACKLOG} (no accept)", flush=True)
time.sleep(7200)
