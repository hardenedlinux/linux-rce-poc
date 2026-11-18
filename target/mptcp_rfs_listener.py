import os, socket, struct, threading, time

# MPTCP streaming listener for the multi-queue/RFS lab.
# PIN_CPU pins the process (and inherited threads) to one CPU and sets
# SO_INCOMING_CPU on the listener/accepted msk so RFS steers the msk's flow to
# that CPU. The sender keeps data flowing on the join subflows (the reader).
CPU = int(os.environ.get("PIN_CPU", "3"))
PORT = int(os.environ.get("PORT", "9700"))
SO_INCOMING_CPU = 49

try:
    os.sched_setaffinity(0, {CPU})
except OSError as e:
    print("setaffinity:", e, flush=True)

def set_inc(s):
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_INCOMING_CPU, struct.pack("i", CPU))
    except OSError as e:
        print("SO_INCOMING_CPU failed:", e, flush=True)

def serve(c, a):
    print("accept", a, "cpu", CPU, flush=True)
    set_inc(c)
    def sender():
        try:
            while True:
                if c.send(b"A" * 1460) <= 0:
                    break
                time.sleep(0.0003)
        except OSError:
            pass
    def receiver():
        try:
            while True:
                if not c.recv(65536):
                    break
        except OSError:
            pass
    threading.Thread(target=sender, daemon=True).start()
    threading.Thread(target=receiver, daemon=True).start()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
set_inc(s)
s.bind(("0.0.0.0", PORT))
s.listen(256)
print(f"MPTCP RFS listener on :{PORT} cpu={CPU}", flush=True)
while True:
    try:
        c, a = s.accept()
    except OSError as e:
        print("accept:", e, flush=True)
        continue
    threading.Thread(target=serve, args=(c, a), daemon=True).start()
