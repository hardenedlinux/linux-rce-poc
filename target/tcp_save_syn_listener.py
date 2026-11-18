import os, socket, time
# Plain TCP listener with TCP_SAVE_SYN=27: each SYN creates a saved_syn
# kmalloc-96 object (12 + IP hdr 20 + TCP hdr+opts) even with NO IP options,
# so it does not race the save_options allocation.
port = int(os.environ.get("PORT", "9801"))
backlog = int(os.environ.get("BACKLOG", "4096"))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_TCP, 27, 1)      # TCP_SAVE_SYN
s.bind(("0.0.0.0", port))
s.listen(backlog)
print(f"TCP_SAVE_SYN listener on :{port} backlog={backlog}", flush=True)
while True:
    try:
        c, a = s.accept()
        c.close()
    except OSError:
        pass
