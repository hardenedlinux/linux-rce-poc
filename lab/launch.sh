#!/bin/bash
# launch.sh <target|instrumented|attacker>
#
# Boots one lab VM.  target/instrumented listen on the QEMU socket link
# (127.0.0.1:12345); the attacker connects to it.  Start the target first.
#
#   stock target      : default Ubuntu 6.8.0-106, no slub_debug
#   instrumented twin : same kernel + slub_debug=P + gdbstub :1234
#   attacker          : raw-socket guest on the same link
#
# SSH: target/instrumented :2223, attacker :2224  (ubuntu@localhost)
set -euo pipefail

ROLE=${1:-target}
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMG="$LAB/lab/harness"
KEY="$LAB/lab/ssh/id_ed25519"
KERNEL="$LAB/lab/kernel/vmlinuz-6.8.0-106-generic"
INITRD="$LAB/lab/kernel/initrd.img-6.8.0-106-generic"
ROOT_UUID="${ROOT_UUID:-6d085073-3c5a-49aa-9133-d0c30d62315b}"
SOCK_PORT="${SOCK_PORT:-12345}"

case "$ROLE" in
  target)
    SSH_PORT=2102; SER_PORT=2132; MEM=4G; DISK="$IMG/target.qcow2"; SEED="$IMG/seed-target.img"
    SERIAL="$IMG/target-serial.log"; PID="$IMG/target.pid"
    USER_MAC=52:54:00:aa:00:01
    MAC=52:54:00:12:34:56; APPEND_EXTRA=""; CONSOLE="console=tty0 console=ttyS0"; MGMT_DEV="virtio-net-pci"
    NETDEV="socket,id=lab0,listen=127.0.0.1:$SOCK_PORT"; TAP=tap-cve-tgt ;;
  instrumented)
    SSH_PORT=2101; SER_PORT=2130; MEM=4G; DISK="$IMG/instrumented.qcow2"; SEED="$IMG/seed-instrumented.img"
    SERIAL="$IMG/instrumented-serial.log"; PID="$IMG/instrumented.pid"
    USER_MAC=52:54:00:12:34:56
    MAC=52:54:00:12:34:59; APPEND_EXTRA="slub_debug=P"; CONSOLE="console=tty0 console=ttyS0"; MGMT_DEV="virtio-net-pci"
    NETDEV="socket,id=lab0,listen=127.0.0.1:$SOCK_PORT"; TAP=tap-cve-ins ;;
  legacy-debug)
    SSH_PORT=2201; SER_PORT=2230; MEM=4G; DISK="$IMG/legacy-debug.qcow2"; SEED="$IMG/seed-legacy.img"
    SERIAL="$IMG/legacy-debug-serial.log"; PID="$IMG/legacy-debug.pid"
    USER_MAC=52:54:00:12:34:56
    MAC=52:54:00:12:34:58; APPEND_EXTRA="slub_debug=P"; CONSOLE="console=tty0 console=ttyS0"; MGMT_DEV="virtio-net-pci"
    NETDEV="socket,id=lab0,listen=127.0.0.1:$SOCK_PORT"; TAP=tap-cve-leg ;;
  attacker)
    SSH_PORT=2224; SER_PORT=2231; MEM=2G; DISK="$IMG/attacker.qcow2"; SEED="$IMG/seed-attacker.img"
    SERIAL="$IMG/attacker-serial.log"; PID="$IMG/attacker.pid"
    USER_MAC=52:54:00:aa:00:03
    MAC=52:54:00:12:34:57; APPEND_EXTRA=""; CONSOLE="console=tty0 console=ttyS0"; MGMT_DEV="virtio-net-pci"
    NETDEV="socket,id=lab0,connect=127.0.0.1:$SOCK_PORT"; TAP=tap-cve-atk ;;
  *) echo "usage: $0 <target|instrumented|attacker>"; exit 2 ;;
esac

# Debug escape hatches (never used for validation runs):
#   EXTRA_APPEND="init=/bin/bash"  -> PID 1 shell on the serial console
#   NO_WAIT=1                      -> start QEMU and return immediately
# NO_SLUB=1 boots the instrumented image with the stock/default cmdline
# (no slub_debug) so it can serve as a second isolated stock target.
if [ "${NO_SLUB:-0}" = 1 ]; then APPEND_EXTRA=""; fi
APPEND_EXTRA="$APPEND_EXTRA ${EXTRA_APPEND:-}"

if [ "${LAB_NET:-socket}" = tap ]; then
  NETDEV="tap,id=lab0,ifname=$TAP,script=no,downscript=no,queues=4"
  LABDEV=(-device virtio-net-pci,netdev=lab0,mq=on,vectors=10,mac="$MAC")
else
  LABDEV=(-device virtio-net-pci,netdev=lab0,mac="$MAC")
fi

for f in "$DISK" "$SEED" "$KERNEL" "$INITRD"; do
  [ -f "$f" ] || { echo "[-] missing: $f"; exit 1; }
done
if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
  echo "[!] $ROLE already running (PID $(cat "$PID"))"; exit 1
fi
rm -f "$PID"
if ss -tln 2>/dev/null | grep -q ":$SSH_PORT\\b"; then
  echo "[!] SSH port $SSH_PORT already in use"; exit 1
fi
if [ "${LAB_NET:-socket}" != tap ] && [ "$ROLE" != attacker ] && ss -tln 2>/dev/null | grep -q ":$SOCK_PORT\\b"; then
  echo "[!] socket port $SOCK_PORT already in use (another target?)"; exit 1
fi

ACCEL=(-cpu qemu64)
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  ACCEL=(-enable-kvm -cpu host)
  echo "[+] KVM acceleration"
else
  echo "[*] no KVM; software emulation (slow)"
fi

EXTRA=()
if [ "$ROLE" = instrumented ] || [ "$ROLE" = legacy-debug ]; then
  if [ "${NO_GDB:-0}" = 1 ]; then
    echo "[+] instrumented: slub_debug=P, gdbstub disabled (monitor: gdbserver tcp::1234)"
  else
    EXTRA=(-gdb tcp::1234)
    echo "[+] instrumented: slub_debug=P, gdbstub tcp::1234"
  fi
fi

echo "[*] launching $ROLE (SSH :$SSH_PORT, socket $NETDEV)"
setsid nohup qemu-system-x86_64 \
  "${ACCEL[@]}" \
  -m "$MEM" -smp 4 \
  -kernel "$KERNEL" -initrd "$INITRD" \
  -append "root=UUID=$ROOT_UUID ro $CONSOLE $APPEND_EXTRA" \
  -drive if=virtio,format=qcow2,file="$DISK" \
  -drive if=virtio,format=raw,file="$SEED" \
  -netdev user,id=mgmt,hostfwd=tcp::${SSH_PORT}-:22 \
  -device "$MGMT_DEV",netdev=mgmt,mac="$USER_MAC" \
  -netdev "$NETDEV" \
  "${LABDEV[@]}" \
  -display none \
  -virtfs local,path="$LAB",mount_tag=host0,security_model=none,id=host0 \
  "${EXTRA[@]}" \
  -serial "file:$SERIAL" \
  -monitor "unix:$IMG/$ROLE-monitor.sock,server=on,wait=off" \
  -pidfile "$PID" \
  > "${SERIAL%.log}-qemu.log" 2>&1 &

if [ "${NO_WAIT:-0}" = 1 ]; then
  echo "[+] $ROLE started (NO_WAIT); SSH :$SSH_PORT"
  exit 0
fi

SSHOPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
         -o ConnectTimeout=4 -o ConnectionAttempts=1 -o BatchMode=yes -o LogLevel=ERROR -i "$KEY" -p "$SSH_PORT")
retries=100
while [ "$retries" -gt 0 ]; do
  if [ -f "$PID" ] && ! kill -0 "$(cat "$PID")" 2>/dev/null; then
    echo "[-] QEMU died; see ${SERIAL%.log}-qemu.log"; exit 1
  fi
  if ssh "${SSHOPTS[@]}" ubuntu@localhost "echo ok" >/dev/null 2>&1; then
    echo "[+] $ROLE ready (SSH :$SSH_PORT)"
    ssh "${SSHOPTS[@]}" ubuntu@localhost \
      'echo "    $(hostname) $(uname -r)"; cat /proc/cmdline; ip -br addr | head -5' || true
    exit 0
  fi
  printf "  waiting for %s (%d/%d)\r" "$ROLE" $((120-retries+1)) 120
  sleep 6
  retries=$((retries-1))
done
echo ""
echo "[-] SSH did not come up; see $SERIAL and ${SERIAL%.log}-qemu.log"
exit 1
