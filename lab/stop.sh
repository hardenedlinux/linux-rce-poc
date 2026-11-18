#!/bin/bash
# stop.sh [target|instrumented|attacker|all]
set -u
ROLE=${1:-all}
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KEY="$LAB/lab/ssh/id_ed25519"
IMG="$LAB/lab/harness"

stop_one() {
  role=$1
  case "$role" in
    target) port=2102 ;;
    legacy-debug) port=2201 ;;
    instrumented) port=2101 ;;
    attacker) port=2224 ;;
    *) return ;;
  esac
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=4 -o LogLevel=ERROR -i "$KEY" -p "$port" \
      ubuntu@localhost "sudo poweroff" >/dev/null 2>&1 || true
  pidf="$IMG/$role.pid"
  if [ -f "$pidf" ]; then
    pid=$(cat "$pidf")
    for _ in $(seq 1 15); do
      kill -0 "$pid" 2>/dev/null || { rm -f "$pidf"; return; }
      sleep 1
    done
    kill -TERM "$pid" 2>/dev/null || true
    sleep 2
    kill -KILL "$pid" 2>/dev/null || true
    rm -f "$pidf"
  fi
}

if [ "$ROLE" = all ]; then
  stop_one attacker; stop_one target; stop_one instrumented; stop_one legacy-debug
else
  stop_one "$ROLE"
fi
echo "[+] stopped: $ROLE"
