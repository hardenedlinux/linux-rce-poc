#!/bin/bash
# ssh.sh <target|instrumented|attacker> [command ...]
# Multiplexes over one persistent SSH connection (avoids sshd MaxStartups
# pre-auth slot exhaustion during rapid lab iterations).
set -u
ROLE=${1:-target}
shift || true
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KEY="$LAB/lab/ssh/id_ed25519"
case "$ROLE" in
  target) PORT=2102 ;;
  legacy-debug) PORT=2201 ;;
  instrumented) PORT=2101 ;;
  attacker) PORT=2224 ;;
  *) echo "usage: $0 <target|instrumented|attacker> [cmd...]"; exit 2 ;;
esac
SOCK="/tmp/cve-lab-ssh-$PORT.sock"
OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
      -o ConnectTimeout=6 -o ConnectionAttempts=1 -o BatchMode=yes
      -o LogLevel=ERROR -o ControlMaster=auto -o ControlPath="$SOCK"
      -o ControlPersist=900 -i "$KEY" -p "$PORT")

if ! ssh "${OPTS[@]}" -O check ubuntu@localhost >/dev/null 2>&1; then
  rm -f "$SOCK"
  ssh "${OPTS[@]}" -M -N -f ubuntu@localhost || {
    echo "[-] cannot establish SSH master on :$PORT" >&2
    exit 1
  }
fi
if [ "$#" -eq 0 ]; then
  exec ssh "${OPTS[@]}" ubuntu@localhost
fi
exec ssh "${OPTS[@]}" ubuntu@localhost "$@"
