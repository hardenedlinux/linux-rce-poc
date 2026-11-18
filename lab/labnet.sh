#!/bin/bash
# labnet.sh <target|instrumented|attacker>
# Mount the 9p lab share and configure the second (lab) NIC over SSH.
set -euo pipefail
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROLE=${1:?role}
case "$ROLE" in
  target) MAC=52:54:00:12:34:56; ADDR=192.168.89.2/24 ;;
  instrumented) MAC=52:54:00:12:34:59; ADDR=192.168.89.2/24 ;;
  legacy-debug)        MAC=52:54:00:12:34:58; ADDR=192.168.89.2/24 ;;
  attacker)            MAC=52:54:00:12:34:57; ADDR=192.168.89.1/24 ;;
  *) echo "usage: $0 <target|instrumented|attacker>"; exit 2 ;;
esac
"$LAB/lab/ssh.sh" "$ROLE" \
  "sudo mkdir -p /mnt/lab; sudo mount -t 9p -o trans=virtio,version=9p2000.L host0 /mnt/lab 2>/dev/null || true; sudo sh -c 'for s in /mnt/lab/lab/labnet-guest.sh; do [ -f \"\$s\" ] && exec sh \"\$s\" $MAC $ADDR; done; echo no-script' "
