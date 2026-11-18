#!/bin/bash
# mq-setup.sh - create the multi-queue tap lab on the host (run with sudo).
#
#   sudo bash lab/mq-setup.sh
#
# Creates br-cve and four multi-queue taps owned by the invoking user:
#   tap-cve-tgt, tap-cve-ins, tap-cve-leg, tap-cve-atk
# Each tap is attached to br-cve.  The guests keep their user-net management
# NIC (SSH); the tap is the lab link (192.168.89.0/24).
set -euo pipefail
USER_NAME=${SUDO_USER:-$USER}
BR=br-cve

# Remove the first-generation names if present (tap-cve-target is valid but
# superseded; tap-cve-instrumented/attacker exceed IFNAMSIZ).
for old in tap-cve-target tap-cve-instrumented tap-cve-attacker; do
  ip link del "$old" 2>/dev/null || true
done
ip link show "$BR" >/dev/null 2>&1 || ip link add "$BR" type bridge
ip addr add 192.168.77.1/24 dev "$BR" 2>/dev/null || true
ip link set "$BR" up

for t in tap-cve-tgt tap-cve-ins tap-cve-leg tap-cve-atk; do
  if ! ip link show "$t" >/dev/null 2>&1; then
    ip tuntap add dev "$t" mode tap multi_queue user "$USER_NAME"
  fi
  ip link set "$t" master "$BR"
  ip link set "$t" up
  echo "[+] $t -> $BR (owner $USER_NAME, multi_queue)"
done
ip -br link | grep -E 'br-cve|tap-cve' || true
