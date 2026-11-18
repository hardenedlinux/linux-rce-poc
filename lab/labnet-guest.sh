#!/bin/sh
# labnet-guest.sh <mac> <addr/prefix>
# Configure the lab NIC on the guest by MAC.  Never touches other NICs.
set -u
MAC=${1:?mac}
ADDR=${2:?addr}
IF=
for d in /sys/class/net/*; do
  [ "$(cat "$d/address" 2>/dev/null)" = "$MAC" ] && { IF=$(basename "$d"); break; }
done
[ -n "$IF" ] || { echo "[-] no NIC with MAC $MAC"; exit 1; }
ip link set "$IF" up
ip addr replace "$ADDR" dev "$IF"
echo "[+] $IF $ADDR"
ip -br addr show "$IF"
