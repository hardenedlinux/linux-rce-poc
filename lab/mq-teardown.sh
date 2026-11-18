#!/bin/bash
# mq-teardown.sh - remove the multi-queue tap lab (run with sudo).
set -u
for t in tap-cve-tgt tap-cve-ins tap-cve-leg tap-cve-atk; do
  ip link del "$t" 2>/dev/null || true
done
ip link del br-cve 2>/dev/null || true
echo "[+] removed br-cve and taps"
