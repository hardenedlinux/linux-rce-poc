#!/bin/sh
# mq-config.sh [ifname] - configure the multi-queue lab NIC in the guest.
# Run as root in the target/attacker after boot.
IF=${1:-ens4}
echo "[+] before:"; ethtool -l "$IF" 2>/dev/null || true
# Ask the driver for 4 combined queues.  With virtio-net mq=on this normally
# succeeds; if not, the device is still usable with its current queues.
ethtool -L "$IF" combined 4 2>/dev/null || true
echo "[+] after:"; ethtool -l "$IF" 2>/dev/null || true
echo "[+] queues:"; ls /sys/class/net/"$IF"/queues

# RFS: global flow table + per-RX-queue counters.  This is target-side tuning
# for the multi-queue experiment, not part of the stock baseline.
sysctl -w net.core.rps_sock_flow_entries=32768 2>/dev/null || true
for f in /sys/class/net/"$IF"/queues/rx-*/rps_flow_cnt; do
  [ -w "$f" ] && echo 32768 > "$f" 2>/dev/null || true
done
for f in /sys/class/net/"$IF"/queues/rx-*/rps_cpus; do
  [ -w "$f" ] && echo f > "$f" 2>/dev/null || true
done
echo "[+] rps_flow_cnt:"
for f in /sys/class/net/"$IF"/queues/rx-*/rps_flow_cnt; do echo "  $f=$(cat "$f" 2>/dev/null)"; done
echo "[+] rps_cpus:"
for f in /sys/class/net/"$IF"/queues/rx-*/rps_cpus; do echo "  $f=$(cat "$f" 2>/dev/null)"; done
