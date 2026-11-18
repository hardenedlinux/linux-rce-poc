#!/bin/bash
# make-seeds.sh [role ...] - regenerate cloud-init seeds and fresh overlays.
# Roles: target instrumented attacker
#
# The lab NIC is matched by MAC and renamed lab0; the management NIC (user
# net) has a distinct MAC so DHCP/SSH keeps working.
set -euo pipefail
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMG="$LAB/lab/harness"
BASE="$LAB/lab/cache/ubuntu-24.04-server-cloudimg-amd64.img"
PUB=$(cat "$LAB/lab/ssh/id_ed25519.pub")
ROLES=${*:-"target instrumented attacker"}

for role in $ROLES; do
  case "$role" in
    target)       host=cve-target;     mac=52:54:00:12:34:56; addr=192.168.89.2/24 ;;
    instrumented) host=cve-instr;      mac=52:54:00:12:34:56; addr=192.168.89.2/24 ;;
    attacker)     host=cve-attacker;   mac=52:54:00:12:34:57; addr=192.168.89.1/24 ;;
    *) echo "unknown role: $role"; exit 2 ;;
  esac

  cat > "$IMG/user-data-$role.tmpl" <<'EOF'
#cloud-config
hostname: @HOST@
manage_etc_hosts: true
ssh_pwauth: true
disable_root: true
package_update: false
package_upgrade: false
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo
    shell: /bin/bash
    lock_passwd: false
    ssh_authorized_keys:
      - @PUB@
growpart:
  mode: auto
  devices: ['/']
resize_rootfs: true
write_files:
  # Do not let network-online.target block boot on the unconfigured lab NIC.
  - path: /etc/systemd/system/systemd-networkd-wait-online.service.d/99-cve-lab.conf
    permissions: '0644'
    content: |
      [Service]
      ExecStart=
      ExecStart=/bin/true
runcmd:
  # Pin the QEMU SLIRP management address; DHCP under slub_debug=P can miss
  # the cloud-init window.  This is harness reachability, not exploit setup.
  - [ sh, -c, "ip addr replace 10.0.2.15/24 dev ens3 2>/dev/null || true; ip route replace default via 10.0.2.2 dev ens3 2>/dev/null || true" ]
EOF
  sed -e "s|@HOST@|$host|g" -e "s|@PUB@|$PUB|g" \
      -e "s|@MAC@|$mac|g" -e "s|@ADDR@|$addr|g" \
      "$IMG/user-data-$role.tmpl" > "$IMG/user-data-$role"
  rm -f "$IMG/user-data-$role.tmpl"

  cat > "$IMG/meta-data-$role" <<EOF
instance-id: cve-2026-98432-$role-$(date +%s)
local-hostname: $host
EOF
  cloud-localds "$IMG/seed-$role.img" "$IMG/user-data-$role" "$IMG/meta-data-$role"
  qemu-img create -f qcow2 -b "$BASE" -F qcow2 "$IMG/$role.qcow2" 8G >/dev/null
  echo "[+] $role: seed + fresh overlay ($addr, lab MAC $mac)"
done
