#!/bin/sh
# Remove the VLAN Flow service. Keeps /etc/vlan-flow (your config) unless you pass --purge.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Run this with sudo." >&2; exit 1; }
systemctl disable --now vlan-flow.service 2>/dev/null || true
rm -f /etc/systemd/system/vlan-flow.service
systemctl daemon-reload
rm -rf /opt/vlan-flow
if [ "${1:-}" = "--purge" ]; then
  rm -rf /etc/vlan-flow /var/lib/private/vlan-flow /var/lib/vlan-flow
  echo "VLAN Flow, its configuration and its event database were removed."
else
  echo "VLAN Flow was removed. Your configuration is still in /etc/vlan-flow (use --purge to delete it and the event database)."
fi
