#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "uninstall.sh must run as root" >&2
  exit 2
fi
systemctl disable --now kurd-node.service 2>/dev/null || true
rm -f /etc/systemd/system/kurd-node.service /etc/sysusers.d/kurd-node.conf /etc/tmpfiles.d/kurd-node.conf
rm -f /usr/local/bin/kurd-node /usr/local/bin/kurdctl
rm -rf /usr/local/lib/kurd-node
rm -rf /usr/local/share/doc/kurd-node
systemctl daemon-reload
echo "Binaries and service files removed. /var/lib/kurd-node was preserved intentionally."
