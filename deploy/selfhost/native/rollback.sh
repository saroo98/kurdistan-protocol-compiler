#!/bin/sh
set -eu

if [ "${1:-}" != "--apply" ] || [ "${2:-}" != "--confirm" ] || [ "${3:-}" != "rollback" ]; then
  echo "usage: rollback.sh --apply --confirm rollback" >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "rollback must run as root" >&2
  exit 2
fi
previous=/var/lib/kurd-node/install/previous
if [ ! -x "$previous/bin/kurd-node" ] || [ ! -x "$previous/bin/kurdctl" ] || [ ! -f "$previous/systemd/kurd-node.service" ]; then
  echo "verified previous installation is unavailable" >&2
  exit 3
fi

was_active=false
if systemctl is-active --quiet kurd-node.service; then
  was_active=true
fi
systemctl stop kurd-node.service 2>/dev/null || true

failed=/var/lib/kurd-node/install/failed-current
rm -rf "$failed"
install -d -o root -g root -m 0700 "$failed/bin" "$failed/systemd" "$failed/lib" "$failed/doc"
cp -p /usr/local/bin/kurd-node "$failed/bin/kurd-node"
cp -p /usr/local/bin/kurdctl "$failed/bin/kurdctl"
cp -p /etc/systemd/system/kurd-node.service "$failed/systemd/kurd-node.service"
for helper in preflight rollback uninstall upgrade; do
  [ ! -f "/usr/local/lib/kurd-node/$helper.sh" ] || cp -p "/usr/local/lib/kurd-node/$helper.sh" "$failed/lib/$helper.sh"
done
if [ -d /usr/local/share/doc/kurd-node ]; then
  cp -Rp /usr/local/share/doc/kurd-node/. "$failed/doc/"
fi

install -o root -g root -m 0755 "$previous/bin/kurd-node" /usr/local/bin/.kurd-node.rollback
install -o root -g root -m 0755 "$previous/bin/kurdctl" /usr/local/bin/.kurdctl.rollback
mv /usr/local/bin/.kurd-node.rollback /usr/local/bin/kurd-node
mv /usr/local/bin/.kurdctl.rollback /usr/local/bin/kurdctl
install -o root -g root -m 0644 "$previous/systemd/kurd-node.service" /etc/systemd/system/kurd-node.service
[ ! -f "$previous/systemd/kurd-node.sysusers.conf" ] || install -o root -g root -m 0644 "$previous/systemd/kurd-node.sysusers.conf" /etc/sysusers.d/kurd-node.conf
[ ! -f "$previous/systemd/kurd-node.tmpfiles.conf" ] || install -o root -g root -m 0644 "$previous/systemd/kurd-node.tmpfiles.conf" /etc/tmpfiles.d/kurd-node.conf
rm -rf /usr/local/share/doc/kurd-node
install -d -o root -g root -m 0755 /usr/local/share/doc/kurd-node
cp -Rp "$previous/doc/." /usr/local/share/doc/kurd-node/
for helper in preflight rollback uninstall upgrade; do
  if [ -f "$previous/lib/$helper.sh" ]; then
    install -o root -g root -m 0755 "$previous/lib/$helper.sh" "/usr/local/lib/kurd-node/$helper.sh"
  fi
done
systemctl daemon-reload
if [ -f /var/lib/kurd-node/state.kurd-state ]; then
  runuser -u kurd-node -- /usr/local/bin/kurdctl doctor --data-dir /var/lib/kurd-node >/dev/null
fi
if [ "$was_active" = true ]; then
  systemctl enable --now kurd-node.service >/dev/null
  systemctl is-active --quiet kurd-node.service
fi
printf '{"schema":"kurd-node-rollback-v1","rolledBack":true,"authorityStateRolledBack":false}\n'
