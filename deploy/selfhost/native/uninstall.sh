#!/bin/sh
set -eu

fail() {
  printf '{"schema":"kurd-node-uninstall-v2","uninstalled":false,"code":"%s"}\n' "$1" >&2
  exit 2
}

[ "$#" -eq 0 ] || fail INVALID_ARGUMENTS
[ "$(id -u)" -eq 0 ] || fail ROOT_REQUIRED
for command in systemctl networkctl nft sysctl rm; do
  command -v "$command" >/dev/null 2>&1 || fail TOOL_MISSING
done

systemctl disable --now kurd-node.socket kurd-node.service kurd-node-network.service 2>/dev/null || true
nft destroy table inet kurd_node >/dev/null 2>&1 || true
networkctl delete kurd0 >/dev/null 2>&1 || true

rm -f \
  /etc/systemd/system/kurd-node.service \
  /etc/systemd/system/kurd-node.socket \
  /etc/systemd/system/kurd-node-network.service \
  /etc/sysusers.d/kurd-node.conf \
  /etc/tmpfiles.d/kurd-node.conf \
  /etc/systemd/network/80-kurd0.netdev \
  /etc/systemd/network/80-kurd0.network \
  /etc/sysctl.d/90-kurd-node.conf \
  /etc/nftables.d/kurd-node.nft \
  /etc/unbound/unbound.conf.d/kurd-node.conf \
  /usr/local/bin/kurd-node \
  /usr/local/bin/kurdctl
rm -rf /usr/local/lib/kurd-node /usr/local/share/doc/kurd-node

systemctl daemon-reload
networkctl reload
sysctl --system >/dev/null
systemctl try-reload-or-restart unbound.service >/dev/null 2>&1 || true
printf '{"schema":"kurd-node-uninstall-v2","uninstalled":true,"authorityStatePreserved":true,"backupStatePreserved":true}\n'
