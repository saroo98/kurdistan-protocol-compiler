#!/bin/sh
set -eu

fail() {
  printf '{"schema":"kurd-node-rollback-v2","rolledBack":false,"code":"%s"}\n' "$1" >&2
  exit 2
}

[ "${1:-}" = "--apply" ] && [ "${2:-}" = "--confirm" ] && [ "${3:-}" = "rollback" ] || fail INVALID_ARGUMENTS
[ "$(id -u)" -eq 0 ] || fail ROOT_REQUIRED

for command in systemctl systemd-analyze networkctl nft unbound-checkconf sysctl stat install runuser sed tr cp mv rm mktemp sleep getent; do
  command -v "$command" >/dev/null 2>&1 || fail TOOL_MISSING
done
listen_port=$(sed -n 's/^ListenStream=\[::\]:\([0-9][0-9]*\)$/\1/p' /etc/systemd/system/kurd-node.socket 2>/dev/null || true)
[ -n "$listen_port" ] || listen_port=443
case "$listen_port" in
  ''|*[!0-9]*) fail INVALID_ARGUMENTS ;;
esac
[ "$listen_port" -ge 1 ] && [ "$listen_port" -le 65535 ] || fail INVALID_ARGUMENTS
preflight_output=$(/usr/local/lib/kurd-node/preflight.sh --runtime --port "$listen_port" --allow-systemd-socket) || fail PREFLIGHT_FAILED
egress_interface_v4=$(printf '%s\n' "$preflight_output" | sed -n 's/.*"egressInterfaceV4":"\([A-Za-z0-9_.:-]*\)".*/\1/p')
egress_interface_v6=$(printf '%s\n' "$preflight_output" | sed -n 's/.*"egressInterfaceV6":"\([A-Za-z0-9_.:-]*\)".*/\1/p')
[ -n "$egress_interface_v4" ] && [ -n "$egress_interface_v6" ] || fail PREFLIGHT_FAILED

previous=/var/lib/kurd-node/install/previous
[ -x "$previous/bin/kurd-node" ] && [ -x "$previous/bin/kurdctl" ] && [ -f "$previous/systemd/kurd-node.service" ] || fail PREVIOUS_UNAVAILABLE

manifest_value() {
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\(\"[^\"]*\"\|[0-9][0-9]*\).*/\1/p" "$2" | tr -d '"'
}

previous_state_version=1
if [ -f "$previous/doc/manifest.json" ]; then
  observed_state_version=$(manifest_value stateVersion "$previous/doc/manifest.json")
  [ -z "$observed_state_version" ] || previous_state_version=$observed_state_version
fi
case "$previous_state_version" in
  1|2) ;;
  *) fail PREVIOUS_STATE_UNSUPPORTED ;;
esac

recreate_owned_tun() {
  networkctl delete kurd0 >/dev/null 2>&1 || true
  networkctl reload >/dev/null 2>&1 || return 1
  attempts=0
  while [ "$attempts" -lt 50 ]; do
    [ -e /sys/class/net/kurd0/tun_flags ] && return 0
    attempts=$((attempts + 1))
    sleep 0.1
  done
  return 1
}

rebind_owned_dns() {
  systemctl restart unbound.service >/dev/null 2>&1 || return 1
  systemctl is-active --quiet unbound.service || return 1
}

was_service_active=false
was_socket_enabled=false
systemctl is-active --quiet kurd-node.service && was_service_active=true || true
systemctl is-enabled --quiet kurd-node.socket && was_socket_enabled=true || true

temporary=$(mktemp -d /var/tmp/kurd-node-rollback.XXXXXX)
previous_doctor=$(mktemp /var/tmp/kurd-node-previous-doctor.XXXXXX)
trap 'rm -rf "$temporary"; rm -f "$previous_doctor"' EXIT HUP INT TERM
if [ -f "$previous/systemd/kurd-node.socket" ]; then
  systemd-analyze verify "$previous/systemd/kurd-node.service" "$previous/systemd/kurd-node.socket" >/dev/null || fail PREVIOUS_SYSTEMD_INVALID
else
  systemd-analyze verify "$previous/systemd/kurd-node.service" >/dev/null || fail PREVIOUS_SYSTEMD_INVALID
fi
[ ! -f "$previous/unbound/kurd-node.conf" ] || unbound-checkconf "$previous/unbound/kurd-node.conf" >/dev/null || fail PREVIOUS_UNBOUND_INVALID
[ ! -f "$previous/nftables/kurd-node.nft" ] || nft -c -f "$previous/nftables/kurd-node.nft" >/dev/null || fail PREVIOUS_NFT_INVALID
if [ "$previous_state_version" = "2" ] && [ -f /var/lib/kurd-node/state.kurd-state ]; then
  install -o root -g kurd-node -m 0750 "$previous/bin/kurdctl" "$previous_doctor"
  runuser -u kurd-node -- "$previous_doctor" doctor --data-dir /var/lib/kurd-node >/dev/null || fail PREVIOUS_DOCTOR_FAILED
fi

systemctl stop kurd-node.socket kurd-node.service kurd-node-network.service 2>/dev/null || true
if [ -x /usr/local/lib/kurd-node/firewall-compat.sh ]; then
  /usr/local/lib/kurd-node/firewall-compat.sh --remove >/dev/null || fail FIREWALL_COMPAT_REMOVE_FAILED
fi

# A state-v2 package may cross back to v1 only after the complete previous
# package has passed validation and every live writer has stopped. The
# authenticated, revision-bound migration marker enforced by kurdctl prevents
# rollback after any v2 authority mutation.
if [ "$previous_state_version" = "1" ] && [ -f /var/lib/kurd-node/state.kurd-state ]; then
  runuser -u kurd-node -- /usr/local/bin/kurdctl migration rollback --data-dir /var/lib/kurd-node --confirm state-v2 >/dev/null || fail STATE_V2_ROLLBACK_REJECTED
fi

failed=/var/lib/kurd-node/install/failed-current
rm -rf "$failed"
install -d -o root -g root -m 0700 "$failed/bin" "$failed/systemd" "$failed/networkd" "$failed/sysctl" "$failed/nftables" "$failed/unbound" "$failed/lib" "$failed/doc"
[ ! -x /usr/local/bin/kurd-node ] || cp -p /usr/local/bin/kurd-node "$failed/bin/kurd-node"
[ ! -x /usr/local/bin/kurdctl ] || cp -p /usr/local/bin/kurdctl "$failed/bin/kurdctl"
for unit in kurd-node.service kurd-node.socket kurd-node-network.service; do
  [ ! -f "/etc/systemd/system/$unit" ] || cp -p "/etc/systemd/system/$unit" "$failed/systemd/$unit"
done
for pair in \
  /etc/systemd/network/80-kurd0.netdev:networkd/80-kurd0.netdev \
  /etc/systemd/network/80-kurd0.network:networkd/80-kurd0.network \
  /etc/sysctl.d/90-kurd-node.conf:sysctl/90-kurd-node.conf \
  /etc/nftables.d/kurd-node.nft:nftables/kurd-node.nft \
  /etc/unbound/unbound.conf.d/kurd-node.conf:unbound/kurd-node.conf; do
  source=${pair%%:*}
  relative=${pair#*:}
  [ ! -f "$source" ] || cp -p "$source" "$failed/$relative"
done
[ ! -d /usr/local/share/doc/kurd-node ] || cp -Rp /usr/local/share/doc/kurd-node/. "$failed/doc/"
[ ! -x /usr/local/lib/kurd-node/firewall-compat.sh ] || cp -p /usr/local/lib/kurd-node/firewall-compat.sh "$failed/lib/firewall-compat.sh"

install -o root -g root -m 0755 "$previous/bin/kurd-node" /usr/local/bin/.kurd-node.rollback
install -o root -g root -m 0755 "$previous/bin/kurdctl" /usr/local/bin/.kurdctl.rollback
mv /usr/local/bin/.kurd-node.rollback /usr/local/bin/kurd-node
mv /usr/local/bin/.kurdctl.rollback /usr/local/bin/kurdctl

restore_or_remove() {
  source=$1
  target=$2
  mode_value=$3
  group_value=$4
  if [ -f "$source" ]; then
    install -o root -g "$group_value" -m "$mode_value" "$source" "$target.new"
    mv "$target.new" "$target"
  else
    rm -f "$target"
  fi
}

network_group=root
getent group systemd-network >/dev/null 2>&1 && network_group=systemd-network
restore_or_remove "$previous/systemd/kurd-node.service" /etc/systemd/system/kurd-node.service 0644 root
restore_or_remove "$previous/systemd/kurd-node.socket" /etc/systemd/system/kurd-node.socket 0644 root
restore_or_remove "$previous/systemd/kurd-node-network.service" /etc/systemd/system/kurd-node-network.service 0644 root
restore_or_remove "$previous/systemd/kurd-node.sysusers.conf" /etc/sysusers.d/kurd-node.conf 0644 root
restore_or_remove "$previous/systemd/kurd-node.tmpfiles.conf" /etc/tmpfiles.d/kurd-node.conf 0644 root
restore_or_remove "$previous/networkd/80-kurd0.netdev" /etc/systemd/network/80-kurd0.netdev 0640 "$network_group"
restore_or_remove "$previous/networkd/80-kurd0.network" /etc/systemd/network/80-kurd0.network 0644 root
restore_or_remove "$previous/sysctl/90-kurd-node.conf" /etc/sysctl.d/90-kurd-node.conf 0644 root
restore_or_remove "$previous/nftables/kurd-node.nft" /etc/nftables.d/kurd-node.nft 0600 root
restore_or_remove "$previous/unbound/kurd-node.conf" /etc/unbound/unbound.conf.d/kurd-node.conf 0644 root

rm -rf /usr/local/share/doc/kurd-node
install -d -o root -g root -m 0755 /usr/local/share/doc/kurd-node
[ ! -d "$previous/doc" ] || cp -Rp "$previous/doc/." /usr/local/share/doc/kurd-node/
for helper in firewall-compat preflight rollback uninstall upgrade; do
  restore_or_remove "$previous/lib/$helper.sh" "/usr/local/lib/kurd-node/$helper.sh" 0755 root
done

nft destroy table inet kurd_node >/dev/null 2>&1 || true
systemctl daemon-reload
recreate_owned_tun || fail PREVIOUS_TUN_RECREATE_FAILED
sysctl --system >/dev/null
rebind_owned_dns || fail PREVIOUS_DNS_REBIND_FAILED
if [ -x /usr/local/lib/kurd-node/firewall-compat.sh ]; then
  listen_port=$(sed -n 's/^ListenStream=\[::\]:\([0-9][0-9]*\)$/\1/p' /etc/systemd/system/kurd-node.socket 2>/dev/null || true)
  [ -n "$listen_port" ] || listen_port=443
  /usr/local/lib/kurd-node/firewall-compat.sh --apply "$listen_port" "$egress_interface_v4" "$egress_interface_v6" >/dev/null || fail PREVIOUS_FIREWALL_COMPAT_FAILED
fi
if [ -f /var/lib/kurd-node/state.kurd-state ]; then
  runuser -u kurd-node -- /usr/local/bin/kurdctl doctor --data-dir /var/lib/kurd-node >/dev/null || fail PREVIOUS_DOCTOR_FAILED
fi
if [ "$was_socket_enabled" = true ] && [ -f /etc/systemd/system/kurd-node.socket ]; then
  systemctl enable --now kurd-node.socket >/dev/null || fail PREVIOUS_START_FAILED
elif [ "$was_service_active" = true ]; then
  systemctl enable --now kurd-node.service >/dev/null || fail PREVIOUS_START_FAILED
fi

trap - EXIT HUP INT TERM
rm -rf "$temporary"
rm -f "$previous_doctor"
printf '{"schema":"kurd-node-rollback-v2","rolledBack":true,"authorityStateRolledBack":%s,"stateVersion":%s}\n' \
  "$( [ "$previous_state_version" = "1" ] && printf true || printf false )" "$previous_state_version"
