#!/bin/sh
set -eu

fail() {
  printf '{"schema":"kurd-node-install-v2","installed":false,"code":"%s"}\n' "$1" >&2
  exit 2
}

mode=${1:---install}
[ "$mode" = "--install" ] || [ "$mode" = "--upgrade" ] || fail INVALID_ARGUMENTS
[ "$(id -u)" -eq 0 ] || fail ROOT_REQUIRED
[ "$(uname -s)" = "Linux" ] || fail OS_UNSUPPORTED
case "$(uname -m)" in
  x86_64) expected_arch=amd64 ;;
  aarch64|arm64) expected_arch=arm64 ;;
  *) fail ARCH_UNSUPPORTED ;;
esac

for command in sha256sum systemctl systemd-analyze systemd-sysusers systemd-tmpfiles networkctl nft unbound unbound-checkconf sysctl stat getent mktemp sed grep basename dirname install mv cp rm runuser; do
  command -v "$command" >/dev/null 2>&1 || fail TOOL_MISSING
done
[ -f manifest.json ] && [ -f SHA256SUMS ] || fail PACKAGE_INCOMPLETE
archive_arch=$(sed -n 's/.*"arch"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' manifest.json)
[ "$archive_arch" = "$expected_arch" ] || fail ARCH_MISMATCH
grep -Eq '"relayDataPlane"[[:space:]]*:[[:space:]]*true' manifest.json || fail AUTHORITY_MISMATCH
grep -Eq '"signed"[[:space:]]*:[[:space:]]*false' manifest.json || fail SIGNATURE_STATE_MISMATCH
sha256sum -c SHA256SUMS >/dev/null || fail CHECKSUM_MISMATCH

unset KURD_PREFLIGHT_TEST_ROOT KURD_PREFLIGHT_ALLOW_TEST_ROOT
preflight_output=$(./preflight.sh --install --port 443) || fail PREFLIGHT_FAILED
egress_interface_v4=$(printf '%s\n' "$preflight_output" | sed -n 's/.*"egressInterfaceV4":"\([A-Za-z0-9_.:-]*\)".*/\1/p')
egress_interface_v6=$(printf '%s\n' "$preflight_output" | sed -n 's/.*"egressInterfaceV6":"\([A-Za-z0-9_.:-]*\)".*/\1/p')
[ -n "$egress_interface_v4" ] && [ -n "$egress_interface_v6" ] || fail PREFLIGHT_FAILED

temporary=$(mktemp -d /var/tmp/kurd-node-install.XXXXXX)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
sed -e "s/KURD_EGRESS_INTERFACE_V4/$egress_interface_v4/g" -e "s/KURD_EGRESS_INTERFACE_V6/$egress_interface_v6/g" nftables/kurd-node.nft >"$temporary/kurd-node.nft"

systemd_root=$temporary/systemd-root
install -d -o root -g root -m 0755 \
  "$systemd_root/etc/systemd/system" \
  "$systemd_root/usr/lib/systemd" \
  "$systemd_root/usr/local/bin" \
  "$systemd_root/usr/local/lib/kurd-node"
systemd_unit_source=
for candidate in /usr/lib/systemd/system /lib/systemd/system; do
  if [ -d "$candidate" ]; then
    systemd_unit_source=$candidate
    break
  fi
done
[ -n "$systemd_unit_source" ] || fail SYSTEMD_CONFIG_INVALID
cp -Rp "$systemd_unit_source" "$systemd_root/usr/lib/systemd/system"
for unit in kurd-node-network.service kurd-node.socket kurd-node.service; do
  install -o root -g root -m 0644 "systemd/$unit" "$systemd_root/etc/systemd/system/$unit"
done

stage_systemd_executable() {
  source=$1
  target=$2
  [ -x "$source" ] || fail SYSTEMD_CONFIG_INVALID
  install -d -o root -g root -m 0755 "$systemd_root$(dirname "$target")"
  install -o root -g root -m 0755 "$source" "$systemd_root$target"
}

stage_systemd_executable bin/kurd-node /usr/local/bin/kurd-node
stage_systemd_executable bin/kurdctl /usr/local/bin/kurdctl
stage_systemd_executable preflight.sh /usr/local/lib/kurd-node/preflight.sh
stage_systemd_executable "$(command -v nft)" /usr/sbin/nft
stage_systemd_executable "$(command -v unbound)" /usr/sbin/unbound
stage_systemd_executable /usr/lib/systemd/systemd-networkd /usr/lib/systemd/systemd-networkd
systemd-analyze --root="$systemd_root" verify kurd-node-network.service kurd-node.socket kurd-node.service >/dev/null || fail SYSTEMD_CONFIG_INVALID
unbound-checkconf unbound/kurd-node-unbound.conf >/dev/null || fail UNBOUND_CONFIG_INVALID
nft -c -f "$temporary/kurd-node.nft" >/dev/null || fail NFT_CONFIG_INVALID

assert_owned_target() {
  target=$1
  if [ -L "$target" ]; then
    fail OWNERSHIP_REJECTED
  fi
  if [ -e "$target" ]; then
    [ -f "$target" ] || fail OWNERSHIP_REJECTED
    [ "$(stat -c %u "$target")" -eq 0 ] || fail OWNERSHIP_REJECTED
  fi
}

install_atomic() {
  source=$1
  target=$2
  mode_value=$3
  owner=$4
  group=$5
  assert_owned_target "$target"
  install -o "$owner" -g "$group" -m "$mode_value" "$source" "$target.new"
  mv -f "$target.new" "$target"
}

install_root=/var/lib/kurd-node/install
previous_new=$install_root/previous.new
previous=$install_root/previous
if [ -x /usr/local/bin/kurd-node ] || [ -x /usr/local/bin/kurdctl ]; then
  install -d -o root -g root -m 0700 "$install_root"
  rm -rf "$previous_new"
  install -d -o root -g root -m 0700 "$previous_new"
  for directory in bin systemd networkd sysctl nftables unbound lib doc; do
    install -d -o root -g root -m 0700 "$previous_new/$directory"
  done
  [ ! -x /usr/local/bin/kurd-node ] || cp -p /usr/local/bin/kurd-node "$previous_new/bin/kurd-node"
  [ ! -x /usr/local/bin/kurdctl ] || cp -p /usr/local/bin/kurdctl "$previous_new/bin/kurdctl"
  for unit in kurd-node.service kurd-node.socket kurd-node-network.service; do
    [ ! -f "/etc/systemd/system/$unit" ] || cp -p "/etc/systemd/system/$unit" "$previous_new/systemd/$unit"
  done
  [ ! -f /etc/sysusers.d/kurd-node.conf ] || cp -p /etc/sysusers.d/kurd-node.conf "$previous_new/systemd/kurd-node.sysusers.conf"
  [ ! -f /etc/tmpfiles.d/kurd-node.conf ] || cp -p /etc/tmpfiles.d/kurd-node.conf "$previous_new/systemd/kurd-node.tmpfiles.conf"
  [ ! -f /etc/systemd/network/80-kurd0.netdev ] || cp -p /etc/systemd/network/80-kurd0.netdev "$previous_new/networkd/80-kurd0.netdev"
  [ ! -f /etc/systemd/network/80-kurd0.network ] || cp -p /etc/systemd/network/80-kurd0.network "$previous_new/networkd/80-kurd0.network"
  [ ! -f /etc/sysctl.d/90-kurd-node.conf ] || cp -p /etc/sysctl.d/90-kurd-node.conf "$previous_new/sysctl/90-kurd-node.conf"
  [ ! -f /etc/nftables.d/kurd-node.nft ] || cp -p /etc/nftables.d/kurd-node.nft "$previous_new/nftables/kurd-node.nft"
  [ ! -f /etc/unbound/unbound.conf.d/kurd-node.conf ] || cp -p /etc/unbound/unbound.conf.d/kurd-node.conf "$previous_new/unbound/kurd-node.conf"
  for helper in preflight rollback uninstall upgrade; do
    [ ! -f "/usr/local/lib/kurd-node/$helper.sh" ] || cp -p "/usr/local/lib/kurd-node/$helper.sh" "$previous_new/lib/$helper.sh"
  done
  if [ -d /usr/local/share/doc/kurd-node ]; then
    cp -Rp /usr/local/share/doc/kurd-node/. "$previous_new/doc/"
  fi
  rm -rf "$install_root/previous.old"
  [ ! -d "$previous" ] || mv "$previous" "$install_root/previous.old"
  mv "$previous_new" "$previous"
  rm -rf "$install_root/previous.old"
fi

for directory in /usr/local/bin /usr/local/lib/kurd-node /usr/local/share/doc/kurd-node /etc/systemd/system /etc/sysusers.d /etc/tmpfiles.d /etc/systemd/network /etc/sysctl.d /etc/nftables.d /etc/unbound/unbound.conf.d; do
  install -d -o root -g root -m 0755 "$directory"
done

install_atomic bin/kurd-node /usr/local/bin/kurd-node 0755 root root
install_atomic bin/kurdctl /usr/local/bin/kurdctl 0755 root root
for unit in kurd-node.service kurd-node.socket kurd-node-network.service; do
  install_atomic "systemd/$unit" "/etc/systemd/system/$unit" 0644 root root
done
install_atomic systemd/kurd-node.sysusers.conf /etc/sysusers.d/kurd-node.conf 0644 root root
install_atomic systemd/kurd-node.tmpfiles.conf /etc/tmpfiles.d/kurd-node.conf 0644 root root
systemd-sysusers /etc/sysusers.d/kurd-node.conf
network_group=root
getent group systemd-network >/dev/null 2>&1 && network_group=systemd-network
install_atomic networkd/80-kurd0.netdev /etc/systemd/network/80-kurd0.netdev 0640 root "$network_group"
install_atomic networkd/80-kurd0.network /etc/systemd/network/80-kurd0.network 0644 root root
install_atomic sysctl/90-kurd-node.conf /etc/sysctl.d/90-kurd-node.conf 0644 root root
install_atomic "$temporary/kurd-node.nft" /etc/nftables.d/kurd-node.nft 0600 root root
install_atomic unbound/kurd-node-unbound.conf /etc/unbound/unbound.conf.d/kurd-node.conf 0644 root root
for helper in preflight rollback uninstall upgrade; do
  install_atomic "$helper.sh" "/usr/local/lib/kurd-node/$helper.sh" 0755 root root
done
for document in docs/* manifest.json THIRD_PARTY_MODULES.json SHA256SUMS; do
  install_atomic "$document" "/usr/local/share/doc/kurd-node/$(basename "$document")" 0644 root root
done

systemd-tmpfiles --create /etc/tmpfiles.d/kurd-node.conf
systemctl daemon-reload
networkctl reload
sysctl --system >/dev/null
unbound-checkconf /etc/unbound/unbound.conf.d/kurd-node.conf >/dev/null
nft -c -f /etc/nftables.d/kurd-node.nft >/dev/null
systemctl try-reload-or-restart unbound.service >/dev/null 2>&1 || true

trap - EXIT HUP INT TERM
rm -rf "$temporary"
printf '{"schema":"kurd-node-install-v2","mode":"%s","installed":true,"relayDataPlane":true,"serviceEnabled":false}\n' "${mode#--}"
