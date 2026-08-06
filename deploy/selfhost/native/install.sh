#!/bin/sh
set -eu

mode=${1:---install}
if [ "$mode" != "--install" ] && [ "$mode" != "--upgrade" ]; then
  echo "usage: install.sh [--install|--upgrade]" >&2
  exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must run as root" >&2
  exit 2
fi
if [ "$(uname -s)" != "Linux" ]; then
  echo "unsupported operating system" >&2
  exit 2
fi
case "$(uname -m)" in
  x86_64) expected_arch=amd64 ;;
  aarch64|arm64) expected_arch=arm64 ;;
  *) echo "unsupported architecture" >&2; exit 2 ;;
esac
archive_arch=$(sed -n 's/.*"arch"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' manifest.json)
if [ "$archive_arch" != "$expected_arch" ]; then
  echo "package architecture mismatch" >&2
  exit 2
fi
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 2; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required" >&2; exit 2; }
sha256sum -c SHA256SUMS
./preflight.sh --install

install_root=/var/lib/kurd-node/install
previous_new="$install_root/previous.new"
previous="$install_root/previous"
if [ -x /usr/local/bin/kurd-node ] || [ -x /usr/local/bin/kurdctl ]; then
  install -d -o root -g root -m 0700 "$install_root"
  rm -rf "$previous_new"
  install -d -o root -g root -m 0700 "$previous_new/bin" "$previous_new/systemd" "$previous_new/lib" "$previous_new/doc"
  [ ! -x /usr/local/bin/kurd-node ] || cp -p /usr/local/bin/kurd-node "$previous_new/bin/kurd-node"
  [ ! -x /usr/local/bin/kurdctl ] || cp -p /usr/local/bin/kurdctl "$previous_new/bin/kurdctl"
  [ ! -f /etc/systemd/system/kurd-node.service ] || cp -p /etc/systemd/system/kurd-node.service "$previous_new/systemd/kurd-node.service"
  [ ! -f /etc/sysusers.d/kurd-node.conf ] || cp -p /etc/sysusers.d/kurd-node.conf "$previous_new/systemd/kurd-node.sysusers.conf"
  [ ! -f /etc/tmpfiles.d/kurd-node.conf ] || cp -p /etc/tmpfiles.d/kurd-node.conf "$previous_new/systemd/kurd-node.tmpfiles.conf"
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

install -o root -g root -m 0755 bin/kurd-node /usr/local/bin/.kurd-node.new
install -o root -g root -m 0755 bin/kurdctl /usr/local/bin/.kurdctl.new
mv /usr/local/bin/.kurd-node.new /usr/local/bin/kurd-node
mv /usr/local/bin/.kurdctl.new /usr/local/bin/kurdctl
install -d -o root -g root -m 0755 /etc/systemd/system /etc/sysusers.d /etc/tmpfiles.d
install -o root -g root -m 0644 systemd/kurd-node.service /etc/systemd/system/kurd-node.service
install -o root -g root -m 0644 systemd/kurd-node.sysusers.conf /etc/sysusers.d/kurd-node.conf
install -o root -g root -m 0644 systemd/kurd-node.tmpfiles.conf /etc/tmpfiles.d/kurd-node.conf
install -d -o root -g root -m 0755 /usr/local/share/doc/kurd-node
install -o root -g root -m 0644 docs/* /usr/local/share/doc/kurd-node/
install -o root -g root -m 0644 manifest.json THIRD_PARTY_MODULES.json SHA256SUMS /usr/local/share/doc/kurd-node/
install -d -o root -g root -m 0755 /usr/local/lib/kurd-node
install -o root -g root -m 0755 rollback.sh uninstall.sh preflight.sh upgrade.sh /usr/local/lib/kurd-node/
systemd-sysusers /etc/sysusers.d/kurd-node.conf
systemd-tmpfiles --create /etc/tmpfiles.d/kurd-node.conf
systemctl daemon-reload
printf '{"schema":"kurd-node-install-v1","mode":"%s","installed":true}\n' "$mode"
