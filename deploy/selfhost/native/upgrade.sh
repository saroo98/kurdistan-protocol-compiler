#!/bin/sh
set -eu

mode=${1:-}
if [ "$mode" != "--check" ] && [ "$mode" != "--apply" ]; then
  echo "usage: upgrade.sh <--check|--apply>" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cd "$script_dir"
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 2; }
sha256sum -c SHA256SUMS >/dev/null
./preflight.sh --install >/dev/null

candidate_version=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' manifest.json)
candidate_arch=$(sed -n 's/.*"arch"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' manifest.json)
current_version=none
if [ -f /usr/local/share/doc/kurd-node/manifest.json ]; then
  current_version=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /usr/local/share/doc/kurd-node/manifest.json)
fi
if [ -z "$candidate_version" ] || [ -z "$candidate_arch" ]; then
  echo "package manifest is incomplete" >&2
  exit 2
fi
if [ "$mode" = "--check" ]; then
  printf '{"schema":"kurd-node-upgrade-check-v1","currentVersion":"%s","candidateVersion":"%s","arch":"%s","verified":true,"signed":false}\n' "$current_version" "$candidate_version" "$candidate_arch"
  exit 0
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "upgrade apply must run as root" >&2
  exit 2
fi

was_active=false
if systemctl is-active --quiet kurd-node.service; then
  was_active=true
fi
if [ -f /var/lib/kurd-node/state.kurd-state ] && [ -x /usr/local/bin/kurdctl ]; then
  runuser -u kurd-node -- /usr/local/bin/kurdctl node drain --data-dir /var/lib/kurd-node >/dev/null
fi
systemctl stop kurd-node.service 2>/dev/null || true

rollback_on_failure() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -x /usr/local/lib/kurd-node/rollback.sh ] && [ -d /var/lib/kurd-node/install/previous ]; then
    /usr/local/lib/kurd-node/rollback.sh --apply --confirm rollback >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap rollback_on_failure EXIT HUP INT TERM
./install.sh --upgrade >/dev/null
if [ -f /var/lib/kurd-node/state.kurd-state ]; then
  runuser -u kurd-node -- /usr/local/bin/kurdctl doctor --data-dir /var/lib/kurd-node >/dev/null
  runuser -u kurd-node -- /usr/local/bin/kurdctl node resume --data-dir /var/lib/kurd-node >/dev/null
fi
if [ "$was_active" = true ]; then
  systemctl enable --now kurd-node.service >/dev/null
  systemctl is-active --quiet kurd-node.service
fi
trap - EXIT HUP INT TERM
printf '{"schema":"kurd-node-upgrade-apply-v1","previousVersion":"%s","currentVersion":"%s","applied":true}\n' "$current_version" "$candidate_version"
