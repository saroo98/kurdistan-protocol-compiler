#!/bin/sh
set -eu

fail() {
  printf '{"schema":"kurd-node-upgrade-v2","applied":false,"code":"%s"}\n' "$1" >&2
  exit 2
}

mode=${1:-}
[ "$mode" = "--check" ] || [ "$mode" = "--apply" ] || fail INVALID_ARGUMENTS

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
cd "$script_dir"
for command in sha256sum sed grep tr id stat install runuser systemctl networkctl sleep; do
  command -v "$command" >/dev/null 2>&1 || fail TOOL_MISSING
done
[ -f manifest.json ] && [ -f SHA256SUMS ] || fail PACKAGE_INCOMPLETE
sha256sum -c SHA256SUMS >/dev/null || fail CHECKSUM_MISMATCH
./preflight.sh --install --port 443 --allow-systemd-socket >/dev/null || fail PREFLIGHT_FAILED

manifest_value() {
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\(\"[^\"]*\"\|[0-9][0-9]*\).*/\1/p" "$2" | tr -d '"'
}

candidate_version=$(manifest_value version manifest.json)
candidate_arch=$(manifest_value arch manifest.json)
candidate_state_version=$(manifest_value stateVersion manifest.json)
current_manifest=/usr/local/share/doc/kurd-node/manifest.json
current_version=none
current_state_version=1
if [ -f "$current_manifest" ]; then
  current_version=$(manifest_value version "$current_manifest")
  observed_state_version=$(manifest_value stateVersion "$current_manifest")
  [ -z "$observed_state_version" ] || current_state_version=$observed_state_version
fi
[ -n "$candidate_version" ] && [ -n "$candidate_arch" ] && [ "$candidate_state_version" = "2" ] || fail MANIFEST_INVALID

if [ "$mode" = "--check" ]; then
  printf '{"schema":"kurd-node-upgrade-check-v2","currentVersion":"%s","candidateVersion":"%s","arch":"%s","currentStateVersion":%s,"candidateStateVersion":2,"verified":true,"signed":false}\n' \
    "$current_version" "$candidate_version" "$candidate_arch" "$current_state_version"
  exit 0
fi
[ "$(id -u)" -eq 0 ] || fail ROOT_REQUIRED

data_dir=/var/lib/kurd-node
state_file=$data_dir/state.kurd-state
backup_dir=/var/backups/kurd-node
passphrase_file=${KURD_BACKUP_PASSPHRASE_FILE:-}
backup_file=
was_service_active=false
was_socket_enabled=false
v2_mutated=false

systemctl is-active --quiet kurd-node.service && was_service_active=true || true
systemctl is-enabled --quiet kurd-node.socket && was_socket_enabled=true || true

if [ -f "$state_file" ]; then
  [ -n "$passphrase_file" ] && [ -f "$passphrase_file" ] && [ ! -L "$passphrase_file" ] || fail BACKUP_PASSPHRASE_REQUIRED
  [ "$(stat -c %u "$passphrase_file")" -eq 0 ] || fail BACKUP_PASSPHRASE_OWNERSHIP
  passphrase_mode=$(stat -c %a "$passphrase_file")
  [ "$passphrase_mode" = "600" ] || [ "$passphrase_mode" = "400" ] || fail BACKUP_PASSPHRASE_PERMISSIONS
  install -d -o kurd-node -g kurd-node -m 0700 "$backup_dir"
  backup_file=$backup_dir/pre-upgrade-$candidate_version.kurd-backup
  [ ! -e "$backup_file" ] || fail BACKUP_EXISTS
  runuser -u kurd-node -- /usr/local/bin/kurdctl node drain --data-dir "$data_dir" >/dev/null || fail DRAIN_FAILED
  runuser -u kurd-node -- /usr/local/bin/kurdctl backup create --data-dir "$data_dir" --file "$backup_file" <"$passphrase_file" >/dev/null || fail BACKUP_FAILED
  runuser -u kurd-node -- /usr/local/bin/kurdctl backup verify --file "$backup_file" <"$passphrase_file" >/dev/null || fail BACKUP_VERIFY_FAILED
fi

rollback_on_failure() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$v2_mutated" = false ] && [ -x /usr/local/lib/kurd-node/rollback.sh ] && [ -d /var/lib/kurd-node/install/previous ]; then
    /usr/local/lib/kurd-node/rollback.sh --apply --confirm rollback >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap rollback_on_failure EXIT HUP INT TERM

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

systemctl stop kurd-node.socket kurd-node.service kurd-node-network.service 2>/dev/null || true
./install.sh --upgrade >/dev/null || fail INSTALL_FAILED
recreate_owned_tun || fail TUN_RECREATE_FAILED

if [ -f "$state_file" ]; then
  runuser -u kurd-node -- /usr/local/bin/kurdctl migration apply --data-dir "$data_dir" >/dev/null || fail MIGRATION_FAILED
  v2_mutated=true
  runuser -u kurd-node -- /usr/local/bin/kurdctl doctor --data-dir "$data_dir" >/dev/null || fail DOCTOR_FAILED
  runuser -u kurd-node -- /usr/local/bin/kurdctl node resume --data-dir "$data_dir" >/dev/null || fail RESUME_FAILED
fi

if [ "$was_socket_enabled" = true ] || [ "$was_service_active" = true ]; then
  systemctl enable --now kurd-node-network.service kurd-node.socket >/dev/null || fail SERVICE_START_FAILED
fi
if [ "$was_service_active" = true ]; then
  systemctl start kurd-node.service >/dev/null || fail SERVICE_START_FAILED
  systemctl is-active --quiet kurd-node.service || fail SERVICE_HEALTH_FAILED
fi

trap - EXIT HUP INT TERM
printf '{"schema":"kurd-node-upgrade-apply-v2","previousVersion":"%s","currentVersion":"%s","applied":true,"stateVersion":2,"backupCreated":%s}\n' \
  "$current_version" "$candidate_version" "$( [ -n "$backup_file" ] && printf true || printf false )"
