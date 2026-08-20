#!/bin/sh
set -eu

fail() {
  printf '{"schema":"kurd-node-upgrade-v2","applied":false,"code":"%s"}\n' "$1" >&2
  exit 2
}

mode=${1:-}
[ "$mode" = "--check" ] || [ "$mode" = "--apply" ] || fail INVALID_ARGUMENTS
shift
listen_port=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --port)
      [ "$#" -ge 2 ] || fail INVALID_ARGUMENTS
      listen_port=$2
      shift 2
      ;;
    *) fail INVALID_ARGUMENTS ;;
  esac
done
if [ -z "$listen_port" ] && [ -f /etc/systemd/system/kurd-node.socket ]; then
  listen_port=$(sed -n 's/^ListenStream=\[::\]:\([0-9][0-9]*\)$/\1/p' /etc/systemd/system/kurd-node.socket)
fi
[ -n "$listen_port" ] || listen_port=443
case "$listen_port" in
  ''|*[!0-9]*) fail INVALID_ARGUMENTS ;;
esac
[ "$listen_port" -ge 1 ] && [ "$listen_port" -le 65535 ] || fail INVALID_ARGUMENTS

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
cd "$script_dir"
for command in sha256sum sed grep tr cut id stat install mktemp cp chown chmod find rm rmdir runuser systemctl networkctl sleep; do
  command -v "$command" >/dev/null 2>&1 || fail TOOL_MISSING
done
[ -f manifest.json ] && [ -f SHA256SUMS ] || fail PACKAGE_INCOMPLETE
candidate_kurdctl_digest=$(sed -n 's/^\([0-9a-f]\{64\}\)  bin\/kurdctl$/\1/p' SHA256SUMS) || fail CHECKSUM_MISMATCH
case "$candidate_kurdctl_digest" in
  ''|*[!0-9a-f]*) fail CHECKSUM_MISMATCH ;;
esac
[ "${#candidate_kurdctl_digest}" -eq 64 ] || fail CHECKSUM_MISMATCH
candidate_inventory_digest=$(sha256sum SHA256SUMS | cut -d' ' -f1) || fail CHECKSUM_MISMATCH
case "$candidate_inventory_digest" in
  ''|*[!0-9a-f]*) fail CHECKSUM_MISMATCH ;;
esac
[ "${#candidate_inventory_digest}" -eq 64 ] || fail CHECKSUM_MISMATCH
sha256sum -c SHA256SUMS >/dev/null || fail CHECKSUM_MISMATCH

validate_source_package() {
  [ -d "$script_dir" ] && [ ! -L "$script_dir" ] || return 1
  [ "$(stat -c %u "$script_dir")" -eq 0 ] || return 1
  package_mode=$(stat -c %a "$script_dir") || return 1
  case "$package_mode" in
    *[2367][0-7]|*[0-7][2367]) return 1 ;;
  esac
  ! find "$script_dir" -type l -print -quit | grep -q . || return 1
  ! find "$script_dir" ! -user root -print -quit | grep -q . || return 1
  ! find "$script_dir" -perm /022 -print -quit | grep -q . || return 1
}

if [ "$mode" = "--apply" ]; then
  [ "$(id -u)" -eq 0 ] || fail ROOT_REQUIRED
  validate_source_package || fail PACKAGE_PERMISSIONS
fi

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
  ./preflight.sh --install --port "$listen_port" --allow-systemd-socket >/dev/null || fail PREFLIGHT_FAILED
  printf '{"schema":"kurd-node-upgrade-check-v2","currentVersion":"%s","candidateVersion":"%s","arch":"%s","currentStateVersion":%s,"candidateStateVersion":2,"verified":true,"signed":false}\n' \
    "$current_version" "$candidate_version" "$candidate_arch" "$current_state_version"
  exit 0
fi

data_dir=/var/lib/kurd-node
recipient_registry=$data_dir/recipient-registry
state_file=$data_dir/state.kurd-state
backup_dir=/var/backups/kurd-node
passphrase_file=${KURD_BACKUP_PASSPHRASE_FILE:-}
backup_file=
backup_created=false
backup_reused=false
was_service_active=false
was_socket_enabled=false
v2_mutated=false
candidate_bridge_dir=
candidate_package_dir=
candidate_bridge=
candidate_bridge_digest=
preinstall_kurdctl=/usr/local/bin/kurdctl

cleanup_candidate_bridge() {
  cleanup_status=0
  if [ -n "$candidate_bridge" ]; then
    if rm -f -- "$candidate_bridge"; then
      candidate_bridge=
    else
      cleanup_status=1
    fi
  fi
  if [ -n "$candidate_package_dir" ]; then
    if [ -n "$candidate_bridge" ]; then
      cleanup_status=1
    elif rm -rf -- "$candidate_package_dir"; then
      candidate_package_dir=
    else
      cleanup_status=1
    fi
  fi
  if [ -n "$candidate_bridge_dir" ]; then
    if [ -n "$candidate_bridge" ] || [ -n "$candidate_package_dir" ]; then
      cleanup_status=1
    elif rmdir -- "$candidate_bridge_dir" 2>/dev/null; then
      candidate_bridge_dir=
    else
      cleanup_status=1
    fi
  fi
  [ "$cleanup_status" -eq 0 ]
}

cleanup_candidate_bridge_bounded() {
  cleanup_attempt=0
  while [ "$cleanup_attempt" -lt 2 ]; do
    if cleanup_candidate_bridge; then
      return 0
    fi
    cleanup_attempt=$((cleanup_attempt + 1))
  done
  return 1
}

cleanup_and_exit() {
  status=$1
  trap - EXIT HUP INT TERM
  cleanup_candidate_bridge_bounded || {
    printf '{"schema":"kurd-node-upgrade-v2","applied":false,"code":"CANDIDATE_BRIDGE_CLEANUP_FAILED"}\n' >&2
    exit 2
  }
  exit "$status"
}

cleanup_on_exit() {
  cleanup_and_exit "$?"
}
trap cleanup_on_exit EXIT
trap 'cleanup_and_exit 129' HUP
trap 'cleanup_and_exit 130' INT
trap 'cleanup_and_exit 143' TERM

verify_candidate_package() {
  [ -n "$candidate_bridge_dir" ] && [ -n "$candidate_package_dir" ] || return 1
  [ -d "$candidate_bridge_dir" ] && [ ! -L "$candidate_bridge_dir" ] || return 1
  [ "$(stat -c %u "$candidate_bridge_dir")" -eq 0 ] || return 1
  [ "$(stat -c %g "$candidate_bridge_dir")" -eq "$(id -g kurd-node)" ] || return 1
  [ "$(stat -c %a "$candidate_bridge_dir")" = "750" ] || return 1
  [ -d "$candidate_package_dir" ] && [ ! -L "$candidate_package_dir" ] || return 1
  [ "$(stat -c %u "$candidate_package_dir")" -eq 0 ] || return 1
  [ "$(stat -c %g "$candidate_package_dir")" -eq 0 ] || return 1
  [ "$(stat -c %a "$candidate_package_dir")" = "700" ] || return 1
  ! find "$candidate_package_dir" -type l -print -quit | grep -q . || return 1
  ! find "$candidate_package_dir" ! -user root -print -quit | grep -q . || return 1
  ! find "$candidate_package_dir" -perm /022 -print -quit | grep -q . || return 1
  observed_inventory_digest=$(sha256sum "$candidate_package_dir/SHA256SUMS" | cut -d' ' -f1) || return 1
  [ "$observed_inventory_digest" = "$candidate_inventory_digest" ] || return 1
  (cd "$candidate_package_dir" && sha256sum -c SHA256SUMS >/dev/null)
}

stage_candidate_package() {
  candidate_bridge_dir=$(mktemp -d /run/kurd-node-upgrade.XXXXXX) || return 1
  chown root:kurd-node "$candidate_bridge_dir" || return 1
  chmod 0750 "$candidate_bridge_dir" || return 1
  candidate_package_dir=$candidate_bridge_dir/package
  install -d -o root -g root -m 0700 "$candidate_package_dir" || return 1
  cp -R -- "$script_dir/." "$candidate_package_dir/" || return 1
  ! find "$candidate_package_dir" -type l -print -quit | grep -q . || return 1
  chown -R root:root "$candidate_package_dir" || return 1
  chmod -R go-w "$candidate_package_dir" || return 1
  verify_candidate_package
}

verify_candidate_bridge() {
  [ -n "$candidate_bridge_dir" ] && [ -n "$candidate_bridge" ] && [ -n "$candidate_bridge_digest" ] || return 1
  [ -d "$candidate_bridge_dir" ] && [ ! -L "$candidate_bridge_dir" ] || return 1
  [ "$(stat -c %u "$candidate_bridge_dir")" -eq 0 ] || return 1
  [ "$(stat -c %g "$candidate_bridge_dir")" -eq "$(id -g kurd-node)" ] || return 1
  [ "$(stat -c %a "$candidate_bridge_dir")" = "750" ] || return 1
  [ -f "$candidate_bridge" ] && [ ! -L "$candidate_bridge" ] || return 1
  [ "$(stat -c %u "$candidate_bridge")" -eq 0 ] || return 1
  [ "$(stat -c %g "$candidate_bridge")" -eq "$(id -g kurd-node)" ] || return 1
  [ "$(stat -c %a "$candidate_bridge")" = "750" ] || return 1
  observed_bridge_digest=$(sha256sum "$candidate_bridge" | cut -d' ' -f1) || return 1
  [ "$observed_bridge_digest" = "$candidate_bridge_digest" ]
}

stage_candidate_bridge() {
  [ -f bin/kurdctl ] && [ ! -L bin/kurdctl ] || return 1
  candidate_bridge_digest=$candidate_kurdctl_digest
  candidate_bridge=$candidate_bridge_dir/kurdctl
  install -o root -g kurd-node -m 0750 bin/kurdctl "$candidate_bridge" || return 1
  verify_candidate_bridge
}

stage_candidate_package || fail CANDIDATE_PACKAGE_FAILED
cd "$candidate_package_dir"
./preflight.sh --install --port "$listen_port" --allow-systemd-socket >/dev/null || fail PREFLIGHT_FAILED

if [ -f "$state_file" ] && [ "$current_state_version" = "2" ]; then
  stage_candidate_bridge || fail CANDIDATE_BRIDGE_FAILED
  preinstall_kurdctl=$candidate_bridge
fi

node_state_transition() {
  action=$1
  if [ "$preinstall_kurdctl" = "$candidate_bridge" ]; then
    verify_candidate_bridge || fail CANDIDATE_BRIDGE_INVALID
  fi
  set +e
  runuser -u kurd-node -- "$preinstall_kurdctl" node "$action" --data-dir "$data_dir" >/dev/null
  status=$?
  set -e
  [ "$status" -eq 0 ] || [ "$status" -eq 7 ]
}

systemctl is-active --quiet kurd-node.service && was_service_active=true || true
systemctl is-enabled --quiet kurd-node.socket && was_socket_enabled=true || true

if [ -f "$state_file" ]; then
  [ -n "$passphrase_file" ] && [ -f "$passphrase_file" ] && [ ! -L "$passphrase_file" ] || fail BACKUP_PASSPHRASE_REQUIRED
  [ "$(stat -c %u "$passphrase_file")" -eq 0 ] || fail BACKUP_PASSPHRASE_OWNERSHIP
  passphrase_mode=$(stat -c %a "$passphrase_file")
  [ "$passphrase_mode" = "600" ] || [ "$passphrase_mode" = "400" ] || fail BACKUP_PASSPHRASE_PERMISSIONS
  install -d -o kurd-node -g kurd-node -m 0700 "$backup_dir"
  state_digest=$(sha256sum "$state_file" | cut -d' ' -f1)
  case "$state_digest" in
    ''|*[!0-9a-f]*) fail STATE_DIGEST_INVALID ;;
  esac
  [ "${#state_digest}" -eq 64 ] || fail STATE_DIGEST_INVALID
  backup_file=$backup_dir/pre-upgrade-$candidate_version-$state_digest.kurd-backup
  node_state_transition drain || fail DRAIN_FAILED
  if [ -e "$backup_file" ]; then
    [ -f "$backup_file" ] && [ ! -L "$backup_file" ] || fail BACKUP_INVALID
    backup_reused=true
  else
    if [ "$preinstall_kurdctl" = "$candidate_bridge" ]; then
      verify_candidate_bridge || fail CANDIDATE_BRIDGE_INVALID
    fi
    runuser -u kurd-node -- "$preinstall_kurdctl" backup create --data-dir "$data_dir" --recipient-registry-dir "$recipient_registry" --file "$backup_file" <"$passphrase_file" >/dev/null || fail BACKUP_FAILED
    backup_created=true
  fi
  if [ "$preinstall_kurdctl" = "$candidate_bridge" ]; then
    verify_candidate_bridge || fail CANDIDATE_BRIDGE_INVALID
  fi
  runuser -u kurd-node -- "$preinstall_kurdctl" backup verify --file "$backup_file" <"$passphrase_file" >/dev/null || fail BACKUP_VERIFY_FAILED
fi

rollback_and_exit() {
  status=$1
  trap - EXIT HUP INT TERM
  if [ "$v2_mutated" = false ] && [ -x /usr/local/lib/kurd-node/rollback.sh ] && [ -d /var/lib/kurd-node/install/previous ]; then
    /usr/local/lib/kurd-node/rollback.sh --apply --confirm rollback >/dev/null 2>&1 || true
  fi
  cleanup_candidate_bridge_bounded || {
    printf '{"schema":"kurd-node-upgrade-v2","applied":false,"code":"CANDIDATE_BRIDGE_CLEANUP_FAILED"}\n' >&2
    exit 2
  }
  exit "$status"
}

rollback_on_exit() {
  rollback_and_exit "$?"
}
trap rollback_on_exit EXIT
trap 'rollback_and_exit 129' HUP
trap 'rollback_and_exit 130' INT
trap 'rollback_and_exit 143' TERM

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

systemctl stop kurd-node.socket kurd-node.service kurd-node-network.service 2>/dev/null || true
verify_candidate_package || fail CANDIDATE_PACKAGE_INVALID
./install.sh --upgrade --port "$listen_port" >/dev/null || fail INSTALL_FAILED
installed_kurdctl_digest=$(sha256sum /usr/local/bin/kurdctl | cut -d' ' -f1) || fail INSTALLED_IDENTITY_INVALID
[ "$installed_kurdctl_digest" = "$candidate_kurdctl_digest" ] || fail INSTALLED_IDENTITY_INVALID
preinstall_kurdctl=/usr/local/bin/kurdctl
cd /
cleanup_candidate_bridge || fail CANDIDATE_BRIDGE_CLEANUP_FAILED
recreate_owned_tun || fail TUN_RECREATE_FAILED
rebind_owned_dns || fail DNS_REBIND_FAILED

if [ -f "$state_file" ]; then
  runuser -u kurd-node -- /usr/local/bin/kurdctl migration apply --data-dir "$data_dir" >/dev/null || fail MIGRATION_FAILED
  v2_mutated=true
  runuser -u kurd-node -- /usr/local/bin/kurdctl doctor --data-dir "$data_dir" >/dev/null || fail DOCTOR_FAILED
  node_state_transition resume || fail RESUME_FAILED
fi

if [ "$was_socket_enabled" = true ] || [ "$was_service_active" = true ]; then
  systemctl enable --now kurd-node-network.service kurd-node.socket >/dev/null || fail SERVICE_START_FAILED
fi
if [ "$was_service_active" = true ]; then
  systemctl start kurd-node.service >/dev/null || fail SERVICE_START_FAILED
  systemctl is-active --quiet kurd-node.service || fail SERVICE_HEALTH_FAILED
fi

trap - EXIT HUP INT TERM
printf '{"schema":"kurd-node-upgrade-apply-v2","previousVersion":"%s","currentVersion":"%s","applied":true,"stateVersion":2,"backupCreated":%s,"backupReused":%s}\n' \
  "$current_version" "$candidate_version" "$backup_created" "$backup_reused"
