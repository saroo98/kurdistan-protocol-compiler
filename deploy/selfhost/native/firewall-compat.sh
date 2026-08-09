#!/bin/sh
set -eu

fail() {
  printf '{"schema":"kurd-node-firewall-compat-v1","status":"FAIL","code":"%s"}\n' "$1" >&2
  exit 2
}

mode=${1:-}
case "$mode" in
  --check|--apply)
    [ "$#" -eq 4 ] || fail INVALID_ARGUMENTS
    ingress_port=$2
    egress_interface_v4=$3
    egress_interface_v6=$4
    ;;
  --remove)
    [ "$#" -eq 1 ] || fail INVALID_ARGUMENTS
    egress_interface_v4=
    egress_interface_v6=
    ingress_port=
    ;;
  *) fail INVALID_ARGUMENTS ;;
esac

case "$ingress_port" in
  ''|*[!0-9]*) [ "$mode" = "--remove" ] || fail INVALID_ARGUMENTS ;;
esac
if [ "$mode" != "--remove" ]; then
  [ "$ingress_port" -ge 1 ] && [ "$ingress_port" -le 65535 ] || fail INVALID_ARGUMENTS
fi

case "$egress_interface_v4:$egress_interface_v6" in
  *[!A-Za-z0-9_.:-]*) fail INVALID_ARGUMENTS ;;
esac

state_dir=/var/lib/kurd-node/install
state_file=$state_dir/firewall-compat-v1.state
marker=kurd-node-managed-v1

if ! command -v ufw >/dev/null 2>&1; then
  [ "$mode" != "--remove" ] || rm -f "$state_file"
  printf '{"schema":"kurd-node-firewall-compat-v1","status":"PASS","mode":"%s","ufwPresent":false,"changed":false}\n' "${mode#--}"
  exit 0
fi

export LC_ALL=C
for command in grep install mktemp mv rm sed ufw; do
  command -v "$command" >/dev/null 2>&1 || fail TOOL_MISSING
done

ipv6_enabled=false
if [ -f /etc/default/ufw ] && grep -Eq '^IPV6=(yes|YES)$' /etc/default/ufw; then
  ipv6_enabled=true
fi

managed_rule_present() {
  comment=$1
  ufw show added 2>/dev/null | grep -F "comment '$comment'" >/dev/null 2>&1
}

check_rules() {
  ufw --dry-run allow in on kurd0 to 10.77.0.1 port 53 proto udp comment "$marker-dns4-udp" >/dev/null
  ufw --dry-run allow in on kurd0 to 10.77.0.1 port 53 proto tcp comment "$marker-dns4-tcp" >/dev/null
  ufw --dry-run route allow in on kurd0 out on "$egress_interface_v4" from 10.77.0.0/24 comment "$marker-route4" >/dev/null
  ufw --dry-run allow in on "$egress_interface_v4" to any port "$ingress_port" proto tcp comment "$marker-ingress4" >/dev/null
  if [ "$ipv6_enabled" = true ]; then
    ufw --dry-run allow in on kurd0 to fd4b:7572:6400::1 port 53 proto udp comment "$marker-dns6-udp" >/dev/null
    ufw --dry-run allow in on kurd0 to fd4b:7572:6400::1 port 53 proto tcp comment "$marker-dns6-tcp" >/dev/null
    ufw --dry-run route allow in on kurd0 out on "$egress_interface_v6" from fd4b:7572:6400::/64 comment "$marker-route6" >/dev/null
    ufw --dry-run allow in on "$egress_interface_v6" to any port "$ingress_port" proto tcp comment "$marker-ingress6" >/dev/null
  fi
}

apply_rules() {
  ufw allow in on kurd0 to 10.77.0.1 port 53 proto udp comment "$marker-dns4-udp" >/dev/null
  ufw allow in on kurd0 to 10.77.0.1 port 53 proto tcp comment "$marker-dns4-tcp" >/dev/null
  ufw route allow in on kurd0 out on "$egress_interface_v4" from 10.77.0.0/24 comment "$marker-route4" >/dev/null
  ufw allow in on "$egress_interface_v4" to any port "$ingress_port" proto tcp comment "$marker-ingress4" >/dev/null
  if [ "$ipv6_enabled" = true ]; then
    ufw allow in on kurd0 to fd4b:7572:6400::1 port 53 proto udp comment "$marker-dns6-udp" >/dev/null
    ufw allow in on kurd0 to fd4b:7572:6400::1 port 53 proto tcp comment "$marker-dns6-tcp" >/dev/null
    ufw route allow in on kurd0 out on "$egress_interface_v6" from fd4b:7572:6400::/64 comment "$marker-route6" >/dev/null
    ufw allow in on "$egress_interface_v6" to any port "$ingress_port" proto tcp comment "$marker-ingress6" >/dev/null
  fi
}

remove_rules() {
  if managed_rule_present "$marker-dns4-udp"; then
    ufw --force delete allow in on kurd0 to 10.77.0.1 port 53 proto udp comment "$marker-dns4-udp" >/dev/null
  fi
  if managed_rule_present "$marker-dns4-tcp"; then
    ufw --force delete allow in on kurd0 to 10.77.0.1 port 53 proto tcp comment "$marker-dns4-tcp" >/dev/null
  fi
  if managed_rule_present "$marker-route4"; then
    ufw --force delete route allow in on kurd0 out on "$egress_interface_v4" from 10.77.0.0/24 comment "$marker-route4" >/dev/null
  fi
  if managed_rule_present "$marker-ingress4"; then
    ufw --force delete allow in on "$egress_interface_v4" to any port "$ingress_port" proto tcp comment "$marker-ingress4" >/dev/null
  fi
  if managed_rule_present "$marker-dns6-udp"; then
    ufw --force delete allow in on kurd0 to fd4b:7572:6400::1 port 53 proto udp comment "$marker-dns6-udp" >/dev/null
  fi
  if managed_rule_present "$marker-dns6-tcp"; then
    ufw --force delete allow in on kurd0 to fd4b:7572:6400::1 port 53 proto tcp comment "$marker-dns6-tcp" >/dev/null
  fi
  if managed_rule_present "$marker-route6"; then
    ufw --force delete route allow in on kurd0 out on "$egress_interface_v6" from fd4b:7572:6400::/64 comment "$marker-route6" >/dev/null
  fi
  if managed_rule_present "$marker-ingress6"; then
    ufw --force delete allow in on "$egress_interface_v6" to any port "$ingress_port" proto tcp comment "$marker-ingress6" >/dev/null
  fi
}

read_state() {
  [ -f "$state_file" ] && [ ! -L "$state_file" ] || return 1
  egress_interface_v4=$(sed -n 's/^egressInterfaceV4=\([A-Za-z0-9_.:-]*\)$/\1/p' "$state_file")
  egress_interface_v6=$(sed -n 's/^egressInterfaceV6=\([A-Za-z0-9_.:-]*\)$/\1/p' "$state_file")
  ingress_port=$(sed -n 's/^ingressPort=\([0-9][0-9]*\)$/\1/p' "$state_file")
  [ -n "$ingress_port" ] || ingress_port=443
  case "$egress_interface_v4:$egress_interface_v6" in
    :*|*:|*[!A-Za-z0-9_.:-]*) fail STATE_INVALID ;;
  esac
}

write_state() {
  install -d -o root -g root -m 0700 "$state_dir"
  temporary=$(mktemp "$state_dir/firewall-compat-v1.state.XXXXXX")
  trap 'rm -f "$temporary"' EXIT HUP INT TERM
  printf 'ingressPort=%s\negressInterfaceV4=%s\negressInterfaceV6=%s\n' "$ingress_port" "$egress_interface_v4" "$egress_interface_v6" >"$temporary"
  install -o root -g root -m 0600 "$temporary" "$state_file.new"
  mv -f "$state_file.new" "$state_file"
  trap - EXIT HUP INT TERM
  rm -f "$temporary"
}

case "$mode" in
  --check)
    check_rules || fail UFW_CHECK_FAILED
    changed=false
    ;;
  --apply)
    check_rules || fail UFW_CHECK_FAILED
    requested_ingress_port=$ingress_port
    requested_egress_interface_v4=$egress_interface_v4
    requested_egress_interface_v6=$egress_interface_v6
    if read_state; then
      remove_rules || fail UFW_REMOVE_FAILED
    fi
    ingress_port=$requested_ingress_port
    egress_interface_v4=$requested_egress_interface_v4
    egress_interface_v6=$requested_egress_interface_v6
    apply_rules || fail UFW_APPLY_FAILED
    write_state || fail STATE_WRITE_FAILED
    changed=true
    ;;
  --remove)
    if read_state; then
      remove_rules || fail UFW_REMOVE_FAILED
    fi
    rm -f "$state_file"
    changed=true
    ;;
esac

printf '{"schema":"kurd-node-firewall-compat-v1","status":"PASS","mode":"%s","ufwPresent":true,"changed":%s}\n' "${mode#--}" "$changed"
