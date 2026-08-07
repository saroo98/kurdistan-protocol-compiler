#!/bin/sh
set -eu

fail() {
  printf '{"schema":"kurd-node-preflight-v2","status":"FAIL","code":"%s"}\n' "$1" >&2
  exit 2
}

mode=${1:-}
if [ "$mode" != "--install" ] && [ "$mode" != "--runtime" ]; then
  fail INVALID_ARGUMENTS
fi
shift

port=443
requested_egress=${KURD_EGRESS_INTERFACE:-}
allow_systemd_socket=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --port)
      [ "$#" -ge 2 ] || fail INVALID_ARGUMENTS
      port=$2
      shift 2
      ;;
    --egress-interface)
      [ "$#" -ge 2 ] || fail INVALID_ARGUMENTS
      requested_egress=$2
      shift 2
      ;;
    --allow-systemd-socket)
      allow_systemd_socket=true
      shift
      ;;
    *) fail INVALID_ARGUMENTS ;;
  esac
done

case "$port" in
  ''|*[!0-9]*) fail INVALID_ARGUMENTS ;;
esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || fail INVALID_ARGUMENTS
case "$requested_egress" in
  *[!A-Za-z0-9_.:-]*) fail INVALID_ARGUMENTS ;;
esac

[ "$(uname -s)" = "Linux" ] || fail OS_UNSUPPORTED
case "$(uname -m)" in
  x86_64|aarch64|arm64) ;;
  *) fail ARCH_UNSUPPORTED ;;
esac

kernel_release=$(uname -r | sed 's/[^0-9.].*$//')
kernel_major=$(printf '%s' "$kernel_release" | cut -d. -f1)
kernel_minor=$(printf '%s' "$kernel_release" | cut -d. -f2)
case "$kernel_major:$kernel_minor" in
  *[!0-9:]*) fail KERNEL_UNSUPPORTED ;;
esac
if [ "$kernel_major" -lt 5 ] || { [ "$kernel_major" -eq 5 ] && [ "$kernel_minor" -lt 10 ]; }; then
  fail KERNEL_UNSUPPORTED
fi

for command in uname sed cut awk df sort wc tr grep id; do
  command -v "$command" >/dev/null 2>&1 || fail TOOL_MISSING
done
command -v systemctl >/dev/null 2>&1 || fail SYSTEMD_MISSING
command -v timedatectl >/dev/null 2>&1 || fail SYSTEMD_MISSING
command -v networkctl >/dev/null 2>&1 || fail NETWORKD_MISSING
systemctl cat systemd-networkd.service >/dev/null 2>&1 || fail NETWORKD_MISSING
command -v ip >/dev/null 2>&1 || fail IPROUTE_MISSING
command -v ss >/dev/null 2>&1 || fail IPROUTE_MISSING
command -v runuser >/dev/null 2>&1 || fail RUNUSER_MISSING
command -v nft >/dev/null 2>&1 || fail NFT_MISSING
command -v unbound-checkconf >/dev/null 2>&1 || fail UNBOUND_MISSING
command -v systemd-analyze >/dev/null 2>&1 || fail SYSTEMD_MISSING
command -v sysctl >/dev/null 2>&1 || fail SYSCTL_MISSING

[ -c /dev/net/tun ] || fail NO_TUN
time_synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
[ "$time_synced" = "yes" ] || fail TIME_NOT_SYNCED

memory_kib=$(awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo)
case "$memory_kib" in
  ''|*[!0-9]*) fail LOW_MEMORY ;;
esac
[ "$memory_kib" -ge 786432 ] || fail LOW_MEMORY

free_kib=$(df -Pk "${KURD_DATA_DIR:-/var/lib}" | awk 'NR == 2 { print $4 }')
case "$free_kib" in
  ''|*[!0-9]*) fail LOW_DISK ;;
esac
[ "$free_kib" -ge 524288 ] || fail LOW_DISK

ipv4_interfaces=$(ip -o -4 route show default | awk '{ for (i=1; i<NF; i++) if ($i == "dev") print $(i+1) }' | sort -u)
[ -n "$ipv4_interfaces" ] || fail NO_IPV4_ROUTE
ipv6_interfaces=$(ip -o -6 route show default | awk '{ for (i=1; i<NF; i++) if ($i == "dev") print $(i+1) }' | sort -u)
[ -n "$ipv6_interfaces" ] || fail NO_IPV6_ROUTE
[ "$(printf '%s\n' "$ipv4_interfaces" | wc -l | tr -d ' ')" -eq 1 ] || fail MULTIPLE_EGRESS
[ "$(printf '%s\n' "$ipv6_interfaces" | wc -l | tr -d ' ')" -eq 1 ] || fail MULTIPLE_EGRESS
egress_interface=$ipv4_interfaces
[ "$ipv6_interfaces" = "$egress_interface" ] || fail MULTIPLE_EGRESS
if [ -n "$requested_egress" ] && [ "$requested_egress" != "$egress_interface" ]; then
  fail EGRESS_MISMATCH
fi

if ss -H -ltn "sport = :$port" | grep -q .; then
  if [ "$allow_systemd_socket" != true ] || ! systemctl is-active --quiet kurd-node.socket; then
    fail PORT_CONFLICT
  fi
fi

if [ "$mode" = "--runtime" ]; then
  system_state=$(systemctl is-system-running 2>/dev/null || true)
  case "$system_state" in
    running|degraded) ;;
    *) fail SYSTEMD_UNAVAILABLE ;;
  esac
fi

printf '{"schema":"kurd-node-preflight-v2","status":"PASS","code":"OK","mode":"%s","egressInterface":"%s","ipv4":true,"ipv6":true}\n' "${mode#--}" "$egress_interface"
