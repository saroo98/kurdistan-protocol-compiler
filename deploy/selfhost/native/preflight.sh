#!/bin/sh
set -eu

mode=${1:-}
if [ "$mode" != "--install" ] && [ "$mode" != "--runtime" ]; then
  echo "usage: preflight.sh <--install|--runtime>" >&2
  exit 2
fi
if [ "$(uname -s)" != "Linux" ]; then
  echo "unsupported operating system" >&2
  exit 2
fi
case "$(uname -m)" in
  x86_64|aarch64|arm64) ;;
  *) echo "unsupported architecture" >&2; exit 2 ;;
esac
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required" >&2; exit 2; }
command -v ss >/dev/null 2>&1 || { echo "iproute2 ss is required" >&2; exit 2; }
command -v runuser >/dev/null 2>&1 || { echo "util-linux runuser is required" >&2; exit 2; }

memory_kib=$(awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo)
if [ -z "$memory_kib" ] || [ "$memory_kib" -lt 524288 ]; then
  echo "at least 512 MiB RAM is required" >&2
  exit 2
fi
free_kib=$(df -Pk "${KURD_DATA_DIR:-/var/lib}" | awk 'NR == 2 { print $4 }')
if [ -z "$free_kib" ] || [ "$free_kib" -lt 262144 ]; then
  echo "at least 256 MiB free storage is required" >&2
  exit 2
fi
if [ ! -r /proc/sys/kernel/random/entropy_avail ]; then
  echo "kernel entropy status is unavailable" >&2
  exit 2
fi
entropy=$(cat /proc/sys/kernel/random/entropy_avail)
if [ "$entropy" -lt 128 ]; then
  echo "kernel entropy is not ready" >&2
  exit 2
fi
epoch=$(date -u +%s)
if [ "$epoch" -lt 1704067200 ]; then
  echo "system clock is earlier than 2024-01-01 UTC" >&2
  exit 2
fi
if [ "$mode" = "--runtime" ] && ! systemctl is-system-running --quiet && ! systemctl is-system-running | grep -Eq '^(running|degraded)$'; then
  echo "systemd is not operational" >&2
  exit 2
fi

echo "preflight passed: linux, supported architecture, systemd, memory, storage, entropy, and clock floor"
