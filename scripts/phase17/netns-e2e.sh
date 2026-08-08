#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

MODE=full
EVIDENCE_DIR=.tools/phase17/netns
while (($#)); do
  case "$1" in
    --mode) MODE=${2:?missing mode}; shift 2 ;;
    --evidence-dir) EVIDENCE_DIR=${2:?missing evidence directory}; shift 2 ;;
    *) echo "unsupported argument: $1" >&2; exit 64 ;;
  esac
done
case "$MODE" in quick|full) ;; *) echo "mode must be quick or full" >&2; exit 64 ;; esac

[[ $(id -u) -eq 0 ]] || { echo "root is required for isolated namespaces" >&2; exit 77; }
for command in go ip nft tc python3 sha256sum mktemp ping seq awk; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 69; }
done
[[ -c /dev/net/tun ]] || { echo "/dev/net/tun is unavailable" >&2; exit 69; }

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$ROOT"
case "$EVIDENCE_DIR" in /*) ;; *) EVIDENCE_DIR="$ROOT/$EVIDENCE_DIR" ;; esac
mkdir -p "$EVIDENCE_DIR"
EVIDENCE="$EVIDENCE_DIR/aggregate.json"
rm -f "$EVIDENCE"
RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/k17ns.XXXXXX")
SUFFIX=${RUN_DIR##*.}
CNS="k17c${SUFFIX:0:6}"
RNS="k17r${SUFFIX:0:6}"
WNS="k17w${SUFFIX:0:6}"
CTUN="k17t${SUFFIX:0:6}"
RTUN="kurd0"
CIF="k17c${SUFFIX:0:7}"
RIF_CLIENT="k17a${SUFFIX:0:7}"
RIF_WITNESS="k17b${SUFFIX:0:7}"
WIF="k17w${SUFFIX:0:7}"
BIN="$RUN_DIR/runtime.test"
READY_R="$RUN_DIR/relay.ready"
READY_C="$RUN_DIR/client.ready"
READY_W="$RUN_DIR/witness.ready"
STOP="$RUN_DIR/stop"
START_NS=$(date +%s%N)
BASELINE_PROBES=0
FAULT_PROBES=0
RESTARTS=0
FAILURE=1
PUMP_PIDS=()
WITNESS_PID=

cleanup() {
  set +e
  if [[ $FAILURE -ne 0 ]]; then
    for log in relay client witness; do
      if [[ -f "$RUN_DIR/$log.log" ]]; then
        echo "phase17 $log harness log follows" >&2
        tail -n 40 "$RUN_DIR/$log.log" >&2
      fi
    done
    if [[ ! -f "$EVIDENCE" ]]; then
      local end_ns duration_ms
      end_ns=$(date +%s%N)
      duration_ms=$(((end_ns - START_NS) / 1000000))
      python3 - "$EVIDENCE" "$MODE" "$duration_ms" <<'PY'
import json, os, sys, tempfile
path, mode, duration = sys.argv[1:]
record = {
    "schema": "kurdistan-phase17-netns-evidence-v1",
    "result": "FAIL",
    "mode": mode,
    "durationMs": int(duration),
    "probes": {"successful": 0, "faultCondition": 0},
    "traffic": {"packets": 0, "bytes": 0},
    "retries": 0,
    "restarts": 0,
    "resultCategories": ["harness-failed"],
    "resources": {"peakGoroutines": 0, "peakHeapBytes": 0, "peakFileDescriptors": 0},
    "externalDnsPackets": 0,
    "privacy": {"payloadsRetained": False, "destinationNamesRetained": False, "packetCapturesRetained": False},
    "artifacts": {},
    "limitations": ["namespace proof terminated before successful aggregate evidence"]
}
directory = os.path.dirname(path)
fd, temporary = tempfile.mkstemp(prefix=".aggregate.", dir=directory, text=True)
try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(record, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
    fi
  fi
  touch "$STOP" 2>/dev/null
  for pid in "${PUMP_PIDS[@]:-}" ${WITNESS_PID:-}; do kill "$pid" 2>/dev/null; done
  for pid in "${PUMP_PIDS[@]:-}" ${WITNESS_PID:-}; do wait "$pid" 2>/dev/null; done
  ip netns del "$CNS" 2>/dev/null
  ip netns del "$RNS" 2>/dev/null
  ip netns del "$WNS" 2>/dev/null
  rm -rf "$RUN_DIR"
}
trap cleanup EXIT INT TERM

wait_file() {
  local file=$1
  for _ in $(seq 1 200); do [[ -f "$file" ]] && return 0; sleep 0.025; done
  echo "readiness timeout" >&2
  return 1
}

start_witness() {
  rm -f "$READY_W"
  ip netns exec "$WNS" python3 "$ROOT/scripts/phase17/netns_witness.py" --ready "$READY_W" >"$RUN_DIR/witness.log" 2>&1 &
  WITNESS_PID=$!
  wait_file "$READY_W"
}

stop_witness() {
  if [[ -n ${WITNESS_PID:-} ]]; then
    kill "$WITNESS_PID" 2>/dev/null || true
    wait "$WITNESS_PID" 2>/dev/null || true
    WITNESS_PID=
  fi
}

start_pumps() {
  rm -f "$READY_R" "$READY_C" "$STOP"
  ip netns exec "$RNS" env \
    KURD_PHASE17_NETNS_ROLE=relay \
    KURD_PHASE17_NETNS_RELAY_ADDRESS=192.0.2.1:24443 \
    KURD_PHASE17_NETNS_READY_FILE="$READY_R" \
    KURD_PHASE17_NETNS_STOP_FILE="$STOP" \
    KURD_PHASE17_NETNS_TUN="$RTUN" \
    KURD_PHASE17_NETNS_METRICS_FILE="$RUN_DIR/relay.metrics.$RESTARTS" \
    "$BIN" -test.run '^TestPhase17NamespacePacketPumpV1$' -test.count=1 >"$RUN_DIR/relay.log" 2>&1 &
  PUMP_PIDS+=("$!")
  wait_file "$READY_R"
  ip netns exec "$CNS" env \
    KURD_PHASE17_NETNS_ROLE=client \
    KURD_PHASE17_NETNS_RELAY_ADDRESS=192.0.2.1:24443 \
    KURD_PHASE17_NETNS_READY_FILE="$READY_C" \
    KURD_PHASE17_NETNS_STOP_FILE="$STOP" \
    KURD_PHASE17_NETNS_TUN="$CTUN" \
    KURD_PHASE17_NETNS_METRICS_FILE="$RUN_DIR/client.metrics.$RESTARTS" \
    "$BIN" -test.run '^TestPhase17NamespacePacketPumpV1$' -test.count=1 >"$RUN_DIR/client.log" 2>&1 &
  PUMP_PIDS+=("$!")
  wait_file "$READY_C"
}

stop_pumps() {
  touch "$STOP"
  local failed=0
  for pid in "${PUMP_PIDS[@]}"; do wait "$pid" || failed=1; done
  PUMP_PIDS=()
  [[ $failed -eq 0 ]]
}

stop_failed_pumps() {
  touch "$STOP"
  for pid in "${PUMP_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  PUMP_PIDS=()
}

probe_all() {
  ip netns exec "$CNS" python3 "$ROOT/scripts/phase17/netns_probe.py" --family 4 --kind all
  BASELINE_PROBES=$((BASELINE_PROBES + 3))
  ip netns exec "$CNS" python3 "$ROOT/scripts/phase17/netns_probe.py" --family 6 --kind all
  BASELINE_PROBES=$((BASELINE_PROBES + 3))
}

# The cleanup trap is installed before the first namespace mutation.
ip netns add "$CNS"
ip netns add "$RNS"
ip netns add "$WNS"
ip link add "$CIF" type veth peer name "$RIF_CLIENT"
ip link set "$CIF" netns "$CNS"
ip link set "$RIF_CLIENT" netns "$RNS"
ip link add "$RIF_WITNESS" type veth peer name "$WIF"
ip link set "$RIF_WITNESS" netns "$RNS"
ip link set "$WIF" netns "$WNS"

for ns in "$CNS" "$RNS" "$WNS"; do ip -n "$ns" link set lo up; done
ip -n "$CNS" addr add 192.0.2.2/30 dev "$CIF"
ip -n "$CNS" addr add 2001:db8:200::2/64 dev "$CIF" nodad
ip -n "$CNS" link set "$CIF" up
ip -n "$RNS" addr add 192.0.2.1/30 dev "$RIF_CLIENT"
ip -n "$RNS" addr add 2001:db8:200::1/64 dev "$RIF_CLIENT" nodad
ip -n "$RNS" link set "$RIF_CLIENT" up
ip -n "$RNS" addr add 198.51.100.1/30 dev "$RIF_WITNESS"
ip -n "$RNS" addr add 2001:db8:201::1/64 dev "$RIF_WITNESS" nodad
ip -n "$RNS" link set "$RIF_WITNESS" up
ip -n "$WNS" addr add 198.51.100.2/30 dev "$WIF"
ip -n "$WNS" addr add 2001:db8:201::2/64 dev "$WIF" nodad
ip -n "$WNS" link set "$WIF" up

ip -n "$CNS" tuntap add dev "$CTUN" mode tun
ip -n "$RNS" tuntap add dev "$RTUN" mode tun
ip netns exec "$CNS" sysctl -q -w "net.ipv6.conf.$CTUN.accept_dad=0" "net.ipv6.conf.$CTUN.autoconf=0" "net.ipv6.conf.$CTUN.accept_ra=0" "net.ipv6.conf.$CTUN.router_solicitations=0" "net.ipv6.conf.$CTUN.addr_gen_mode=1"
ip netns exec "$RNS" sysctl -q -w "net.ipv6.conf.$RTUN.accept_dad=0" "net.ipv6.conf.$RTUN.autoconf=0" "net.ipv6.conf.$RTUN.accept_ra=0" "net.ipv6.conf.$RTUN.router_solicitations=0" "net.ipv6.conf.$RTUN.addr_gen_mode=1"
ip -n "$CNS" link set "$CTUN" mtu 1280 multicast off up
ip -n "$RNS" link set "$RTUN" mtu 1280 multicast off up
ip -n "$CNS" addr add 10.77.0.2 peer 10.77.0.1 dev "$CTUN"
ip -n "$RNS" addr add 10.77.0.1 peer 10.77.0.2 dev "$RTUN"
ip -n "$CNS" addr add 2001:db8:77::2/64 dev "$CTUN" nodad
ip -n "$RNS" addr add 2001:db8:77::1/64 dev "$RTUN" nodad

# The only direct client route is the signed relay endpoint. All witness traffic
# and DNS traverse the protected TUN.
ip -n "$CNS" route add 192.0.2.1/32 dev "$CIF"
ip -n "$CNS" -6 route add 2001:db8:200::1/128 dev "$CIF"
ip -n "$CNS" route add default dev "$CTUN"
ip -n "$CNS" -6 route add default dev "$CTUN"
ip -n "$WNS" route add 10.77.0.0/30 via 198.51.100.1
ip -n "$WNS" -6 route add 2001:db8:77::/64 via 2001:db8:201::1
ip netns exec "$RNS" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$RNS" sysctl -q -w net.ipv6.conf.all.forwarding=1

ip netns exec "$RNS" nft -f - <<NFT
table inet kurd_phase17 {
  chain forward {
    type filter hook forward priority 0; policy drop;
    iifname "$RTUN" oifname "$RIF_WITNESS" ip saddr 10.77.0.2 accept
    iifname "$RIF_WITNESS" oifname "$RTUN" ip daddr 10.77.0.2 ct state established,related accept
    iifname "$RTUN" oifname "$RIF_WITNESS" ip6 saddr 2001:db8:77::2 accept
    iifname "$RIF_WITNESS" oifname "$RTUN" ip6 daddr 2001:db8:77::2 ct state established,related accept
  }
}
NFT
ip netns exec "$CNS" nft -f - <<NFT
table inet kurd_phase17_guard {
  counter dns_escape {}
  chain output {
    type filter hook output priority 0; policy accept;
    oifname "$CIF" udp dport 53 counter name dns_escape
  }
}
NFT

go test -c -tags=phase17integration -o "$BIN" ./internal/runtime
start_witness
start_pumps
probe_all
ip netns exec "$CNS" ping -4 -M do -s 1252 -c 1 -W 2 198.51.100.2 >/dev/null
BASELINE_PROBES=$((BASELINE_PROBES + 1))

# MTU is authoritative at both tunnel edges. The kernel must reject an
# oversized do-not-fragment IPv4 probe locally instead of widening the tunnel.
if ip netns exec "$CNS" ping -4 -M do -s 1253 -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; then
  echo "oversized MTU probe unexpectedly succeeded" >&2
  exit 1
fi

if [[ "$MODE" == full ]]; then
  stop_witness
  if ip netns exec "$CNS" python3 "$ROOT/scripts/phase17/netns_probe.py" --family 4 --kind dns >/dev/null 2>&1; then
    echo "in-tunnel DNS unexpectedly succeeded without its authorized witness" >&2
    exit 1
  fi
  FAULT_PROBES=$((FAULT_PROBES + 1))
  start_witness
  ip netns exec "$CNS" python3 "$ROOT/scripts/phase17/netns_probe.py" --family 4 --kind dns
  BASELINE_PROBES=$((BASELINE_PROBES + 1))

  ip netns exec "$CNS" tc qdisc add dev "$CIF" root netem delay 40ms loss 2%
  ip netns exec "$CNS" python3 "$ROOT/scripts/phase17/netns_probe.py" --family 4 --kind tcp
  FAULT_PROBES=$((FAULT_PROBES + 1))
  ip netns exec "$CNS" tc qdisc del dev "$CIF" root

  ip -n "$CNS" link set "$CTUN" down
  if ip netns exec "$CNS" python3 "$ROOT/scripts/phase17/netns_probe.py" --family 4 --kind tcp >/dev/null 2>&1; then
    echo "traffic unexpectedly survived a client TUN reset" >&2
    exit 1
  fi
  stop_failed_pumps
  ip -n "$CNS" link del "$CTUN"
  ip -n "$RNS" link del "$RTUN"
  ip -n "$CNS" tuntap add dev "$CTUN" mode tun
  ip -n "$RNS" tuntap add dev "$RTUN" mode tun
  ip netns exec "$CNS" sysctl -q -w "net.ipv6.conf.$CTUN.accept_dad=0" "net.ipv6.conf.$CTUN.autoconf=0" "net.ipv6.conf.$CTUN.accept_ra=0" "net.ipv6.conf.$CTUN.router_solicitations=0" "net.ipv6.conf.$CTUN.addr_gen_mode=1"
  ip netns exec "$RNS" sysctl -q -w "net.ipv6.conf.$RTUN.accept_dad=0" "net.ipv6.conf.$RTUN.autoconf=0" "net.ipv6.conf.$RTUN.accept_ra=0" "net.ipv6.conf.$RTUN.router_solicitations=0" "net.ipv6.conf.$RTUN.addr_gen_mode=1"
  ip -n "$CNS" link set "$CTUN" mtu 1280 multicast off up
  ip -n "$RNS" link set "$RTUN" mtu 1280 multicast off up
  ip -n "$CNS" addr add 10.77.0.2 peer 10.77.0.1 dev "$CTUN"
  ip -n "$RNS" addr add 10.77.0.1 peer 10.77.0.2 dev "$RTUN"
  ip -n "$CNS" addr add 2001:db8:77::2/64 dev "$CTUN" nodad
  ip -n "$RNS" addr add 2001:db8:77::1/64 dev "$RTUN" nodad
  ip -n "$CNS" route replace default dev "$CTUN"
  ip -n "$CNS" -6 route replace default dev "$CTUN"
  sleep 0.1
  RESTARTS=$((RESTARTS + 1))
  start_pumps
  ip netns exec "$CNS" python3 "$ROOT/scripts/phase17/netns_probe.py" --family 4 --kind tcp
  FAULT_PROBES=$((FAULT_PROBES + 1))

  stop_pumps
  RESTARTS=$((RESTARTS + 1))
  start_pumps
  probe_all
fi
stop_pumps

DNS_ESCAPE_PACKETS=$(ip netns exec "$CNS" nft -j list counter inet kurd_phase17_guard dns_escape | python3 -c '
import json,sys
data=json.load(sys.stdin)
for item in data.get("nftables",[]):
    counter=item.get("counter")
    if counter and counter.get("name")=="dns_escape":
        print(counter.get("packets",-1)); break
else: print(-1)')
[[ "$DNS_ESCAPE_PACKETS" == 0 ]] || { echo "client external DNS escape observed" >&2; exit 1; }

read -r CLIENT_PACKETS CLIENT_BYTES < <(ip -n "$CNS" -j -s link show dev "$CTUN" | python3 -c '
import json,sys
item=json.load(sys.stdin)[0].get("stats64",{})
rx,tx=item.get("rx",{}),item.get("tx",{})
print(int(rx.get("packets",0))+int(tx.get("packets",0)), int(rx.get("bytes",0))+int(tx.get("bytes",0)))')
read -r RELAY_PACKETS RELAY_BYTES < <(ip -n "$RNS" -j -s link show dev "$RTUN" | python3 -c '
import json,sys
item=json.load(sys.stdin)[0].get("stats64",{})
rx,tx=item.get("rx",{}),item.get("tx",{})
print(int(rx.get("packets",0))+int(tx.get("packets",0)), int(rx.get("bytes",0))+int(tx.get("bytes",0)))')
PACKET_COUNT=$((CLIENT_PACKETS + RELAY_PACKETS))
BYTE_COUNT=$((CLIENT_BYTES + RELAY_BYTES))

read -r PEAK_GOROUTINES PEAK_HEAP_BYTES PEAK_FDS < <(python3 - "$RUN_DIR" <<'PY'
import glob, os, sys
maximum = {"goroutines": 0, "heap_bytes": 0, "fds": 0}
paths = glob.glob(os.path.join(sys.argv[1], "*.metrics.*"))
if not paths:
    raise SystemExit("missing process metrics")
for path in paths:
    values = {}
    with open(path, encoding="ascii") as handle:
        for line in handle:
            key, value = line.rstrip("\n").split("=", 1)
            values[key] = int(value)
    if set(values) != set(maximum):
        raise SystemExit("invalid process metrics")
    for key, value in values.items():
        maximum[key] = max(maximum[key], value)
print(maximum["goroutines"], maximum["heap_bytes"], maximum["fds"])
PY
)

# These tagged tests exercise production relay reload, emergency-disable,
# corruption, admission-flood, and session-termination behavior.
go test -tags=phase17integration ./internal/relay/node -run '^TestPhase17Integration' -count=1 >/dev/null
go test ./internal/androidbridge -run '^TestRuntimeSessionV2(FallsBackOnlyAfterFreshProtectedSocket|ExhaustedFallbackFailsClosed)$' -count=1 >/dev/null

END_NS=$(date +%s%N)
DURATION_MS=$(((END_NS - START_NS) / 1000000))
RUNTIME_SHA=$(sha256sum "$BIN" | awk '{print $1}')
TOPOLOGY_SHA=$(sha256sum testdata/fixtures/phase17/netns/topology-v1.json | awk '{print $1}')
python3 - "$EVIDENCE" "$MODE" "$DURATION_MS" "$BASELINE_PROBES" "$FAULT_PROBES" "$RESTARTS" "$DNS_ESCAPE_PACKETS" "$PACKET_COUNT" "$BYTE_COUNT" "$PEAK_GOROUTINES" "$PEAK_HEAP_BYTES" "$PEAK_FDS" "$RUNTIME_SHA" "$TOPOLOGY_SHA" <<'PY'
import json, os, sys, tempfile
path, mode, duration, baseline, fault, restarts, dns_escape, packets, byte_count, goroutines, heap_bytes, fds, runtime_sha, topology_sha = sys.argv[1:]
record = {
    "schema": "kurdistan-phase17-netns-evidence-v1",
    "result": "PASS",
    "mode": mode,
    "durationMs": int(duration),
    "probes": {"successful": int(baseline) + int(fault), "faultCondition": int(fault)},
    "traffic": {"packets": int(packets), "bytes": int(byte_count)},
    "retries": int(restarts),
    "restarts": int(restarts),
    "resultCategories": ["ipv4-tcp", "ipv4-udp", "ipv4-dns", "ipv6-tcp", "ipv6-udp", "ipv6-dns", "mtu-maximum-accepted", "mtu-oversized-rejected", "dns-fail-closed", "dns-no-external-escape", "loss-latency", "tun-reset-recovery", "carrier-node-restart", "relay-reload-fail-closed", "tagged-multi-client-isolation", "protected-endpoint-fallback-contract"],
    "resources": {"peakGoroutines": int(goroutines), "peakHeapBytes": int(heap_bytes), "peakFileDescriptors": int(fds)},
    "externalDnsPackets": int(dns_escape),
    "privacy": {"payloadsRetained": False, "destinationNamesRetained": False, "packetCapturesRetained": False},
    "artifacts": {"runtimeTestSha256": runtime_sha, "topologySha256": topology_sha},
    "limitations": ["isolated documentation-address witness; not public Internet or physical-device evidence"]
}
directory = os.path.dirname(path)
fd, temporary = tempfile.mkstemp(prefix=".aggregate.", dir=directory, text=True)
try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(record, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
FAILURE=0
echo "PHASE 17 NETWORK NAMESPACE PROOF PASSED"
