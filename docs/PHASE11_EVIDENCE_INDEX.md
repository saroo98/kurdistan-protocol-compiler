<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 11 evidence index

Phase 11 adds a bounded Kurd-over-TLS/TCP loopback conformance path. It does not
establish a public relay, production trust authority, general Internet
forwarding, or censorship-resilience evidence.

## Reproducible local evidence

| Boundary | Command | Evidence |
|---|---|---|
| Complete Go repository | `go run ./cmd/gate` | Build, vet, uncached tests, and full audit |
| Phase 11 race-sensitive Go packages | `go test -race -count=1` over the Phase 11 product, protocol, crypto, carrier, runtime, harness, and bridge packages | Race detector result |
| Android host boundary | `go run ./cmd/gate -android` | Go gate plus `phase11Gate`, release/internal APK build, lint, unit tests, native and manifest inspection |
| Android emulator/device boundary | `android/gradlew phase11DeviceGate --no-build-cache` | Install, clean launch, 15-test instrumentation floor, every exposed Compose control callback, crash-buffer inspection, and raw evidence under `.tools/phase11/device-gate/latest/` |
| Canonical wire | `go test -count=1 ./internal/protocol/wirev1` | Canonical vector and malformed corpus |
| Process-separated Kurd session | `go test -count=1 ./internal/runtime -run 'ProcessSeparated|RelaySubprocess|ProcessRecord'` and `go test -count=1 ./internal/product/sessionplan -run Fallback` | Independent client/relay handshake and record state, subprocess relay, delivery commit, replay rejection, and bounded fallback |

The machine-readable status is
`testdata/evidence/phase11/acceptance-status.json`. The verification tests reject
any Phase 11 record that converts an unobserved external result into a pass or
claims production readiness.

## Evidence boundaries

- The internal Android variant contains deterministic nonproduction authority
  and test certificates. The release variant must not contain either.
- The release bridge exposes the bounded ABI but fails closed with trust
  unavailable until production authority provisioning is implemented.
- Emulator evidence covers Android lifecycle, UI controls, import and protected
  storage, the reserved TUN/DNS range, Kurd loopback record transit, per-app
  exclusion, cancellation, shutdown, and crash detection.
- Device compatibility evidence is allow-listed to SDK level, supported ABIs,
  and security-patch level. The gate does not capture serial numbers, complete
  system properties, Android IDs, or hardware identifiers.
- Owned-LAN, owned-relay, physical-device matrix, mobile handover, capacity, and
  censorship-resilience results remain **[UNVERIFIED]**.

No local result in this index supports the words uncensorable, undetectable,
anonymous, production-ready, publicly deployable, or fully audited.
