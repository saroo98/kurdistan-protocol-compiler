<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 13 evidence index

Status: local implementation validation complete; release remains no-go

## Required local evidence

| Area | Evidence |
| --- | --- |
| Product model | Unit tests for validation, defaults, serialization, migration, and unsafe-value rejection |
| Android runtime | Unit tests for routing, DNS, per-app policy, lifecycle, and fail-closed configuration |
| User interface | Compose tests covering every destination, primary action, state, dialog, and recovery branch |
| Accessibility | API 36 automated accessibility checks plus pseudo-English, pseudo-RTL, 200 percent text, landscape, and tablet-size scenarios |
| Privacy | Manifest, bytecode, log, diagnostic, storage, clipboard, and export canary scans |
| Integration | Exact device manifest on API 26, API 34, and API 36 x86_64 emulators covering profile import, connect/stop, authority failures, policy application, diagnostics, backup/restore, reset, pseudo-locales, accessibility where supported, and adaptive layouts |
| Regression | `go run ./cmd/gate`, `android/gradlew phase13Gate`, and `go run ./cmd/gate -android` |

Machine-readable acceptance status will live at
`testdata/evidence/phase13/acceptance-status.json` and must distinguish local
passes from successor-phase external evidence.

## Retained local results

- `android/gradlew phase13Gate --dependency-verification=strict --no-configuration-cache --no-daemon --no-build-cache --rerun-tasks` passed all 1,078 executed tasks on 2026-08-01.
- `android/gradlew phase13DeviceGate --dependency-verification=strict --no-configuration-cache --no-daemon --no-build-cache --rerun-tasks` passed the exact manifest on API 26, API 34, and API 36 x86_64 emulators. API 26 passed all 25 applicable cases; API 34 and API 36 passed all 26. Every retained post-run application-crash buffer is empty.
- The same device gate first rejected a foreground-service startup-ordering crash on malformed authority input. The service now enters the foreground before parsing or rejecting the bounded authority request, and the clean rerun protects that regression.
- Scoped reset is exercised for settings, profiles/providers, routing, diagnostics, and everything. Scope selection, destructive confirmation, and the retained full-reset recovery path are covered by the exact device manifest.
- `go run ./cmd/phase13verify -root .` and the focused verifier tests pass.
- The deliberate Phase 13 evidence overlay includes the API 26 shutdown and API 34 foreground-service race repairs with exact historical predecessors.
- `go run ./cmd/gate`, the clean 1,078-task `phase13Gate`, and `go run ./cmd/gate -android` pass after those repairs.

## External evidence

Production authority, provider, relay, operator identity, signing,
distribution, physical-device/OEM fleet, hostile-network, and controlled-field
results remain **[UNVERIFIED]**.
Local or emulator evidence cannot convert these entries into passes.
`ROADMAP.md` assigns their implementation and observation to Phases 16-22.
