<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0036: Continuous Health Monitoring And Failover

Milestone 30 adds deterministic active-path health monitoring for the adaptive runtime model.

The goal is to evaluate local synthetic evidence after a path has been selected: progress events, stalls, reset bursts, blackhole-like failures, relay burn risk, confidence expiry, flapping, reconnect loops, and fallback exhaustion. The model is local and synthetic. It does not run network probes or contact external targets.

## Model

`internal/pathhealth` defines:

- active path identity and state
- health events and transition timelines
- degradation detection
- score decay and confidence expiry
- failover decisions
- relay burn quarantine
- payload-free fixture summaries

Health scenarios include stable paths, no-progress recovery, stall failover, reset bursts, blackhole-like failure, relay burn quarantine, reconnect loops, flapping, all-alternates-fail, and high-risk or experimental failover controls.

## Audit Gates

`kcheck pathhealth --quick` and the default quick audit include gates for:

- active monitor execution
- degradation detection
- score decay
- failover decision behavior
- relay burn quarantine
- control detection
- generated backend parity
- trace hygiene
- mutant detection
- fixture drift

## Fixtures

Committed fixtures under `testdata/pathhealth/` freeze the scenario set, event timelines, degradation reports, failover decisions, controls, and parity metadata.

## Commands

```bash
go run ./cmd/kcheck pathhealth --quick
go run ./cmd/kcheck pathhealth --full --out testdata/audit/pathhealth.json
go run ./cmd/kcheck pathhealth verify
```

## Limitations

This milestone models health and failover decisions inside deterministic synthetic scenarios only. It is not a live health checker, public-network probe, carrier implementation, or production failover system.
