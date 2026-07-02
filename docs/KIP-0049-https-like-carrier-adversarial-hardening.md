<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0049: HTTPS-Like Carrier Adversarial Hardening

Milestone 43 hardens the M42 HTTPS-like carrier prototype with deterministic adversarial gates. It does not add a new carrier family. It attacks the lab prototype for fixed-shape collapse, profile-insensitive output, padding-only variation, unsafe fallback, trace leakage, replay/control-marker weaknesses, stream isolation failures, backpressure/reset regressions, integration bypass, public-claim overstatement, and generated-backend drift.

## Background

M42 implemented a bounded lab carrier shape. It maps internal stream events into symbolic request/response-shaped carrier markers, records carrier session and stream lifecycle summaries, models backpressure/reset/error behavior, and verifies relay/localpipeline/pathhealth/measurementreview integration through safe fixture metadata.

M43 treats that prototype as an attack surface. The goal is to prove that regressions become visible and gateable before adding another carrier family.

## Collapse Risks

The adversary package checks:

- fixed carrier shape
- fixed request-shape sequence
- fixed response-shape sequence
- identical request/response shape pairs
- profile-insensitive carrier output
- accepted profiles with non-collapsed shape sets

Padding-only variation is rejected separately because changing only marker sizes is not meaningful carrier diversity.

## Unsafe Fallback Risks

The scanner and fixtures include controls for:

- public network fallback
- arbitrary egress fallback
- real TLS fallback
- real HTTPS-client fallback
- SNI/Host/domain fallback
- payload forwarding fallback
- measurement upload fallback

All of these controls must be rejected. The repository still uses symbolic lab metadata only.

## Trace Hygiene Risks

M43 scans M42 fixtures, M43 fixtures, generated outputs, audit JSON, docs, and status text for unsafe material. The fixtures store safe buckets and hashes, not raw payload bodies, raw bytes, endpoint data, resolver data, account/device/location identifiers, keys, nonces, auth tags, proof material, or secrets.

## Replay And Control Markers

M43 does not change production cryptography. It adds symbolic controls for:

- duplicate carrier markers
- replayed session markers
- replayed stream markers
- stale reset markers
- duplicated backpressure markers

The report requires all of these to be rejected as unsafe control states.

## Stream, Backpressure, Reset, And Error Cases

The adversarial fixtures cover:

- cross-stream reset controls
- cross-stream backpressure controls
- cross-stream error propagation controls
- shape contamination controls
- ignored backpressure controls
- unbounded queue controls
- hidden pressure controls
- reset-swallowed controls
- session-reset misclassification controls
- raw error string controls

These are safe metadata scenarios. They do not forward payloads to external targets.

## Integration Bypass

M43 requires the HTTPS-like carrier to remain bound to the verified architecture. The bypass controls cover M41 contract checks, carrierreadiness, carrierreview, measurementreview, labegress, loopbackrelay, localpipeline, relaybridge, pathhealth, and pathrace.

## Generated Backend Parity

Generated modules include:

```text
protocol/httpscarrieradversary_generated.go
protocol/httpscarrieradversary_test.go
protocol/httpscarrieradversary_parity_test.go
protocol/httpscarrieradversary_hygiene_test.go
```

Generated constants specialize the adversary schema version, profile ID, seed, runtime policy, collapse controls, unsafe fallback controls, replay controls, stream/backpressure/reset controls, forbidden behavior controls, and backend version.

## Commands

```bash
go run ./cmd/kcheck httpscarrieradversary --quick
go run ./cmd/kcheck httpscarrieradversary --full --out testdata/audit/httpscarrieradversary.json
go run ./cmd/kcheck httpscarrieradversary generate --out testdata/httpscarrieradversary/httpscarrieradversary-report-golden.json --force
go run ./cmd/kcheck httpscarrieradversary verify
go run ./cmd/kcheck httpscarrieradversary compare --old testdata/httpscarrieradversary/httpscarrieradversary-report-golden.json --new testdata/httpscarrieradversary/httpscarrieradversary-report-golden.json
```

`testdata/audit/httpscarrieradversary.json` is an ignored audit artifact.

## Audit Gates

M43 adds gates for:

- `httpscarrieradversary_collapse_detection`
- `httpscarrieradversary_profile_sensitivity`
- `httpscarrieradversary_padding_only_rejection`
- `httpscarrieradversary_unsafe_fallback_detection`
- `httpscarrieradversary_trace_hygiene`
- `httpscarrieradversary_replay_controls`
- `httpscarrieradversary_stream_isolation`
- `httpscarrieradversary_backpressure`
- `httpscarrieradversary_reset_error`
- `httpscarrieradversary_integration_bypass`
- `httpscarrieradversary_public_claim_safety`
- `httpscarrieradversary_generated_backend_parity`
- `httpscarrieradversary_mutant_detection`
- `httpscarrieradversary_fixture_drift`

## Mutants And Controls

The mutant registry includes controls for fixed shapes, padding-only variation, profile-insensitive behavior, generated profile ignored behavior, unsafe fallback categories, raw fixture leakage, payload/secret leakage, replay marker acceptance, cross-stream reset, ignored backpressure, swallowed reset, pipeline bypass, generated drift, and public claim overstatement.

## Known Limitations

M43 proves deterministic adversarial coverage for the M42 lab carrier prototype. It does not prove deployability, real-world censorship resistance, production readiness, Android readiness, or public-network behavior.

## Next Milestone

M44 is the DNS-survival / constrained-carrier design lock. M45 should implement the constrained-carrier lab prototype against that contract before any real carrier, resolver, public-network, or deployment behavior is considered.
