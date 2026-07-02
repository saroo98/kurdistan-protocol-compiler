<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0053: Carrier Collapse and Mutation Audit

Milestone 47 adds a cross-carrier hardening audit for the reviewed carrier families and the multi-carrier runtime selector. It does not introduce a new carrier family or public-network behavior. The purpose is to prove that the existing lab carrier path does not collapse into one fixed shape, one fixed selection policy, padding-only variation, unsafe fallback, review-gate bypass, trace leakage, or generated-backend drift.

## Scope

The audit composes evidence from:

- HTTPS-like carrier review, prototype, and adversarial hardening.
- Constrained carrier review and prototype evidence.
- Multi-carrier runtime selection fixtures.
- Transport bundle, pathrace, pathhealth, carrierreview, measurementreview, labegress, and localpipeline gates.
- Generated/interpreted parity checks.
- Trace hygiene and public-claim safety checks.

The audit emits safe metadata only: carrier-family buckets, shape-class buckets, profile hashes, selection fingerprints, gate conclusions, mutation-control names, and stable fixture hashes.

## Collapse Classes

The scanner records these collapse classes:

- `single_carrier_collapse`
- `single_shape_collapse`
- `padding_only_variation`
- `profile_insensitive_output`
- `bundle_insensitive_output`
- `pathhealth_ignored`
- `pathrace_ignored`
- `measurementreview_bypassed`
- `carrierreview_bypassed`
- `unsafe_fallback_enabled`
- `high_risk_default_enabled`
- `fixed_error_behavior`
- `reset_swallowed`
- `backpressure_hidden`
- `stream_isolation_broken`
- `generated_backend_drift`

Each class is represented in the committed fixture set and in the mutation coverage report.

## Mutation Controls

Milestone 47 adds carrier-collapse mutant controls for fixed carrier defaults, fixed shape defaults, padding-only variation, profile-insensitive output, bundle-insensitive output, pathrace/pathhealth bypass, measurementreview/carrierreview/labegress bypass, unsafe fallback, high-risk default selection, payload and secret leakage, generated backend drift, and trace-hygiene bypass.

The mutant controls are gate-level checks. They do not create live traffic, public carrier behavior, payload forwarding, packet capture, or endpoint probing.

## Fixtures

Fixtures live under:

```text
testdata/carriercollapse/
```

The primary fixture is:

```text
carriercollapse-report-golden.json
```

Companion reports separate carrier-family diversity, shape diversity, profile sensitivity, bundle sensitivity, selection collapse, fallback safety, review enforcement, stream/backpressure/reset behavior, generated parity, trace hygiene, mutation coverage, and public-claim safety.

Fixtures must not contain raw payloads, raw bytes, endpoint data, SNI values, Host header values, DNS queries, resolver addresses, keys, nonces, auth tags, proof material, packet captures, or public-network targets.

## Gates

The audit adds these gates:

```text
carriercollapse_family_diversity
carriercollapse_shape_diversity
carriercollapse_profile_sensitivity
carriercollapse_bundle_sensitivity
carriercollapse_pathrace_enforcement
carriercollapse_pathhealth_enforcement
carriercollapse_measurementreview_enforcement
carriercollapse_carrierreview_enforcement
carriercollapse_labegress_enforcement
carriercollapse_fallback_safety
carriercollapse_runtime_security_metadata
carriercollapse_stream_isolation
carriercollapse_backpressure_visibility
carriercollapse_reset_propagation
carriercollapse_generated_backend_parity
carriercollapse_trace_hygiene
carriercollapse_public_claim_safety
carriercollapse_mutant_detection
carriercollapse_fixture_drift
```

## Commands

```bash
go run ./cmd/kcheck carriercollapse --quick
go run ./cmd/kcheck carriercollapse --full --out testdata/audit/carriercollapse.json
go run ./cmd/kcheck carriercollapse generate --out testdata/carriercollapse/carriercollapse-report-golden.json --force
go run ./cmd/kcheck carriercollapse verify
go run ./cmd/kcheck carriercollapse compare --old testdata/carriercollapse/carriercollapse-report-golden.json --new testdata/carriercollapse/carriercollapse-report-golden.json
```

The full audit output under `testdata/audit/` is an ignored local artifact.

## Generated Backend Parity

Generated modules include carrier-collapse constants and tests. The generated source scanner verifies profile-specific carrier-collapse files, parity tests, and hygiene tests. The generated backend version for this milestone is `0.47.0-lab`.

## Limitations

M47 is an audit milestone. It does not prove field readiness and does not add real HTTPS, real DNS, public-network carrier routing, public resolver use, arbitrary target forwarding, deployment automation, Android behavior, payload logging, or packet capture.

## Next Milestone

M48 should review payload-bearing local proxy adapter behavior before any local proxy adapter implementation is allowed.
