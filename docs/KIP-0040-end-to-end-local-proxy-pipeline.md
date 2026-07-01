<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0040: End-To-End Local Proxy Pipeline

Milestone 34 connects the deterministic local proxy ingress, proxy egress, relay bridge, runtime, byte transport, and adaptive path evidence into one payload-free local pipeline model.

This is still a synthetic local model. It does not add a socket listener, outbound dialer, real relay, DNS resolver, packet capture, deployment behavior, concrete proxy adapter, VPN adapter, HTTP carrier, TLS mimicry, WebSocket carrier, CDN behavior, or live-network testing.

## Purpose

Earlier milestones validated each boundary separately. The local pipeline model checks that those boundaries compose without losing isolation, backpressure, reset/error propagation, descriptor rejection, generated-backend parity, or trace hygiene.

The model answers:

- can ingress requests bind to egress descriptors safely?
- can bridge sessions and streams preserve synthetic target behavior?
- can byte transport summaries stay bounded and deterministic?
- can adaptive path prerequisites remain attached to pipeline summaries?
- can generated and interpreted backends agree on safe pipeline metadata?
- can collapsed or leak-like controls be detected?

## Pipeline Model

`internal/localpipeline` defines deterministic local pipeline scenarios, runs, fixture manifests, boundary reports, misuse reports, parity reports, collapse reports, and fixture comparison helpers.

Each scenario includes safe metadata for:

- ingress class
- egress class
- bridge class
- byte transport class
- adaptive path class
- synthetic target class
- expected runtime stream count
- expected byte bucket
- backpressure, reset, error, descriptor rejection, and failover expectations

## Scenarios

Committed fixtures cover:

- `pipeline_single_flow_echo`
- `pipeline_many_small_requests`
- `pipeline_large_backpressure`
- `pipeline_slow_chunked_response`
- `pipeline_reset_isolation`
- `pipeline_target_error_isolation`
- `pipeline_bridge_backpressure`
- `pipeline_path_failover`
- `pipeline_descriptor_rejection`
- `pipeline_mixed_synthetic_targets`
- `pipeline_collapsed_control`
- `pipeline_leak_control`

The final two are controls used by misuse and collapse detection. They are expected to fail or warn inside the model, not to represent valid production behavior.

## Audit Gates

M34 adds these gates:

- `localpipeline_correctness`
- `localpipeline_boundary_integration`
- `localpipeline_backpressure`
- `localpipeline_error_reset_isolation`
- `localpipeline_descriptor_rejection`
- `localpipeline_trace_hygiene`
- `localpipeline_collapse_resistance`
- `localpipeline_generated_backend_parity`
- `localpipeline_mutant_detection`
- `localpipeline_fixture_drift`

The default quick audit includes these gates.

## Commands

```bash
go run ./cmd/kcheck localpipeline --quick
go run ./cmd/kcheck localpipeline --full --out testdata/audit/localpipeline.json
go run ./cmd/kcheck localpipeline generate --out testdata/localpipeline/localpipeline-golden.json --force
go run ./cmd/kcheck localpipeline verify
go run ./cmd/kcheck localpipeline compare --old testdata/localpipeline/localpipeline-golden.json --new testdata/localpipeline/localpipeline-golden.json
```

## Fixtures

Committed fixtures live under:

- `testdata/localpipeline/localpipeline-golden.json`
- `testdata/localpipeline/localpipeline-scenarios-golden.json`
- `testdata/localpipeline/localpipeline-runs-golden.json`
- `testdata/localpipeline/localpipeline-boundary.json`
- `testdata/localpipeline/localpipeline-collapse.json`
- `testdata/localpipeline/localpipeline-misuse-report.json`
- `testdata/localpipeline/localpipeline-parity.json`

They contain scenario names, counts, state paths, hashes, and safe summary metadata only.

## Generated Backend Parity

`kgen` emits:

- `protocol/localpipeline_generated.go`
- `protocol/localpipeline_test.go`
- `protocol/localpipeline_parity_test.go`
- `protocol/localpipeline_hygiene_test.go`

The generated source includes profile-specific local-pipeline constants and deterministic fixture/parity accessors. `kcheck codegen --quick` checks the generated local-pipeline markers and tests.

## Limitations

The local pipeline is an integration model and fixture layer. It does not implement a concrete local socket adapter, public proxy listener, real relay dialer, real DNS/HTTP/TLS/WebSocket carrier, VPN device, mobile client, deployment pipeline, or field measurement path.

## Next Milestone

The recommended next milestone is M35: production integration readiness review. That review should turn the accumulated local pipeline evidence into a structured readiness inventory before any concrete adapter is introduced.
