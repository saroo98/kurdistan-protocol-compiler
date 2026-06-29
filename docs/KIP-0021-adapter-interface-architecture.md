<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0021: Adapter Interface Architecture

Milestone 15 defines the adapter boundary that future local ingress and byte-transport implementations can use. It is an interface, contract, validation, deterministic harness, and audit milestone.

It does not add concrete SOCKS, TUN, VPN, HTTP, TLS, WebSocket, CDN, deployment, or external-network adapters.

## Purpose

The adapter layer separates local flow lifecycle from the existing runtime, stream, proxy-semantics, carrier, and security layers. The goal is to make future adapter integration misuse-resistant before any concrete adapter is written.

Conceptual path:

```text
local source
  -> adapter ingress interface
  -> flow lifecycle model
  -> runtime session manager
  -> stream/proxysem/carrier/security layers
  -> adapter egress interface
  -> trace-safe adapter summary
```

## Adapter Kinds

The internal model defines three kinds:

- `ingress`
- `egress`
- `carrier`

Milestone 15 implements deterministic in-memory contracts for these shapes. Concrete external adapters are future work.

## Contracts

The package `internal/adapter` defines:

- adapter config validation
- ingress and egress interfaces
- flow descriptors
- adapter chunks with byte counts only
- canonical capability ordering and hashing
- bounded harness summaries
- safe trace metadata

No adapter chunk stores payload contents.

## Flow Lifecycle

Valid path:

```text
new -> opening -> open -> half_closed/draining -> closed
```

Terminal failure paths:

```text
new/opening/open/half_closed/draining -> reset
new/opening/open/half_closed/draining -> failed
```

Invalid transitions are rejected. Repeated close/reset is idempotent after terminal state. Writes after close, reset, or failure are rejected.

## Config Validation

Adapter config validation checks:

- non-empty adapter name
- supported adapter kind
- non-empty runtime ID
- bounded flow, byte, buffer, and event limits
- known capability names
- duplicate capability rejection
- secret-like value rejection or redaction

Error strings avoid echoing secret-like values.

## Capability Model

Adapter capabilities are canonicalized and hashed. Required capabilities include ingress/egress contracts, flow lifecycle, reset, half-close, backpressure, priority, metadata-only summaries, runtime stream mapping, and trace-safe summaries.

Runtime compatibility rejects missing capabilities and downgrades.

## Deterministic Harness

The in-memory harness models:

- flow open/close/reset
- bounded reads/writes
- backpressure
- flow-to-runtime stream mapping
- runtime stream-to-flow mapping
- payload-free summaries

It is a contract test harness, not a real adapter.

## Runtime Boundary

`internal/runtime/adapter_boundary.go` maps adapter flow descriptors into runtime streams and proxy-semantics relay intent metadata. It propagates:

- flow close to stream close
- stream reset to adapter reset
- target error to adapter-safe error metadata
- target reset to adapter reset metadata
- runtime/carrier backpressure to adapter backpressure counters

## Trace Model

Adapter traces include only safe metadata:

- adapter kind
- flow state
- flow event
- flow count bucket
- chunk count bucket
- byte count bucket
- reset/close/backpressure counts
- runtime stream mapping result
- scenario name
- payload/secret hygiene flags

They do not include raw payloads, raw packet contents, raw destinations, keys, nonces, auth tags, proof material, or secrets.

## Adapter Adversary Scenarios

`internal/adapteradversary` provides deterministic scenarios:

- `single_flow_happy_path`
- `many_small_flows`
- `large_flow_backpressure`
- `flow_reset_isolation`
- `target_error_to_flow_error`
- `target_reset_to_flow_reset`
- `half_close_behavior`
- `adapter_capability_downgrade`
- `malformed_flow_descriptor`
- `adapter_queue_pressure`

## Collapse Scanner

The adapter collapse scanner extracts payload-free features from scenario summaries and flags suspicious stability such as fixed flow-to-stream mapping shape, fixed backpressure pattern, and padding-only variation.

## Mutants

Milestone 15 adds test-only adapter mutants:

- `adapter_accepts_invalid_flow`
- `adapter_ignores_backpressure`
- `adapter_leaks_payload_trace`
- `adapter_leaks_secret_trace`
- `adapter_accepts_capability_downgrade`
- `adapter_ignores_max_flows`
- `adapter_wrong_reset_mapping`
- `adapter_padding_only_diversity`

Audit gates must detect these regressions.

## Audit Gates

`kcheck adapter` reports:

- `adapter_interface_contracts`
- `adapter_config_validation`
- `adapter_flow_lifecycle`
- `adapter_runtime_boundary`
- `adapter_capability_compatibility`
- `adapter_backpressure`
- `adapter_error_reset_mapping`
- `adapter_trace_hygiene`
- `adapter_collapse_resistance`
- `adapter_mutant_detection`
- `adapter_generated_backend_parity`

## Commands

```bash
go run ./cmd/kcheck adapter --quick
go run ./cmd/kcheck adapter --full --out testdata/audit/adapter.json
go run ./cmd/kcheck codegen --quick
```

Generated modules include:

```text
protocol/adapter_generated.go
protocol/adapter_test.go
protocol/adapteradversary_test.go
```

## Limitations

This milestone proves interface behavior under deterministic local tests. It does not prove production adapter safety, traffic-analysis resistance, live-network behavior, censorship resistance, or deployment readiness. Concrete adapters require separate design, threat modeling, review, and negative tests.

## Next Milestone

Milestone 16 should build a deterministic local adapter prototype using this contract while keeping hardening, trace hygiene, and generated-backend parity mandatory.
