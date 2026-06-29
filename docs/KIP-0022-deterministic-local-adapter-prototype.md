<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0022: Deterministic Local Adapter Prototype

Milestone 16 implements the first concrete adapter prototype on top of the adapter interface architecture. It is deterministic and in-memory, and it exists to prove that adapter flows can drive the runtime stack before any concrete network adapter is designed.

## Purpose

The local adapter prototype connects deterministic local source models to memory ingress and egress adapters, maps flows into runtime streams, exercises proxy semantics and carrier metadata, writes to a deterministic sink, and emits payload-free summaries.

Conceptual path:

```text
deterministic local source
  -> memory ingress adapter
  -> adapter flow lifecycle
  -> runtime adapter boundary
  -> runtime stream/session manager
  -> proxy semantics and carrier metadata
  -> memory egress adapter
  -> deterministic local sink
```

## Local Ingress And Egress Models

`internal/localadapter` provides:

- `MemoryIngressAdapter`
- `MemoryEgressAdapter`
- `MemoryPipeAdapter`
- bounded local adapter config validation
- safe local adapter trace events
- deterministic summaries

The adapters can carry deterministic synthetic bytes internally for correctness checks. Traces, summaries, status output, audit reports, and generated artifacts use byte counts, buckets, classes, and flags only.

## Source Models

The deterministic source models are:

- `small_burst_source`
- `large_object_source`
- `slow_drip_source`
- `mixed_flow_source`
- `resetting_source`
- `half_close_source`

The same seed produces the same plan. Different seeds can vary safe byte-count metadata where the source model allows it.

## Sink Model

The sink validates:

- sequence ordering
- duplicate chunks
- writes after close or reset
- missing terminal events where scenarios expect closure
- byte and chunk counts

The sink records only safe counters and flags.

## Runtime Integration

The runner maps local flows through the existing runtime adapter boundary. It validates profile loading, capability negotiation, runtime stream creation, target error/reset propagation, backpressure, and clean session closure.

Required scenario coverage includes:

- single-flow echo
- many small flows
- large-flow backpressure
- slow drip input
- mixed flows
- reset isolation
- target error mapping
- target reset mapping
- half-close behavior
- queue pressure
- malformed source chunk rejection

## Backpressure And Isolation

The prototype verifies that local adapter buffer pressure and runtime/carrier pressure are surfaced as safe metadata. Reset and target error scenarios are isolated to the affected flow while other flows continue.

## Local Adapter Adversary

`internal/localadapteradversary` extracts payload-free features from local adapter scenario runs:

- flow count
- source and sink chunk counts
- source and sink byte buckets
- lifecycle path
- reset and close counts
- target error/reset mapping
- backpressure and queue pressure
- runtime stream mapping
- session result
- hygiene flags
- failure reason bucket

The collapse scanner flags suspiciously fixed behavior across profiles, including identical flow-to-stream mapping, fixed backpressure patterns, fixed reset/close behavior, and padding-only diversity.

## Mutants

Milestone 16 adds test-only local adapter mutants:

- `local_adapter_ignores_source_backpressure`
- `local_adapter_accepts_post_close_write`
- `local_adapter_drops_final_chunk`
- `local_adapter_duplicates_chunk`
- `local_adapter_wrong_flow_stream_mapping`
- `local_adapter_payload_trace_leak`
- `local_adapter_secret_trace_leak`
- `local_adapter_padding_only_diversity`

Audit gates must detect these regressions.

## Audit Gates

`kcheck localadapter` reports:

- `local_adapter_correctness`
- `local_adapter_flow_lifecycle`
- `local_adapter_runtime_integration`
- `local_adapter_backpressure`
- `local_adapter_error_reset_isolation`
- `local_adapter_sequence_integrity`
- `local_adapter_trace_hygiene`
- `local_adapter_collapse_resistance`
- `local_adapter_mutant_detection`
- `local_adapter_generated_backend_parity`

## Generated Backend Parity

Generated modules include:

```text
protocol/localadapter_generated.go
protocol/localadapter_test.go
protocol/localadapteradversary_test.go
```

Generated code specializes local adapter constants, source model defaults, sink behavior, max-flow and max-buffer limits, runtime mapping policy, backpressure policy, trace hygiene flags, and generated backend version `0.16.0-lab`.

## Commands

```bash
go run ./cmd/kcheck localadapter --quick
go run ./cmd/kcheck localadapter --full --out testdata/audit/localadapter.json
go run ./cmd/kcheck codegen --quick
go run ./cmd/generated-client --localadapter-demo --flows 4
```

## Limitations

The prototype is deterministic and in-memory. It does not implement sockets, packet capture, SOCKS, TUN, VPN, HTTP, TLS, WebSocket, CDN behavior, deployment behavior, or external network targets. It proves that the adapter boundary is usable under controlled local tests; it does not prove production adapter readiness.

## Next Milestone

Milestone 17 should add a deterministic byte transport harness that moves encoded byte frames through a bounded local byte pipe and reconstructs receiver-side semantic events.
