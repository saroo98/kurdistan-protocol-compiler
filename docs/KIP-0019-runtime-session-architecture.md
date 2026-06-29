<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0019: Runtime Session Architecture

## Summary

Milestone 13 adds an internal runtime session architecture for Kurdistan. The runtime layer sits above generated profiles, security prerequisites, carrier abstraction, proxy semantics, and multi-stream semantics. It models how a local client and server runtime would load a profile, negotiate capabilities, verify compatibility, establish a session, exchange secure envelopes, manage logical streams, and emit safe trace metadata.

This milestone does not add production adapters or live network transports. It provides a deterministic architecture and audit surface for future implementation hardening.

Implementation hardening is covered next in [KIP-0020](KIP-0020-implementation-hardening.md), including invariant checks, panic-safety wrappers, resource bounds, trace hygiene, and pre-adapter readiness.

## Runtime Layer

The runtime package defines:

- client and server roles
- runtime config validation and redaction
- profile loading and profile ID checks
- session lifecycle transitions
- capability negotiation
- profile compatibility checks
- security context creation
- in-memory link delivery
- secure channel setup
- stream manager integration
- runtime trace metadata

The intended local stack is:

```text
scenario runner
        |
        v
runtime session manager
        |
        v
secure channel and in-memory link
        |
        v
carrier / proxysem / stream semantics
        |
        v
payload-free trace and audit
```

## Session Lifecycle

Runtime sessions move through a small explicit lifecycle:

- `new`
- `negotiating`
- `securing`
- `open`
- `draining`
- `closed`
- `failed`

Invalid transitions are rejected. Close and failure reasons are represented as bucketed trace metadata.

## Capability Negotiation

Client and server runtime configs declare required features. Negotiation selects the intersection of peer capabilities and rejects removed required capabilities as downgrade attempts.

Runtime adversary scenarios include a capability downgrade attempt to prove that the runtime gate fails if downgrade acceptance is introduced.

## Profile Compatibility

The runtime checks profile identity and generation hash before session establishment. It also reuses the compatibility constraints introduced in KIP-0018:

- schema version
- compiler security version
- supported security suites
- required capabilities
- carrier family support
- envelope limits
- stream limits
- replay window limits

Profile mismatch scenarios must fail before the runtime opens the session.

## Security Context Creation

The runtime creates a security context using the profile hash, selected capabilities, transcript binding, security suite, stream policy, proxy policy, carrier policy, and a deterministic session nonce. Directional key schedules and secure envelope metadata come from the security prerequisite layer.

Trace events record only safe metadata such as transcript match, capability match, role, state, and bucketed frame information.

## In-Memory Link Model

The link model is deterministic and local. It records:

- direction
- session ID
- sequence
- envelope kind
- byte count
- metadata class

Raw secure envelopes are not serialized into trace events. Queue depth limits model carrier/link backpressure without using external networking.

## Runtime Adversary Scenarios

The runtime adversary package includes deterministic local scenarios:

- `happy_path_session`
- `capability_downgrade_attempt`
- `profile_mismatch_session`
- `replay_injection`
- `carrier_queue_pressure`
- `target_error_runtime_isolation`
- `target_reset_runtime_isolation`
- `large_object_runtime`
- `malformed_link_frame`
- `close_race`

The scenarios verify lifecycle correctness, negotiation failure handling, compatibility rejection, replay rejection, backpressure propagation, error/reset isolation, trace hygiene, and close behavior.

## Runtime Features And Collapse Scanner

Runtime feature extraction is payload-free. It includes:

- role and session state buckets
- negotiation result
- compatibility result
- security context result
- transcript and capability match
- frame direction bucket
- runtime frame bucket
- stream event bucket
- replay rejection count
- backpressure count
- target error/reset count
- close/failure reason bucket
- payload and secret hygiene flags

The collapse scanner reports suspicious stability when profiles converge on the same runtime state path, negotiation bucket, link frame pattern, backpressure shape, close behavior, or trace hygiene result.

## Runtime Mutants

Milestone 13 adds runtime mutant modes:

- `runtime_accepts_capability_downgrade`
- `runtime_accepts_profile_mismatch`
- `runtime_accepts_replay`
- `runtime_ignores_backpressure`
- `runtime_leaks_secret_trace`
- `runtime_leaks_payload_trace`
- `runtime_no_state_validation`
- `runtime_padding_only_diversity`

Mutation gates prove that these collapsed or unsafe behaviors are detected by the runtime audit.

## Generated Backend Parity

The generated source backend now emits:

- `protocol/runtime_generated.go`
- `protocol/runtime_test.go`
- `protocol/runtimeadversary_test.go`

Generated modules specialize runtime profile constants, compatibility schema, security version, carrier policy, stream policy, proxy policy, and runtime limits. Generated CLIs support:

```bash
go run ./cmd/generated-client --runtime-demo --streams 4
go run ./cmd/generated-trace --runtime --streams 4 --trace generated-runtime.jsonl --summary generated-runtime-summary.json
```

The codegen audit checks generated runtime tests, generated runtime trace capture, profile-specific runtime source differences, and generated-backend parity markers.

## Audit Commands

Run the runtime audit:

```bash
go run ./cmd/kcheck runtime --quick
go run ./cmd/kcheck runtime --full --out testdata/audit/runtime.json
```

Run the full quick audit, including runtime gates:

```bash
go run ./cmd/kcheck --quick
```

Run generated backend checks:

```bash
go run ./cmd/kcheck codegen --quick
```

## Limitations

- The runtime link is deterministic and in-memory.
- Scenarios use synthetic targets and payload byte counts.
- Secure envelopes use test-only key material.
- Trace analysis is a regression heuristic, not proof of real-world traffic analysis resistance.
- Generated modules still reuse shared helper packages.
- Future adapter work requires separate hardening and review.

## Relationship To Earlier KIPs

KIP-0018 defines transcript binding, nonce/replay checks, capability negotiation primitives, and secure envelope metadata. KIP-0019 composes those pieces into runtime sessions and adversarial runtime gates.
