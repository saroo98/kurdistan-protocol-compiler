<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0016: Lab Proxy Semantics

## Summary

Milestone 10 adds an internal proxy-semantics model above the multi-stream session layer. It lets local scenarios express relay-like intent without adding a real proxy adapter, external targets, SOCKS, VPN mode, HTTP carriers, or deployment behavior.

The model is:

```text
proxy-semantics scenario
        |
        v
relay intent
        |
        v
synthetic target descriptor
        |
        v
multi-stream session
        |
        v
generated framing / scheduler / padding / stream policies
        |
        v
payload-free trace + audit system
```

## Relay Intent

A relay intent binds one logical stream to a synthetic target descriptor. It records only safe metadata:

- stream ID
- relay intent ID
- target class and variant
- request class
- priority class
- response mode
- request and response byte limits

The intent is an internal semantic object. Generated profiles define how proxy semantic operations are represented through profile-specific message symbols and frame metadata.

## Synthetic Targets

The target registry is deterministic and local. Supported target classes are:

- `echo`
- `discard`
- `fixed_response`
- `slow_response`
- `chunked_response`
- `large_object`
- `error_response`
- `reset_midstream`
- `drip_response`
- `jittery_response`

Descriptors reject unknown classes, unsafe destination-like parameters, and oversized values. Handlers return byte counts, chunks, errors, resets, and backpressure metadata; they do not return or log payload contents.

## Proxy Semantic Operations

The IR adds generated semantic mappings for:

- `open_relay`
- `target_descriptor`
- `target_data`
- `target_response`
- `target_error`
- `target_close`
- `target_reset`
- `target_metadata`

Profiles also include proxy policy fields for relay intent encoding, target descriptor encoding, request class encoding, response mode encoding, target error/close/reset policy, metadata policy, target class mapping, and request/response limits.

## Target Error, Reset, And Close

Target errors are stream-local. A synthetic error on one stream must not close the whole session. Reset-midstream targets emit partial response metadata and then reset only their stream. Close behavior is recorded as target-close metadata and remains profile-policy driven.

## Target-Induced Backpressure

Slow and large synthetic targets can produce backpressure metadata. Large responses also exercise the existing flow-control recovery path through window updates. This keeps proxy behavior tied to the multi-stream flow-control model.

## Proxy Trace Features

Trace events include payload-free proxy metadata:

- target class bucket
- request class bucket
- response mode bucket
- target event type
- target error bucket
- target reset and close flags
- response chunk bucket
- target backpressure flag
- proxy scenario name

Raw frames, payload bytes, secrets, target data, and external destinations are not logged.

## Collapse Scanner

The proxy collapse scanner looks for suspicious stability across profiles, including:

- fixed relay intent encoding
- fixed target descriptor encoding
- fixed response mode pattern
- fixed target error behavior
- fixed reset and close behavior
- fixed request class mapping
- fixed metadata policy
- padding-only proxy diversity

The scanner is a regression heuristic. It can detect many collapses but cannot prove real-world indistinguishability or resistance to traffic analysis.

## Proxy Mutants

Milestone 10 adds proxy mutant modes:

- `fixed_target_descriptor_encoding`
- `fixed_target_open_sequence`
- `fixed_target_error_policy`
- `fixed_target_close_policy`
- `fixed_response_chunking`
- `no_target_backpressure`
- `padding_only_proxy_diversity`

Audit tests require these mutants to fail the relevant proxy gates.

## Generated Backend Parity

`kgen` now emits generated proxy-semantics constants and tests:

- relay intent encoding constants
- target descriptor encoding constants
- target class mappings
- target error/close/reset policy constants
- response mode constants
- proxy semantic wire symbols
- proxy safety limits
- generated proxysem demo and trace helpers

Generated modules support:

```bash
go run ./cmd/generated-client --proxysem-demo --targets mixed --streams 4
go run ./cmd/generated-trace --proxysem --targets mixed --streams 4 --trace out.jsonl --summary summary.json
```

## Commands

Run the proxy audit:

```bash
go run ./cmd/kcheck proxysem --quick
go run ./cmd/kcheck proxysem --full --out testdata/audit/proxysem.json
```

Run the standard and generated-backend audits:

```bash
go run ./cmd/kcheck --quick
go run ./cmd/kcheck codegen --quick
```

Run tests and fuzz targets:

```bash
go test ./...
go test -fuzz=Fuzz ./internal/proxysem
go test -fuzz=Fuzz ./internal/framing
```

## Limitations

This milestone models proxy-style semantics only. It does not implement a production proxy adapter, external target connection logic, carrier integration, production key exchange, deployment behavior, or real-world censorship testing. The model is useful for compiler, trace, adversarial audit, and generated-backend regression work.

## Next Layer

KIP-0017 adds carrier abstraction modeling above these proxy semantics. Proxysem scenarios emit semantic messages, and carrier models verify that different abstract envelope shapes can preserve those semantics without adding real carrier integrations.
