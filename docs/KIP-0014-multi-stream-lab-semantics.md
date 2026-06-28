<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0014: Multi-Stream Lab Semantics

## Status

Accepted for Milestone 8.

## Summary

Kurdistan now models multiple logical streams inside one lab protocol session. This remains a loopback-only research harness. It is not SOCKS, VPN mode, HTTP proxying, external networking, deployment support, or live censorship testing.

## Why Multi-Stream Semantics Are Needed

Single-stream echo proves basic local interoperability, but it does not exercise stream lifecycle, independent close/reset behavior, flow-control pressure, or scheduler decisions across competing streams. Multi-stream semantics let the audit ask whether generated profiles preserve stable internal operations while continuing to vary wire behavior and trace shape.

## Stable Internal Semantics

The internal semantic operations are:

- `OPEN_STREAM`
- `DATA`
- `CLOSE_STREAM`
- `RESET_STREAM`
- `WINDOW_UPDATE`
- `SESSION_CLOSE`
- `ERROR`
- `PADDING`

These names are internal only. Profiles still generate semantic-to-wire mappings, frame grammar choices, stream ID encodings, scheduler policy, padding policy, and invalid-input behavior.

## Generated Wire Behavior

Profiles define stream ID strategy and encoding mode, max concurrent streams, per-stream and session flow-control windows, window update policy, stream priority policy, close and reset policy, and generated wire symbols for stream semantics.

The frame codec uses profile-specific stream ID encoding and profile-specific semantic tags. There is no fixed external `OPEN_STREAM` byte tag, fixed stream ID layout, or fixed close/reset encoding.

## Stream Lifecycle

The lab stream state machine supports `idle`, `open`, `half-closed-local`, `half-closed-remote`, `closed`, and `reset`.

A reset is stream-local in the lab model. Closing or resetting one stream must not kill the whole session or other active streams.

## Flow Control And Backpressure

Each stream has a window and the session has an aggregate window. Writes that exceed either window return backpressure instead of consuming scheduler slots. `WINDOW_UPDATE` restores credit. Trace events record safe window buckets such as `blocked`, `low`, `medium`, and `high`, never payload bytes.

## Scheduler Policies

The scheduler supports stream-aware ordering for `fifo`, `interactive_first`, `weighted_round_robin`, and `smallest_pending_first`. Blocked, closed, and reset streams are skipped.

## Trace Metadata

Trace events may include stream label bucket, stream event type, stream state, stream and session window buckets, priority class, close/reset event type, and backpressure marker.

Traces do not include payload contents, raw frames, secrets, proofs, or external target data.

## Generated Backend Parity

Generated modules include profile-specific stream constants and `protocol/multistream_test.go`. The generated client supports:

```bash
go run ./cmd/generated-client --multistream-demo --streams 3
```

The generated trace command supports:

```bash
go run ./cmd/generated-trace --multistream --streams 4 --trace generated-multistream.jsonl --summary generated-multistream-summary.json
```

`kcheck codegen --quick` includes `multi_stream_generated_parity`, which compares generated and interpreted multi-stream lab traces for the same profiles. Milestone 9 extends this with `multi_stream_generated_backend_parity`, which runs adversarial stream scenario tests inside generated modules.

## Audit Gates

Milestone 8 adds `multi_stream_semantics`, `multi_stream_diversity`, `multi_stream_backpressure`, and `multi_stream_generated_parity`.

These gates check local stream lifecycle behavior, generated stream-policy variation, backpressure/window-update representation, and generated-backend parity.

Milestone 9 adds `multi_stream_adversarial_scenarios`, `multi_stream_collapse_resistance`, and `multi_stream_mutant_detection`. See `docs/KIP-0015-multi-stream-adversarial-testing.md` for scenario definitions and stream collapse limits.

## Limitations

- This is an in-memory and loopback-only lab harness.
- It does not implement real proxy semantics, SOCKS, VPN, HTTP carriers, external targets, deployment, production key exchange, or live-network testing.
- The stream scheduler and flow control are deterministic research models, not production transport code.
- Passing these gates does not prove undetectability, censorship resistance, production safety, or real-world robustness.

## Next Layer

Milestone 10 builds on this stream model with internal proxy-style relay intents and synthetic targets. See [KIP-0016: Lab Proxy Semantics](KIP-0016-lab-proxy-semantics.md).
