<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0015: Multi-Stream Adversarial Testing

## Status

Accepted for Milestone 9.

## Summary

Milestone 8 added lab-only multi-stream semantics. Milestone 9 adds adversarial multi-stream scenarios, stream-level feature extraction, collapse scanning, stream mutants, audit gates, and generated-backend parity checks.

This remains strictly local and lab-only. It does not add SOCKS, VPN mode, HTTP carriers, TLS mimicry, CDN behavior, deployment scripts, production key exchange, external targets, mobile apps, live-network testing, or operational evasion guidance.

## Why Happy-Path Echo Is Insufficient

A simple multi-stream echo can pass even if all profiles expose the same stream behavior. Adversarial stream scenarios force the scheduler, flow-control model, close/reset lifecycle, and trace metadata to show whether generated profiles still differ under pressure.

The goal is not to prove real-world resistance. The goal is to catch local regressions where stream polymorphism collapses into fixed observable patterns.

## Scenario Definitions

- `balanced_interleave`: opens four streams, sends similar chunk sizes, interleaves progress fairly, and closes all streams normally.
- `bulk_vs_interactive`: opens one large bulk stream plus small interactive streams and checks that `interactive_first` profiles show interactive progress before bulk work.
- `blocked_stream`: exhausts one stream window, verifies that only that stream is blocked, and verifies that other streams continue.
- `session_window_exhaustion`: exhausts the session window, verifies global backpressure, and verifies recovery when a window update is represented.
- `reset_midstream`: resets one stream after partial data and verifies that other streams continue.
- `close_race`: closes one stream while another is active and verifies the lifecycle remains valid.
- `uneven_stream_sizes`: mixes tiny, medium, and large streams and verifies that small streams are not starved in the lab scheduler model.

## Stream-Level Features

The stream adversary extracts payload-free features:

- stream count
- stream open order
- stream close order
- reset count
- reset position bucket
- window-update count
- backpressure event count
- blocked stream ratio
- session-blocked count
- interleaving score
- fairness score
- largest-stream dominance ratio
- scheduler decision pattern
- priority-progress ratio
- stream ID pattern bucket
- close/reset outcome pattern

Traces do not include payload contents, raw frames, secrets, proofs, keys, or external target data.

## Collapse Scanner

The collapse scanner checks whether too many profiles share the same observable stream behavior. It flags suspicious stability for:

- same stream ID sequence or encoding bucket
- same window-update rhythm
- same scheduler decision pattern
- same close/reset outcome
- the same composite stream behavior across profiles

Some same-shape behavior is expected for a specific scenario, such as balanced open/close order. The scanner treats those as context rather than automatic failures.

## Stream Mutants

The test-only stream mutants simulate regressions:

- `fixed_stream_id_strategy`: all profiles share one stream ID strategy or encoding.
- `fixed_window_update_policy`: all profiles share window-update thresholds or rhythm.
- `fifo_scheduler_only`: profiles collapse to FIFO behavior regardless of configured priority policy.
- `fixed_reset_close_policy`: all profiles share reset and close behavior.
- `no_backpressure`: runtime behavior ignores flow-control backpressure.
- `padding_only_stream_diversity`: stream behavior is fixed and only padding varies.

The audit gate passes only when these mutants are detected as regressions.

## Audit Gates

Root `kcheck --quick` now includes:

- `multi_stream_adversarial_scenarios`
- `multi_stream_collapse_resistance`
- `multi_stream_mutant_detection`

Generated-backend audit includes:

- `multi_stream_generated_backend_parity`

The generated-backend gate relies on generated module tests plus generated trace metadata. Generated modules run adversarial scenario tests against their profile-specific static profile.

## Commands

```bash
go run ./cmd/kcheck --quick
go run ./cmd/kcheck streamadversary --quick
go run ./cmd/kcheck streamadversary --full --out testdata/audit/stream-adversary.json
go run ./cmd/kcheck codegen --quick
```

## Limitations

- This is a deterministic lab model, not a production transport.
- Scenarios are local and synthetic. They do not model real network loss, delay, middleboxes, or live censorship systems.
- Feature extraction is heuristic and payload-free. It can detect known collapse modes but cannot prove undetectability.
- Generated code still reuses shared lab helpers for safe IO, stream session logic, trace output, and test harnesses.
- Passing the stream adversary audit does not imply production readiness, real-world robustness, or censorship resistance.
