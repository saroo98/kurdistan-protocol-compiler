<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0007: Testing And Benchmarks

The test plan covers profile validation, deterministic generation, state-machine enforcement, generated frame encode/decode, transcript authentication, scheduler behavior, padding bounds, local relay round trips, trace encoding, and trace comparison.

Profile-difference criteria include first-contact pattern, state count, transition count, state graph edges, frame grammar, message symbol mapping, scheduler policy, padding policy, and invalid-input policy.

Trace comparison considers first-contact count and sizes, state path, semantic order, frame-size histogram, padding histogram, and scheduler events. Two traces are meaningfully different when several of these dimensions differ.

Benchmarks cover:

- profile generation
- frame encode/decode
- 1 KiB local round trip
- 1 MiB local round trip
- scheduler overhead
- padding overhead

Benchmark output is a localhost lab baseline. It does not prove production performance, real-world robustness, or undetectability. If throughput is poor, the next task is to profile the local bottleneck before adding features.
