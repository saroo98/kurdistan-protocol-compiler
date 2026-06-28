<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0002: Protocol IR

The protocol IR gives the compiler a stable internal representation while allowing generated profiles to vary structurally.

The root profile records the schema version, profile ID, seed, role policy, local carrier, states, transitions, first-contact sequence, message symbols, frame grammar, auth model, scheduler, padding, invalid-input behavior, and safety limits.

The state machine model uses named states and role-specific transitions. A valid profile must include a start state, relay-ready state, terminal state, and reachable path from start to relay-ready.

Message symbols map stable internal semantics such as `open_stream`, `data`, `close_stream`, `padding`, and `error` to generated wire symbols. Wire symbols must be unique and must not use forbidden fixed constants such as `HELLO`, `AUTH`, or `OPEN`.

The frame grammar controls length mode, type mode, header order, fragmentation, checksum mode, and padding placement. Scheduler and padding policies control batching, flush intervals, prioritization, and generated padding sizes.

Invalid-input policy is represented as local lab behavior only. It describes how unknown first messages, malformed frames, failed auth, and replay are handled in tests without providing live deployment guidance.

Validation checks schema version, limits, state references, path reachability, message mappings, generated wire symbol uniqueness, padding bounds, scheduler bounds, invalid-input options, and profile generation hash consistency.
