<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0003: Compiler Design

The compiler takes an integer seed and produces deterministic JSON. The same seed must produce the same profile, and different seeds should usually produce structurally different profiles.

Generation steps:

1. Derive a profile ID and test-only key material from the seed.
2. Choose one first-contact family.
3. Generate state names, transition messages, and wire symbols.
4. Choose frame grammar length, type, header, fragmentation, checksum, and padding placement modes.
5. Choose scheduler mode, flush interval, batch size, max in-flight frame count, and priority mode.
6. Choose padding and invalid-input policies.
7. Compute a generation hash and validate before returning the profile.

First-contact generation currently supports `C-S-C-PROOF`, `C-C-S-PROOF`, `C-S-S-PROOF`, and `C-DECOY-C-S-PROOF`. These names are internal and are not written on the wire.

Trace expectations are implicit in the generated profile: first-contact count, state path, message symbols, frame sizes, scheduler mode, and padding distribution should vary across profiles.

The compiler does not generate deployment files, public relay configuration, external targets, or operational guidance.
