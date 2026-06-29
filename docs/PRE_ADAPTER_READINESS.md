<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Pre-Adapter Readiness Matrix

This matrix tracks whether the current implementation is ready for review before any future adapter work. `ready-for-review` means local invariants and gates exist; it does not mean production-ready.

| Category | Status | Evidence | Remaining risk | Next action |
| --- | --- | --- | --- | --- |
| compiler | ready-for-review | profile generation, seed stability, hash mutation, validation tests | future compiler changes may collapse diversity | keep corpus and mutation gates mandatory |
| profile validation | ready-for-review | unsupported policies and bounded limits rejected | schema expansion needs new validators | require tests for each new policy |
| framing | ready-for-review | round trip, malformed, oversized, cross-profile checks, fuzz tests | generated grammars may need more edge cases | expand corpus on grammar changes |
| stream semantics | ready-for-review | stream limit, terminal state, flow-control, backpressure gates | adapter IO may add concurrency pressure | keep stream adversary gates mandatory |
| proxy semantics | ready-for-review | synthetic target registry, proxy adversary scenarios, target isolation gates | synthetic targets are not real destinations | model adapter descriptors separately |
| carrier abstraction | ready-for-review | envelope validation, reconstruction, queue/retry/reorder gates | abstract models are not real carriers | add adapter-specific carrier tests later |
| security context | ready-for-review | transcript binding, key schedule, nonce, replay, downgrade, config hygiene gates | no production key exchange yet | design key exchange separately |
| runtime session lifecycle | ready-for-review | role validation, lifecycle, capability, compatibility, in-memory link gates | no real socket session manager | review adapter lifecycle before implementation |
| generated backend parity | ready-for-review | codegen audit, source scanner, generated hardening tests | generated code still uses shared helpers | continue scanner expansion |
| trace hygiene | ready-for-review | structured scanner rejects secret/payload markers and leak flags | new trace fields may need allowlist updates | run hardening gate after trace changes |
| resource bounds | ready-for-review | frame, stream, session, queue, target, envelope bounds tested | adapter buffers are not modeled yet | define adapter limits before implementation |
| panic safety | ready-for-review | `MustNotPanic` wrappers and fuzz tests for critical decoders | coverage is representative, not exhaustive | add wrappers for new parsers |
| API misuse resistance | ready-for-review | nil/zero/unknown/oversized/malformed misuse checks | public APIs may expand | add contract tests with each API |
| concurrency/race prep | ready-for-review | nonce/replay concurrent checks and race-test advice | most runtime pieces are deterministic single-session models | run `go test -race ./...` before adapter work |
| documentation | ready-for-review | KIP-0020, README, AGENTS, STATUS, docs site updates | docs can drift | update docs with every new command/gate |

