# Kurdistan Protocol Compiler

![Status](https://img.shields.io/badge/status-lab--research-orange)
![Scope](https://img.shields.io/badge/scope-local--only-blue)
![Language](https://img.shields.io/badge/language-Go-00ADD8)

Kurdistan is a censorship-resistance protocol research project building toward a production-grade polymorphic relay transport compiler.

> Status: Kurdistan is a lab-only research prototype. It is not a VPN, not a SOCKS proxy, not production-ready, and does not claim real-world censorship resistance or undetectability.

## What Is Kurdistan?

Kurdistan explores whether relay transport protocols can be generated as profile-specific implementations instead of being shipped as one fixed protocol family with a stable fingerprint.

The project currently generates private lab transport profiles with:

- profile-specific first-contact sequences
- generated client/server state machines
- generated frame grammars and semantic wire mappings
- scheduler, padding, and probing behavior
- invalid-input and malformed-frame policies
- HMAC transcript proof for lab authentication tests
- multi-stream relay semantics with flow control and backpressure
- payload-free trace capture
- generated Go source modules
- adversarial diversity, mutation, and black-box trace audits

The current repository focuses on the compiler, generated transport profile model, interpreted runtime, generated source backend, and local adversarial audit harness. It is not a deployable proxy, VPN, bridge, or production censorship-circumvention tool.

## Why This Project Exists

Many censorship-resistant networking systems and pluggable transport designs must defend against protocol fingerprinting, traffic analysis, probing, and active interference. Fixed protocol families can develop recognizable signatures over time, even when payload encryption is correct.

Kurdistan investigates a different design direction: a protocol compiler that can generate structurally different relay transports per deployment or research run. The long-term motivation is resilient communication in adversarial network environments, including heavily filtered countries such as Iran and other regions affected by internet censorship.

This repository does not claim to work in Iran today. It does not claim to bypass filtering, evade detection, or provide production security. The current work is controlled anti-censorship research around protocol fingerprint diversity, adversarial testing, and generated relay transport design.

## What Kurdistan Is Building

Kurdistan is intended to sit at the generated transport layer of a future proxy transport architecture:

```text
Application or future proxy adapter
        |
        v
Stable internal relay semantics
        |
        v
Kurdistan generated transport
        |
        v
Carrier layer, future or lab-only
        |
        v
Remote relay, future or lab-only
```

Current work is concentrated on the generated transport/compiler layer. Future proxy or VPN transport integration would require a separate production security design, threat model, implementation hardening, independent review, and explicit scope change.

## Current Status

| Milestone | Status |
|---|---|
| Compiler/runtime scaffold | Done |
| Diversity audit | Done |
| Regression gates | Done |
| Adversarial lab simulator | Done |
| Mutation/longitudinal testing | Done |
| Generated source backend | Done |
| Generated backend audit | Done |
| Multi-stream lab semantics | Done |
| Multi-stream adversarial testing | Done |
| Lab-only proxy semantics | Next |
| Carrier abstraction | Future |
| Production security model | Future |
| Proxy/VPN integration | Future |

## Features

- Deterministic profile generation from seeds.
- Generated first-contact grammar and transcript proof model.
- Generated frame grammar with profile-specific semantic-to-wire mappings.
- Generated scheduler, padding, malformed-input, probing, and invalid-auth behavior.
- Standard-library-only HMAC-SHA256 transcript proof for lab testing.
- Payload-free JSONL trace capture.
- Profile corpus diversity metrics.
- Black-box trace diversity scanner.
- Adversarial clustering and synthetic controls.
- Mutation tests for collapsed protocol behavior.
- Longitudinal audit comparison against baseline JSON reports.
- Generated source backend with `kgen`.
- Source scanner for generated-code artifacts.
- Multi-stream lab relay semantics.
- Stream ID strategies, close/reset behavior, flow control, and backpressure.
- Stream adversary scenarios for interleaving, scheduler pressure, blocked streams, resets, close races, and uneven stream sizes.
- Generated-backend parity checks for interpreted vs generated behavior.

## Non-Goals And Safety Boundary

Kurdistan intentionally does not implement:

- SOCKS proxy mode
- VPN mode
- HTTP carrier mode
- TLS mimicry
- CDN behavior
- domain fronting
- public relay deployment
- external target fetching
- mobile apps
- production key exchange
- live-network testing
- real-world censorship deployment

All current runtime behavior is loopback-only or in-memory lab behavior. Traces do not include payload contents, raw frames, secrets, proofs, keys, or external destination data.

## Architecture

```text
cmd/kdc
  profile generation, validation, corpus summaries

internal/ir + internal/compiler
  protocol profile schema and deterministic profile compiler

internal/fsm + internal/framing + internal/scheduler + internal/stream
  interpreted lab runtime for state machines, frames, scheduling, and streams

cmd/kgen + internal/codegen
  generated Go source backend for profile-specific modules

internal/trace + internal/adversary + internal/streamadversary
  payload-free trace features, clustering, collapse scanning, and adversarial controls

cmd/kcheck + internal/audit
  regression gates, generated-backend audit, stream adversary audit, STATUS.md generation
```

The interpreted runtime is useful for research iteration. The generated source backend exists because a shared interpreter may itself introduce common implementation artifacts. `kgen` emits profile-specific Go constants and tables so generated modules can compile and interoperate locally.

## Quickstart

The repository is Go-based and currently uses only local lab commands.

```bash
go test ./...
go vet ./...
go run ./cmd/kcheck --quick
go run ./cmd/kcheck streamadversary --quick
go run ./cmd/kcheck codegen --quick
```

If Go is not on `PATH` in this workspace, use the bundled tool:

```bash
.tools\go\bin\go.exe test ./...
.tools\go\bin\go.exe vet ./...
.tools\go\bin\go.exe run ./cmd/kcheck --quick
```

Generate and validate a local lab profile:

```bash
go run ./cmd/kdc generate --seed 12345 --out profiles/examples/profile-12345.json
go run ./cmd/kdc validate --profile profiles/examples/profile-12345.json
```

Generate a profile-specific Go module:

```bash
go run ./cmd/kgen --profile profiles/examples/profile-12345.json --out .generated/profile-12345 --force
```

Build the generated module:

```bash
cd .generated/profile-12345
go test ./...
go run ./cmd/generated-client --multistream-demo --streams 3
```

These commands are local/lab commands only. They do not start a public service or contact external targets.

## Audits And Gates

Kurdistan treats diversity as something to test, not assume.

`kcheck` runs local-only audit gates for:

- profile diversity across generated IR structures
- black-box trace diversity
- adversarial clustering
- fixed-signature detection
- malformed/probe behavior
- cosmetic-difference controls
- same-profile consistency
- different-profile separation
- fuzz-test presence
- mutation testing
- longitudinal audit comparison
- generated-backend semantic equivalence
- generated source scanner checks
- multi-stream semantics and backpressure
- stream adversary collapse resistance

Useful commands:

```bash
go run ./cmd/kcheck --quick
go run ./cmd/kcheck --full --out testdata/audit/latest.json
go run ./cmd/kcheck --quick --status STATUS.md
go run ./cmd/kcheck compare --old testdata/audit/baseline-small.json --new testdata/audit/latest.json
```

Run adversarial analyses directly:

```bash
go run ./cmd/kcheck adversary --quick
go run ./cmd/kcheck streamadversary --quick
```

`STATUS.md` is generated from the latest local audit and is intended as a compact project status snapshot. It is not a security claim.

## Generated Source Backend

`kgen` emits a buildable, profile-specific Go module with:

- static profile constants
- generated state tables
- generated framing tables
- generated scheduler constants
- generated stream policy constants
- invalid-input and auth constants
- generated tests and benchmarks
- local-only generated client/server/echo/trace commands

Generated code is not just a wrapper around `kclient` or `kserver`. It specializes profile-specific protocol data while still reusing small lab helpers for safe IO, HMAC, trace output, and deterministic local testing.

The generated source backend is not a production runtime. It is evidence for the research question: can generated protocols compile and interoperate locally while preserving profile-specific behavior?

## Multi-Stream Semantics

Kurdistan now models multiple logical streams inside one lab session.

Current multi-stream semantics include:

- `OPEN_STREAM`
- `DATA`
- `CLOSE_STREAM`
- `RESET_STREAM`
- `WINDOW_UPDATE`
- `SESSION_CLOSE`
- `ERROR`
- `PADDING`

Profiles vary stream ID strategy, stream ID encoding, max concurrent streams, initial stream/session windows, stream priority policy, window update policy, close policy, and reset policy.

The stream adversary audit exercises:

- balanced interleaving
- bulk-vs-interactive scheduling pressure
- blocked stream behavior
- session-window exhaustion
- reset midstream
- close races
- uneven stream sizes

The audit checks that padding noise alone is not mistaken for meaningful multi-stream diversity.

## Roadmap

1. Milestone 10: lab-only proxy-semantics modeling.
2. Milestone 11: lab carrier abstraction.
3. Milestone 12: production security design.
4. Milestone 13: implementation hardening.
5. Milestone 14: local proxy adapter prototype, still controlled and lab-only.
6. Future: proxy/VPN transport integration after security review.

Proxy/VPN integration is explicitly future work. It should not be added until the security model, carrier abstraction, audit story, and deployment risks have been reviewed.

## Research Positioning

Kurdistan is related to:

- censorship-resistance research
- anti-censorship networking research
- pluggable transport research
- protocol generation
- polymorphic transport protocols
- relay transport protocol design
- proxy transport architecture
- VPN transport research
- adversarial network measurement
- traffic analysis resistance research
- protocol fingerprint diversity
- internet censorship research, including Iran internet censorship as a motivating environment

These are research categories, not claims that this code is ready for real-world deployment.

## Contributing

Contributions should preserve the lab-only boundary unless a future milestone explicitly changes it.

Requirements:

- no deployment code
- no external targets
- no payload logging
- no production key exchange
- no SOCKS, VPN, HTTP carrier, TLS mimicry, or CDN behavior without an explicit future milestone
- tests for behavior changes
- docs for new commands, audit gates, or protocol semantics
- payload-free traces only

Run the relevant checks before submitting changes:

```bash
go test ./...
go vet ./...
go run ./cmd/kcheck --quick
```

## License

No license has been selected yet. Until a license is added, treat the repository as not licensed for reuse beyond the owner’s explicit permission.
