# Kurdistan Protocol Compiler

![Status](https://img.shields.io/badge/status-experimental-orange)
![Language](https://img.shields.io/badge/language-Go-00ADD8)
![Area](https://img.shields.io/badge/area-protocol--compiler-blue)

Kurdistan is a censorship-resistance protocol research project building toward a production-grade polymorphic relay transport compiler.

Kurdistan explores a core question in anti-censorship networking: can a relay transport be generated as many structurally different protocol implementations, instead of shipping one recognizable protocol fingerprint?

## What Is Kurdistan?

Kurdistan is a protocol compiler for generated relay transports. A generated profile defines how a private transport behaves across first contact, state transitions, framing, scheduling, padding, probing, authentication checks, stream semantics, and invalid-input handling.

Current profile generation covers:

- profile-specific first-contact sequences
- generated client/server state machines
- generated frame grammars and semantic wire mappings
- scheduler, padding, probing, and malformed-input behavior
- HMAC transcript proof for controlled authentication tests
- multi-stream relay semantics with flow control and backpressure
- payload-free trace capture
- generated Go source modules
- adversarial diversity, mutation, and black-box trace audits

The current codebase is a research compiler, runtime harness, source generator, and audit system. Production transport integration is future work.

## Why This Project Exists

Many censorship-resistant networking systems and pluggable transports must defend against protocol fingerprinting, traffic analysis, probing, and active interference. Fixed protocol families can develop recognizable signatures over time, even when payload encryption is correct.

Kurdistan investigates a compiler-based alternative: generate structurally different relay transports per deployment or research run while preserving stable internal semantics. The long-term motivation is resilient communication in adversarial network environments, including heavily filtered countries such as Iran and other regions affected by internet censorship.

Today, the repository is focused on protocol generation, local interoperability, trace diversity, and regression gates. It is not yet a deployable censorship-circumvention system.

## What Kurdistan Is Building

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
Carrier layer
        |
        v
Remote relay
```

Current work is concentrated on the generated transport/compiler layer. Future proxy or VPN integration requires a separate production security design, carrier abstraction, implementation hardening, and review.

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
- Generated scheduler, padding, probing, and invalid-auth behavior.
- Standard-library-only HMAC-SHA256 transcript proof for controlled tests.
- Payload-free JSONL trace capture.
- Profile corpus diversity metrics.
- Black-box trace diversity scanner.
- Adversarial clustering and synthetic controls.
- Mutation tests for collapsed protocol behavior.
- Longitudinal audit comparison against baseline JSON reports.
- Generated source backend with `kgen`.
- Source scanner for generated-code artifacts.
- Multi-stream relay semantics.
- Stream ID strategies, close/reset behavior, flow control, and backpressure.
- Stream adversary scenarios for interleaving, scheduler pressure, blocked streams, resets, close races, and uneven stream sizes.
- Generated-backend parity checks for interpreted vs generated behavior.

## Current Boundary

The repository currently contains compiler, runtime, generator, and audit work. It does not contain deployment code, external targets, production key exchange, payload logging, SOCKS mode, VPN mode, HTTP carriers, TLS mimicry, CDN behavior, mobile clients, or live-network testing.

That boundary is intentional while the protocol model, audit gates, and generated backend are still being built.

## Architecture

```text
cmd/kdc
  profile generation, validation, corpus summaries

internal/ir + internal/compiler
  protocol profile schema and deterministic profile compiler

internal/fsm + internal/framing + internal/scheduler + internal/stream
  runtime model for state machines, frames, scheduling, and streams

cmd/kgen + internal/codegen
  generated Go source backend for profile-specific modules

internal/trace + internal/adversary + internal/streamadversary
  payload-free trace features, clustering, collapse scanning, and adversarial controls

cmd/kcheck + internal/audit
  regression gates, generated-backend audit, stream adversary audit, STATUS.md generation
```

The interpreted runtime supports fast research iteration. The generated source backend exists because a shared interpreter can introduce common implementation artifacts. `kgen` emits profile-specific Go constants and tables so generated modules can compile and interoperate locally.

## Quickstart

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

Generate and validate a profile:

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

## Audits And Gates

Kurdistan treats diversity as something to measure.

`kcheck` covers:

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

`STATUS.md` is generated from the latest audit and is intended as a compact project status snapshot.

## Generated Source Backend

`kgen` emits a buildable, profile-specific Go module with:

- static profile constants
- generated state tables
- generated framing tables
- generated scheduler constants
- generated stream policy constants
- invalid-input and auth constants
- generated tests and benchmarks
- generated client/server/echo/trace commands

Generated code specializes profile-specific protocol data while still reusing small helper packages for safe IO, HMAC, trace output, and deterministic testing.

## Multi-Stream Semantics

Kurdistan models multiple logical streams inside one session.

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
2. Milestone 11: carrier abstraction.
3. Milestone 12: production security design.
4. Milestone 13: implementation hardening.
5. Milestone 14: local proxy adapter prototype.
6. Future: proxy/VPN transport integration after security review.

## Research Positioning

Kurdistan is related to censorship-resistance research, anti-censorship networking, pluggable transport research, protocol generation, polymorphic transport protocols, relay transport design, proxy transport architecture, VPN transport research, adversarial network measurement, traffic analysis resistance research, protocol fingerprint diversity, and internet censorship research.

## Contributing

Contributions should keep the current repository scope intact unless a future milestone explicitly changes it. Behavior changes need tests, and new commands, audit gates, or protocol semantics need docs. Traces must remain payload-free.

Run the relevant checks before submitting changes:

```bash
go test ./...
go vet ./...
go run ./cmd/kcheck --quick
```

## License

No license has been selected yet. Until a license is added, treat the repository as not licensed for reuse beyond the owner’s explicit permission.
