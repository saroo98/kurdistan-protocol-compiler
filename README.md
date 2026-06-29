<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

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
- adversarial diversity, mutation, black-box trace audits, security invariant gates, runtime session audits, implementation hardening gates, and adapter contract gates

The current codebase is a research compiler, runtime session harness, source generator, and audit system. Production transport integration is future work.

## Why This Project Exists

Many censorship-resistant networking systems and pluggable transports must defend against protocol fingerprinting, traffic analysis, probing, and active interference. Fixed protocol families can develop recognizable signatures over time, even when payload encryption is correct.

Kurdistan investigates a compiler-based alternative: generate structurally different relay transports per deployment or research run while preserving stable internal semantics. The long-term motivation is resilient communication in adversarial network environments, including heavily filtered countries such as Iran and other regions affected by internet censorship.

Today, the repository is focused on protocol generation, local interoperability, trace diversity, and regression gates. It is not yet a deployable censorship-circumvention system.

## What Kurdistan Is Building

```text
Local application or future packet source
        |
        v
Adapter ingress/egress interface
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

Current work is concentrated on the generated transport/compiler layer and its deterministic runtime boundaries, including internal carrier-shape modeling, production security prerequisites, runtime session architecture, hardening, and adapter interface contracts. Concrete proxy or VPN integration still requires separate design review.

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
| Lab-only proxy semantics | Done |
| Carrier abstraction | Done |
| Production security prerequisites | Done |
| Runtime session architecture | Done |
| Implementation hardening | Done |
| Adapter interface architecture | Done |
| Local adapter prototype | Done |
| Deterministic byte transport harness | Done |
| Byte-path parity and fixture freeze | Done |
| Protocol feature corpus and wire-shape baselines | Done |
| Wire-shape generator prototype | Done |
| Wire evaluation and classifier dataset harness | Next |
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
- Internal proxy-semantics model with synthetic target descriptors and relay intents.
- Synthetic target registry for echo, discard, fixed, slow, chunked, large, error, reset, drip, and jittery responses.
- Proxy adversary scenarios, proxy feature extraction, collapse scanning, and proxy mutant detection.
- Carrier abstraction models for stream, message, datagram-like, chunked, batch, interactive, long-poll-style, and lossy/reordered carrier shapes.
- Carrier adversary scenarios for batching pressure, chunked large responses, queue backpressure, reorder/retry recovery, and proxysem parity.
- Security prerequisite layer for transcript binding, key schedule interfaces, nonce management, replay rejection, downgrade resistance, capability negotiation, compatibility, config hygiene, secure envelope metadata, and security mutation tests.
- Runtime session architecture with role validation, session lifecycle, capability negotiation, profile compatibility checks, secure channel setup, in-memory links, stream manager integration, and runtime adversary scenarios.
- Implementation hardening checks for invariants, API misuse resistance, panic safety, resource limits, trace hygiene, concurrency/race prep, compatibility, generated parity, and pre-adapter readiness.
- Adapter interface architecture for bounded ingress/egress contracts, flow lifecycle, capability compatibility, runtime stream mapping, backpressure propagation, and trace-safe summaries.
- Deterministic local adapter prototype with memory ingress/egress adapters, source/sink models, runtime integration, sequence checks, and safe summaries.
- Deterministic byte transport harness with byte frame encoding/decoding, fragmentation/reassembly, bounded byte pipe, sequence checks, corruption rejection, and safe trace metadata.
- Byte-path fixture freeze with deterministic golden summaries, malformed byte corpus metadata, generated/interpreted parity checks, and fixture drift gates.
- Protocol-feature corpus with abstract encrypted-protocol feature taxonomy, safe wire-feature extraction, first-N packet-shape model, corpus comparison, collapse scanning, and wire-shape baselines.
- Wire-shape generator prototype with deterministic policy sampling, profile integration, bytepath application, expected feature matching, collapse scanning, fixtures, and generated-backend parity.
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

internal/proxysem + internal/proxyrelay + internal/proxyadversary
  synthetic proxy-semantics model, relay-intent runner, and proxy collapse scanning

internal/carrier + internal/carrierrelay + internal/carrieradversary
  abstract carrier envelopes, semantic reconstruction, carrier collapse scanning, and carrier mutants

internal/security
  transcript binding, key schedule, nonce/replay policy, capability negotiation, compatibility, config hygiene, and secure envelope model

internal/runtime + internal/runtimeadversary
  runtime roles, session lifecycle, compatibility negotiation, in-memory links, runtime traces, and runtime collapse scanning

internal/adapter + internal/adapteradversary
  ingress/egress contracts, flow lifecycle, deterministic harness, runtime boundary checks, adapter traces, and collapse scanning

internal/localadapter + internal/localadapteradversary
  memory ingress/egress adapters, deterministic source/sink models, runtime runner, local adapter traces, and collapse scanning

internal/bytetransport + internal/bytetransportadversary
  byte frame encoder/decoder, fragmentation/reassembly, bounded byte pipe, sequence checks, byte transport traces, and collapse scanning

internal/fixtures + internal/byteparity
  byte-path fixture manifests, malformed byte corpus metadata, stable hashes, drift checks, and generated/interpreted parity reports

internal/protocorpus + internal/wirefeatures
  abstract protocol-feature taxonomy, corpus manifests, first-N packet-shape model, safe feature vectors, corpus comparison, and wire-shape baselines

internal/wiregen + internal/wiregencompare
  deterministic wire-shape policy sampling, profile policy integration, expected feature comparison, fixture baselines, and collapse scanning

internal/hardening
  invariant registry, API contract checks, panic-safety harness, resource bounds, trace hygiene, concurrency checks, adapter coverage, and readiness matrix

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
go run ./cmd/kcheck proxysem --quick
go run ./cmd/kcheck carrier --quick
go run ./cmd/kcheck security --quick
go run ./cmd/kcheck runtime --quick
go run ./cmd/kcheck hardening --quick
go run ./cmd/kcheck adapter --quick
go run ./cmd/kcheck localadapter --quick
go run ./cmd/kcheck bytetransport --quick
go run ./cmd/kcheck bytepath --quick
go run ./cmd/kcheck protocorpus --quick
go run ./cmd/kcheck wirefeatures --quick
go run ./cmd/kcheck wiregen --quick
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
go run ./cmd/generated-client --proxysem-demo --targets mixed --streams 4
go run ./cmd/generated-client --carrier-demo --carrier mixed --streams 4
go run ./cmd/generated-client --security-demo --streams 4
go run ./cmd/generated-client --runtime-demo --streams 4
go run ./cmd/generated-client --hardening-demo --streams 4
go run ./cmd/generated-client --adapter-demo --flows 4
go run ./cmd/generated-client --localadapter-demo --flows 4
go run ./cmd/generated-client --bytetransport-demo --flows 4
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
- proxy-semantics correctness, diversity, target backpressure, error/reset isolation, and mutant detection
- carrier semantic reconstruction, carrier diversity, queue backpressure, loss/reorder recovery, proxysem parity, and carrier mutant detection
- security transcript binding, key schedule, nonce uniqueness, replay rejection, downgrade resistance, capability negotiation, profile compatibility, config hygiene, trace hygiene, and security mutant detection
- runtime session lifecycle, capability negotiation, profile compatibility, security context creation, replay rejection, stream management, backpressure, error/reset isolation, trace hygiene, and runtime mutant detection
- implementation hardening for invariant registry, API contracts, panic safety, resource bounds, trace hygiene, concurrency checks, generated parity, pre-adapter readiness, and hardening mutant detection
- adapter interface contracts, config validation, flow lifecycle, runtime boundary mapping, capability compatibility, backpressure, error/reset mapping, trace hygiene, collapse resistance, mutant detection, and generated-backend parity
- local adapter correctness, flow lifecycle, runtime integration, backpressure, error/reset isolation, sequence integrity, trace hygiene, collapse resistance, mutant detection, and generated-backend parity
- byte transport encoding correctness, fragmentation/reassembly, pipe backpressure, sequence integrity, corruption rejection, runtime integration, error/reset isolation, trace hygiene, collapse resistance, mutant detection, and generated-backend parity
- byte-path fixture stability, generated/interpreted parity, malformed byte corpus rejection, regression baselines, trace hygiene, and warning-only performance buckets
- protocol corpus schema validation, taxonomy coverage, entry coverage, and corpus trace hygiene
- wire-feature extraction, first-N packet modeling, corpus comparison, collapse resistance, generated-backend parity, mutant detection, and baseline drift
- wire-shape policy generation, profile integration, bytepath feature application, expected feature matching, collapse resistance, generated-backend parity, mutant detection, and baseline drift

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
go run ./cmd/kcheck proxysem --quick
go run ./cmd/kcheck carrier --quick
go run ./cmd/kcheck security --quick
go run ./cmd/kcheck runtime --quick
go run ./cmd/kcheck adapter --quick
go run ./cmd/kcheck localadapter --quick
go run ./cmd/kcheck bytetransport --quick
go run ./cmd/kcheck bytepath --quick
go run ./cmd/kcheck protocorpus --quick
go run ./cmd/kcheck wirefeatures --quick
go run ./cmd/kcheck wiregen --quick
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

## Adapter Interface Architecture

Milestone 15 defines the boundary that future local ingress and byte-transport implementations will plug into. It adds adapter kinds, bounded flow descriptors, config validation, canonical capability hashes, explicit flow lifecycle transitions, a deterministic in-memory harness, runtime stream mapping, backpressure propagation, safe adapter trace metadata, adapter adversary scenarios, adapter mutants, and generated-backend parity checks.

This is an interface and contract layer. It does not implement concrete SOCKS, TUN, VPN, HTTP, TLS, WebSocket, CDN, deployment, or external-network adapters.

Run:

```bash
go run ./cmd/kcheck adapter --quick
go run ./cmd/kcheck adapter --full --out testdata/audit/adapter.json
```

## Deterministic Local Adapter Prototype

Milestone 16 implements the first concrete local adapter prototype on top of the adapter contracts. `internal/localadapter` provides memory ingress, memory egress, a combined local pipe, deterministic source models, sink sequence validation, runtime-boundary execution, safe trace metadata, and bounded summaries.

The prototype exercises single-flow echo, many small flows, large-flow backpressure, slow drip input, mixed flows, reset isolation, target error/reset mapping, half-close behavior, queue pressure, and malformed source chunks. It remains an in-memory deterministic harness, not a concrete network adapter.

Run:

```bash
go run ./cmd/kcheck localadapter --quick
go run ./cmd/kcheck localadapter --full --out testdata/audit/localadapter.json
```

## Deterministic Byte Transport Harness

Milestone 17 adds the first deterministic byte-oriented transport harness. It encodes runtime/local-adapter output into bounded byte frames, moves them through an in-memory byte pipe, decodes and reconstructs receiver-side metadata, enforces sequence and corruption checks, and preserves payload-free traces.

The harness includes bounded fragmentation/reassembly, queue backpressure, replay/duplicate sequence rejection, corruption rejection, malformed byte rejection, byte transport adversary scenarios, byte transport mutants, and generated-backend parity checks.

Run:

```bash
go run ./cmd/kcheck bytetransport --quick
go run ./cmd/kcheck bytetransport --full --out testdata/audit/bytetransport.json
```

## Byte-Path Fixture Freeze

Milestone 18 freezes deterministic byte-path baselines before broader wire-shape work. `internal/fixtures` stores safe byte-path summaries, stable hashes, malformed byte corpus metadata, and broad performance buckets. `internal/byteparity` compares interpreted and generated backend summaries at the semantic level while reporting safe byte-shape differences separately.

Committed fixtures live under `testdata/fixtures/` and contain only summaries, buckets, scenario names, hashes, and expected results.

Run:

```bash
go run ./cmd/kcheck fixtures verify
go run ./cmd/kcheck fixtures generate --out testdata/fixtures/bytepath-golden.json --force
go run ./cmd/kcheck fixtures compare --old testdata/fixtures/bytepath-golden.json --new testdata/fixtures/bytepath-golden.json
go run ./cmd/kcheck bytepath --quick
go run ./cmd/kcheck bytepath --full --out testdata/audit/bytepath.json
```

## Protocol Feature Corpus And Wire-Shape Baselines

Milestone 19 adds the first abstract protocol-feature corpus and wire-feature baseline layer. The corpus describes coarse, safe protocol-shape features such as phases, field kinds, visibility classes, first-flight buckets, frame-size buckets, fragment rhythm, control richness, and metadata exposure. It does not copy or implement third-party protocols.

`internal/wirefeatures` extracts payload-free feature vectors from deterministic byte-path fixtures, computes a first-N packet-shape model, compares generated profiles against the abstract corpus, and scans for collapse. Golden baselines live under `testdata/wirefeatures/`.

Run:

```bash
go run ./cmd/kcheck protocorpus --quick
go run ./cmd/kcheck protocorpus --full --out testdata/audit/protocorpus.json
go run ./cmd/kcheck wirefeatures --quick
go run ./cmd/kcheck wirefeatures --full --out testdata/audit/wirefeatures.json
go run ./cmd/kcheck wirefeatures verify
```

## Wire-Shape Generator Prototype

Milestone 20 adds the first deterministic wire-shape generator prototype. `internal/wiregen` samples policy plans from the abstract protocol-feature corpus, validates safe policy metadata, hashes generated policies, and attaches a `wire_shape` section to every compiled profile.

`internal/wiregencompare` builds expected safe feature vectors from those policies, compares them against byte-path features, scans for collapse, and stores committed regression fixtures under `testdata/wiregen/`.

Run:

```bash
go run ./cmd/kcheck wiregen --quick
go run ./cmd/kcheck wiregen --full --out testdata/audit/wiregen.json
go run ./cmd/kcheck wiregen generate --out testdata/wiregen/wiregen-policy-golden.json --force
go run ./cmd/kcheck wiregen verify
go run ./cmd/kcheck wiregen compare --old testdata/wiregen/wiregen-policy-golden.json --new testdata/wiregen/wiregen-policy-golden.json
```

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

## Proxy-Semantics Model

Kurdistan now models proxy-style relay intent internally without adding a real proxy adapter. A logical stream can bind to a synthetic target descriptor, send request-like byte counts, receive response-like chunks, and record target errors, resets, close events, slow responses, and backpressure as safe trace metadata.

Synthetic targets include `echo`, `discard`, `fixed_response`, `slow_response`, `chunked_response`, `large_object`, `error_response`, `reset_midstream`, `drip_response`, and `jittery_response`. The proxy adversary audit checks that these behaviors remain isolated across streams and do not collapse into fixed observable patterns.

## Carrier Abstraction Model

Kurdistan now separates semantic relay messages from abstract carrier envelopes. A proxysem or stream scenario can emit semantic messages, pass them through a carrier model, and verify that decoding reconstructs the same payload-free semantic shape.

Carrier families include `stream_carrier`, `message_carrier`, `datagram_like_carrier`, `chunked_carrier`, `batch_carrier`, `interactive_carrier`, `long_poll_style_carrier`, and `lossy_reordered_carrier`. The model records safe metadata for envelope counts, chunking, batching, flush behavior, retry/reorder events, and carrier-induced backpressure.

## Security Prerequisite Layer

Milestone 12 adds the security architecture that future real adapters would need before integration work: profile and transcript binding, deterministic key schedule interfaces, directional nonce management, replay windows, downgrade checks, capability negotiation, compatibility validation, config redaction, secure envelope metadata, security mutants, and generated-backend parity.

This layer uses standard Go cryptographic primitives for deterministic tests and synthetic secure envelopes. It is not a complete production transport security protocol.

## Runtime Session Architecture

Milestone 13 adds an internal runtime layer above compiled profiles and below scenario runners. It models client/server roles, session lifecycle transitions, capability negotiation, profile compatibility checks, security context creation, in-memory link delivery, secure envelope exchange, stream manager integration, and runtime trace metadata.

The runtime adversary audit exercises happy-path sessions, capability downgrade attempts, profile mismatch, replay injection, carrier queue pressure, target error/reset isolation, large object pressure, malformed link frames, and close races. The generated backend includes runtime constants, runtime tests, runtime trace capture, and a local `--runtime-demo` command.

## Implementation Hardening

Milestone 14 adds a hardening layer before adapter work. It checks cross-package invariants, API misuse behavior, panic safety, resource limits, trace hygiene, deterministic concurrency/race-prep behavior, generated/interpreted parity, compatibility, hardening mutants, and a pre-adapter readiness matrix. Milestone 15 extends those checks to the adapter interface boundary.

Run:

```bash
go run ./cmd/kcheck hardening --quick
go run ./cmd/kcheck hardening --full --out testdata/audit/hardening.json
go run ./cmd/kcheck hardening --race-advice
```

## Roadmap

1. Milestone 20: wire-shape generator prototype.
2. Milestone 21: wire evaluation and classifier dataset harness.
3. Milestone 22: host-based detection resistance.
4. Milestone 23: relay churn, migration, and fleet lifecycle model.
5. Milestone 24: concrete local proxy ingress design review.

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

Kurdistan Protocol Compiler uses separate licenses for code and documentation:

- Source code: GNU Affero General Public License v3.0 or later (`AGPL-3.0-or-later`)
- Documentation: Creative Commons Attribution-ShareAlike 4.0 International (`CC BY-SA 4.0`)

Copyright 2026 Saro.

Use, modification, and distribution must preserve copyright notices and comply with the applicable license terms.
