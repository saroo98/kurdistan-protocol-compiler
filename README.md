# Kurdistan Protocol Compiler

Kurdistan is a lab-only research prototype for compiling one-off relay protocol profiles. A profile defines a generated first-contact sequence, state machine, frame grammar, semantic wire mapping, scheduler, padding policy, invalid-input behavior, lab-only multi-stream policy, and trace expectations.

Kurdistan is not a VPN, a proxy, a deployment system, or a censorship bypass product. This repository does not include TUN/TAP interfaces, SOCKS, HTTP proxying, public relay service code, TLS mimicry, CDN bypass, domain-fronting, mobile apps, cloud deployment, or external target fetching. All runtime demos and tests are loopback-only.

## Why A Compiler First

The project starts with a compiler because the research question is whether local relay profiles can vary structurally while preserving stable internal semantics. Building a VPN first would lock the project into one transport shape too early and would add deployment concerns outside this milestone.

## Polymorphic Relay Protocols

In this prototype, polymorphic means two generated profiles are not just the same byte protocol with different keys. Profiles can differ in:

- first-contact message sequence and sizes
- client/server state graph
- semantic operation to wire symbol mapping
- frame length and type encoding
- fragmentation and padding
- scheduler mode and flush behavior
- multi-stream ID encoding, flow-control windows, stream priority, close/reset, and window-update behavior
- invalid-input and probe response behavior
- trace shape

The fixed global pieces are the Go runtime, JSON profile format, trace format, test harness, benchmark harness, safety limits, local-only TCP carrier, standard-library crypto, and maximum size/time limits.

## Generate And Validate A Profile

```bash
go run ./cmd/kdc generate --seed 12345 --out profiles/examples/profile-12345.json
go run ./cmd/kdc validate --profile profiles/examples/profile-12345.json
```

## Local Echo Demo

Run these in separate terminals. Every address is loopback-only.

```bash
go run ./cmd/kecho --listen 127.0.0.1:9000
```

```bash
go run ./cmd/kserver \
  --profile profiles/examples/profile-12345.json \
  --listen 127.0.0.1:7000 \
  --target 127.0.0.1:9000
```

```bash
go run ./cmd/kclient \
  --profile profiles/examples/profile-12345.json \
  --server 127.0.0.1:7000 \
  --message "hello kurdistan"
```

The client sends the message through the generated protocol to the local server, the server relays only to the local echo target, and the client verifies the echoed response. Payload contents are not logged.

## Generated Source Backend

Generate a lab-only profile-specific Go module from a validated profile:

```bash
go run ./cmd/kgen \
  --profile profiles/examples/profile-12345.json \
  --out .generated/profile-12345
```

Use `--force` to overwrite generated files in an existing output directory:

```bash
go run ./cmd/kgen --profile profiles/examples/profile-12345.json --out .generated/profile-12345 --force
```

Build and test the generated module:

```bash
cd .generated/profile-12345
go test ./...
```

Run the generated loopback-only commands in separate terminals:

```bash
go run ./cmd/generated-echo --listen 127.0.0.1:9100
go run ./cmd/generated-server --listen 127.0.0.1:7100 --target 127.0.0.1:9100
go run ./cmd/generated-client --server 127.0.0.1:7100 --message "hello generated"
```

Generated client and server commands accept `--trace out.jsonl` for payload-free trace events. Generated modules also include a self-contained trace runner:

```bash
go run ./cmd/generated-trace --trace generated.jsonl --summary generated-summary.json
```

Run the generated local-only multi-stream demo without starting a server:

```bash
go run ./cmd/generated-client --multistream-demo --streams 3
go run ./cmd/generated-trace --multistream --streams 4 --trace generated-multistream.jsonl --summary generated-multistream-summary.json
```

Generated output is ignored under `.generated/` and is intended for local lab inspection only.

## Traces

Both `kclient` and `kserver` accept `--trace out.jsonl`. Trace events include metadata such as state, semantic operation, frame sizes, padding sizes, and scheduler mode. Traces never include payload bytes, keys, proofs, raw frames, external destinations, or personal data.

```bash
go run ./cmd/ktrace compare \
  --a testdata/traces/profile-a.jsonl \
  --b testdata/traces/profile-b.jsonl
```

The compare command exits zero when traces are meaningfully different and nonzero when they are invalid or suspiciously similar.

Scan a directory of traces for suspiciously stable signatures:

```bash
go run ./cmd/ktrace scan --dir testdata/traces
```

Generate a small loopback-only trace corpus and summary:

```bash
go run ./cmd/ktrace corpus --start-seed 1 --count 20 --out testdata/traces/corpus-summary.json
```

## Corpus Diversity Audit

Generate an aggregate profile corpus summary without writing full profiles:

```bash
go run ./cmd/kdc corpus --start-seed 1 --count 1000 --out testdata/corpus/summary.json
```

The corpus command validates every generated profile and writes aggregate metrics only unless `--write-profiles` is explicitly provided.

Run regression gates that combine profile diversity and black-box trace diversity:

```bash
go run ./cmd/kcheck --quick
go run ./cmd/kcheck --full --out testdata/audit/latest.json
go run ./cmd/kcheck --quick --status STATUS.md
```

Run the adversarial black-box clustering analysis directly:

```bash
go run ./cmd/kcheck adversary --quick
go run ./cmd/kcheck adversary --quick --out testdata/audit/adversary.json
```

Run the optional generated-backend audit:

```bash
go run ./cmd/kcheck codegen --quick
go run ./cmd/kcheck codegen --full --out testdata/audit/codegen.json
go run ./cmd/kcheck codegen --quick --status STATUS.md
```

The generated-backend audit checks semantic equivalence against the interpreted runtime, generated trace diversity across profiles, fixed-signature regressions, mutant detection, generated source scanner results, generated/interpreted multi-stream parity, and generated-module stream adversary scenario tests.

Run the local-only multi-stream adversary audit directly:

```bash
go run ./cmd/kcheck streamadversary --quick
go run ./cmd/kcheck streamadversary --full --out testdata/audit/stream-adversary.json
```

The stream adversary audit runs deterministic local scenarios for balanced interleaving, bulk-vs-interactive pressure, blocked streams, session-window exhaustion, reset midstream, close races, and uneven stream sizes. It extracts payload-free stream features and checks that stream behavior has not collapsed into fixed observable patterns.

Compare audit reports for longitudinal regressions:

```bash
go run ./cmd/kcheck compare --old testdata/audit/baseline-small.json --new testdata/audit/baseline-small.json
```

Generate `STATUS.md` with baseline comparison:

```bash
go run ./cmd/kcheck --quick --status STATUS.md --baseline testdata/audit/baseline-small.json
```

## Tests And Benchmarks

```bash
gofmt -w .
go test ./...
go vet ./...
go test -bench=. ./...
go test -fuzz=Fuzz ./internal/framing
go run ./cmd/kcheck streamadversary --quick
```

Benchmarks measure profile generation, frame encode/decode, local round trips, scheduler overhead, and padding overhead. They are lab measurements only and do not imply real-world performance or detectability.

## Safety Boundary

This repository only proves local interoperability and structural variation in a lab harness. It does not prove that generated protocols are undetectable, safe for production, or effective in any real-world censorship environment.
