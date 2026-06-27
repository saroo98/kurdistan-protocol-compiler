# Kurdistan Protocol Compiler

Kurdistan is a lab-only research prototype for compiling one-off relay protocol profiles. A profile defines a generated first-contact sequence, state machine, frame grammar, semantic wire mapping, scheduler, padding policy, invalid-input behavior, and trace expectations.

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

## Tests And Benchmarks

```bash
gofmt -w .
go test ./...
go vet ./...
go test -bench=. ./...
go test -fuzz=Fuzz ./internal/framing
```

Benchmarks measure profile generation, frame encode/decode, local round trips, scheduler overhead, and padding overhead. They are lab measurements only and do not imply real-world performance or detectability.

## Safety Boundary

This repository only proves local interoperability and structural variation in a lab harness. It does not prove that generated protocols are undetectable, safe for production, or effective in any real-world censorship environment.
