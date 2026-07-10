<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0048: HTTPS-Like Carrier Lab Prototype

Milestone 42 implements the first bounded carrier-family prototype under the M41 design lock. The carrier is HTTPS-like only in the sense that it uses symbolic request/response shape classes and bounded lab fixture exchange. It does not implement TLS, a browser-compatible HTTPS client, SNI routing, Host header routing, domain dependence, CDN/provider behavior, public-network egress, arbitrary proxying, packet capture, or payload logging.

## Relationship To M41

M41 froze the implementation contract: allowed shape classes, blocked behavior, stream mapping, backpressure, reset/error semantics, fixture schema, trace hygiene, misuse controls, generated parity requirements, and M42 acceptance criteria.

M42 turns that contract into repository behavior:

- `internal/contracts/carrier/httpslikecarrier`
- `testdata/httpslikecarrier`
- `kcheck httpslikecarrier`
- generated backend source markers and tests
- audit gates for fixtures, misuse controls, parity, and hygiene

## Shape Classes

Request-side classes are symbolic and payload-free:

- short request marker
- chunked request marker
- large-object request marker
- reset/error request marker

Response-side classes are also symbolic:

- fixed response marker
- chunked response marker
- delayed/large response marker
- reset/error/backpressure response marker

Shape selection is deterministic and profile-sensitive. Fixtures record shape class names, marker byte buckets, stream IDs, sequence numbers, and stable hashes. They do not record request bodies, response bodies, raw bytes, headers, domains, SNI, Host values, URLs, DNS queries, resolver metadata, keys, nonces, auth tags, proof material, or secrets.

## Session And Stream Lifecycle

The prototype records carrier session states:

```text
configured -> selected -> opening -> active -> backpressured -> draining -> closed
configured -> selected -> opening -> active -> reset
configured -> rejected
```

Stream summaries track opening, active, backpressure, draining, closed, reset, and target-error states. Multi-stream summaries verify independent close/reset handling and cross-stream isolation.

## Backpressure And Reset/Error Handling

Backpressure is represented through bounded queue and marker-count metadata. Reset and target-error behavior is represented with safe buckets. The prototype records integration evidence for:

- loopback relay mapping
- lab egress mapping
- relay bridge mapping
- proxy egress mapping
- local pipeline mapping
- path race and path health prerequisites
- carrier review enforcement
- measurement review enforcement

## Runtime And Security Metadata

M42 binds to runtime and secure-envelope metadata summaries without changing production keying. It records generated transport compatibility and verifies that no cryptographic secret, key, nonce base, auth tag, proof material, plaintext, ciphertext, or payload field appears in fixtures or generated outputs.

## Fixtures

The committed fixture set lives in:

```text
testdata/httpslikecarrier/
```

It includes accepted carrier session, multi-stream, backpressure, reset/error, profile-sensitive selection, fixed-shape collapse control, padding-only variation control, profile-insensitive control, unsafe metadata controls, public-network control, and generated-backend parity summaries.

## Commands

```bash
go run ./cmd/kcheck httpslikecarrier --quick
go run ./cmd/kcheck httpslikecarrier --full --out testdata/audit/httpslikecarrier.json
go run ./cmd/kcheck httpslikecarrier generate --out testdata/httpslikecarrier/httpslikecarrier-report-golden.json --force
go run ./cmd/kcheck httpslikecarrier verify
go run ./cmd/kcheck httpslikecarrier compare --old testdata/httpslikecarrier/httpslikecarrier-report-golden.json --new testdata/httpslikecarrier/httpslikecarrier-report-golden.json
```

`testdata/audit/httpslikecarrier.json` is an ignored audit artifact.

## Audit Gates

M42 adds gates for:

- scope enforcement
- shape selection diversity
- session lifecycle
- stream lifecycle
- bounded fixture exchange
- backpressure mapping
- reset/error mapping
- relay integration
- pipeline integration
- runtime/security metadata
- resource limits
- misuse detection
- generated backend parity
- trace hygiene
- mutant detection
- fixture drift

## Generated Backend

Generated modules include:

```text
protocol/httpslikecarrier_generated.go
protocol/httpslikecarrier_test.go
protocol/httpslikecarrier_parity_test.go
protocol/httpslikecarrier_hygiene_test.go
```

Generated constants specialize the schema version, profile ID, seed, runtime policy, carrier family, request/response shape counts, session states, stream states, misuse controls, and backend version.

## Limitations

This milestone is a lab carrier prototype. It proves a bounded carrier family can be represented, audited, and generated without crossing the M41 boundary. It does not prove deployability, censorship resistance, undetectability, field readiness, Android readiness, or production HTTPS behavior.

M43 adds adversarial hardening against fixed shape behavior, profile-insensitive output, unsafe fallback, leakage, generated drift, and integration bypass. See [KIP-0049](KIP-0049-https-like-carrier-adversarial-hardening.md).

M44 is next because the constrained-carrier family needs a separate design lock before any DNS-survival-style prototype is implemented.
