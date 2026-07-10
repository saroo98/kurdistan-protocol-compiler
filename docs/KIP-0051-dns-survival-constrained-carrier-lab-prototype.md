<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0051: DNS-Survival / Constrained-Carrier Lab Prototype

Milestone 45 implements the second bounded lab carrier family. The prototype models constrained request/response behavior with symbolic query-shape and response-shape buckets, capacity limits, truncation, retries, failure classes, path-health feedback, and local diagnostic summaries.

This is a deterministic lab prototype. It does not perform resolver access, public probing, domain-dependent routing, exact query logging, resolver address logging, packet capture, payload logging, or deployment behavior.

## Purpose

The HTTPS-like carrier prototype models one high-level request/response shape. M45 adds a second shape family with much tighter capacity constraints. It provides evidence that Kurdistan can model low-capacity request/response carriers while preserving stream isolation, backpressure, generated parity, and trace hygiene.

## Local Deterministic Harness

`internal/contracts/carrier/constrainedcarrier` exposes a local deterministic harness. It uses fixture-only resolver classes and symbolic buckets:

- `loopback_resolver_bucket`
- `fixture_resolver_bucket`
- `in_memory_resolver_bucket`

The harness records only aggregate metadata. It does not store resolver addresses, exact query strings, hostnames, domains, payloads, packet captures, or secrets.

## Query and Response Shapes

Query-side shapes include small, chunked, repeated, delayed, truncated, retry, failure, and reset markers. Response-side shapes include small, truncated, delayed, failure, retry, poison/failure, and reset markers.

All shape records are profile-sensitive, payload-free, hashable, and represented as safe classes rather than raw bytes.

## Capacity and Truncation

The carrier records capacity buckets, marker-size buckets, truncation buckets, truncation-to-retry mappings, and oversize rejection controls. The fixture set stores no raw byte counts and no raw request or response bytes.

## Retry and Failure

Retry behavior is bounded by max-retry controls. Failure classes include timeout, poison/failure, and reset buckets. Failure results feed safe path-health and local-pipeline summaries so future multi-carrier selection can reason about constrained-carrier health without sensitive network metadata.

## Stream Mapping

The prototype maps stream classes to query/response shape classes and records independent stream close/reset outcomes. One stream can reset without collapsing the session or leaking cross-stream metadata.

## Backpressure

Backpressure is represented through capacity-pressure, truncation-pressure, and retry-pressure buckets. Queues are bounded, ignored-pressure controls are modeled, and pressure summaries remain aggregate-only.

## Integration

M45 records safe integration evidence for:

- loopback relay
- lab egress
- relay bridge
- proxy egress
- local pipeline
- path racing
- path health
- carrier review
- measurement review

These are metadata-level integrations, not public carrier deployment paths.

## Misuse Controls and Mutants

The misuse scanner covers public resolver allowance, default resolver-style queries, exact query logging, resolver address logging, domain dependence, wildcard resolver configuration, public network allowance, arbitrary egress, payload forwarding/logging, packet capture, measurement upload, fixed-shape collapse, padding-only variation, retry storms, truncation/failure misclassification, backpressure failures, reset swallowing, integration bypass, generated drift, payload leaks, and secret leaks.

## Generated Backend Parity

`kgen` emits constrained-carrier constants, fixture accessors, parity tests, and hygiene tests. Generated modules specialize query shapes, response shapes, capacity buckets, retry/failure buckets, blocked scopes, misuse controls, and backend version `0.45.0-lab`. M46 adds the next composition layer that selects across reviewed lab carrier families without adding public carrier behavior.

## Commands

```bash
go run ./cmd/kcheck constrainedcarrier --quick
go run ./cmd/kcheck constrainedcarrier --full --out testdata/audit/constrainedcarrier.json
go run ./cmd/kcheck constrainedcarrier generate --out testdata/constrainedcarrier/constrainedcarrier-report-golden.json --force
go run ./cmd/kcheck constrainedcarrier verify
go run ./cmd/kcheck constrainedcarrier compare --old testdata/constrainedcarrier/constrainedcarrier-report-golden.json --new testdata/constrainedcarrier/constrainedcarrier-report-golden.json
```

## Known Limitations

The prototype is symbolic and deterministic. It does not validate performance, availability, or censorship behavior on public networks. It is not a resolver client, not a tunnel, not a VPN mode, and not a field-test artifact.

## Next Milestone

M46 integrates reviewed carrier families into controlled multi-carrier runtime selection while preserving carrier review, measurement review, path health, generated parity, and trace hygiene constraints. M47 should add carrier collapse and mutation audit coverage for the multi-carrier selector.
