<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0017: Carrier Abstraction Modeling

## Summary

Milestone 11 adds an internal carrier abstraction layer. It separates semantic relay messages from abstract carrier envelopes so generated profile behavior can be tested across different carrier shapes without implementing real network transports.

The models are deterministic and local. They do not implement HTTP, TLS, CDN behavior, external targets, deployment, or live network testing.

## Why Carrier Abstraction Is Needed

Proxy-semantics modeling answers whether Kurdistan can express relay-like intents internally. Carrier abstraction asks whether those semantics survive different ways of being carried without collapsing into one stable envelope fingerprint.

Carrier abstraction models:

- envelope boundaries
- batching and coalescing
- chunking and reconstruction
- priority flushing
- retry and reorder metadata
- carrier queue backpressure
- semantic reconstruction

## Relationship To Proxy Semantics

Proxysem and stream scenarios produce payload-free semantic messages. Carrier models encode those messages into envelopes, then decode them back into semantic messages. Audits compare the reconstructed semantic shape and observable carrier metadata.

```text
proxysem / stream scenario
        |
        v
semantic messages
        |
        v
carrier abstraction
        |
        v
carrier envelopes
        |
        v
trace + audit
```

## Carrier Model Registry

The registry includes:

- `stream_carrier`
- `message_carrier`
- `datagram_like_carrier`
- `chunked_carrier`
- `batch_carrier`
- `interactive_carrier`
- `long_poll_style_carrier`
- `lossy_reordered_carrier`

Unknown carrier families are rejected. Limits are bounded by profile safety settings.

## Envelope Model

Carrier envelopes store safe metadata only:

- carrier family
- sequence number
- envelope kind
- stream bucket
- message count
- byte count
- chunk index and final-chunk flag
- flush class
- padding class
- timing bucket
- retry, reorder, drop, and ACK metadata
- backpressure flag

Payload contents, raw frames, keys, proofs, and external target data are not stored.

## Backpressure And Recovery

Carrier models can mark deterministic queue pressure and recovery metadata. Lossy/reordered models simulate pseudo-loss, pseudo-reordering, bounded retries, and clean failure modes for malformed or unrecoverable envelopes.

## Carrier Adversary Scenarios

The carrier adversary package includes:

- `stream_vs_message_equivalence`
- `batching_pressure`
- `chunked_large_response`
- `interactive_vs_bulk`
- `long_poll_queue_pressure`
- `datagram_reorder_recovery`
- `lossy_retry_recovery`
- `carrier_backpressure_chain`
- `mixed_carrier_matrix`
- `malformed_carrier_envelope`

## Collapse Scanner

The collapse scanner flags suspicious stability in:

- carrier family
- envelope encoding pattern
- flush pattern
- batch policy
- chunking policy
- retry pattern
- reorder behavior
- backpressure pattern
- priority mapping
- padding-only carrier diversity

## Mutants

Milestone 11 adds carrier mutants:

- `fixed_carrier_family`
- `fixed_envelope_encoding`
- `fixed_flush_policy`
- `fixed_batch_policy`
- `fixed_chunking_policy`
- `no_carrier_backpressure`
- `no_reorder_recovery`
- `padding_only_carrier_diversity`

Audit gates require these mutants to fail relevant checks.

## Generated Backend Parity

`kgen` emits carrier-specific constants, tests, and local demo helpers. Generated modules include:

- `protocol/carrier_generated.go`
- `protocol/carrier_test.go`
- `protocol/carrieradversary_test.go`

Generated demo commands:

```bash
go run ./cmd/generated-client --carrier-demo --carrier mixed --streams 4
go run ./cmd/generated-trace --carrier mixed --proxysem --streams 4 --trace out.jsonl --summary summary.json
```

## Commands

```bash
go run ./cmd/kcheck carrier --quick
go run ./cmd/kcheck carrier --full --out testdata/audit/carrier.json
go run ./cmd/kcheck codegen --quick
go test ./...
```

## Limitations

Carrier abstraction is a local model, not a production transport. It does not implement HTTP, TLS, CDN behavior, deployment, external targets, or live network testing. It provides deterministic regression evidence for semantic preservation and fingerprint diversity within the repository.
