<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0073: Offline Diagnostic-Export Contract

## Status

- status: implemented contract
- scope: M6 deterministic in-memory redacted export only
- implementation: `internal/product/diagnosticexport`

M6 opens only the diagnostic-export catalog entry. It converts caller-supplied
fixed categorical values into canonical in-memory JSON after explicit prepare,
preview, and confirmation steps. It does not collect diagnostics, infer facts,
write a file, share, upload, retain, log, transmit, or control runtime behavior.

## Vocabulary and bounds

The exact v1 schema is `offline-diagnostic-export-v1`. Six fixed categories
admit 28 category/value pairs in a fixed order. Only `failure_summary` carries
one of the fixed count buckets `zero`, `one`, `few`, or `many`; all other count
fields must be empty. Unknown categories, values, count combinations, duplicate
pairs, zero revisions, non-user-initiated requests, and incompatible versions
fail closed with stable errors that do not echo input.

Validation applies a ten-entry per-category preflight cap, an exact 28-entry
semantic cap, and a 4,096-byte encoded cap. Canonical JSON contains only
`schema`, the fixed privacy identifier
`local-user-initiated-redacted-no-telemetry-v1`, and ordered entries with
category, value, and optional count. Identical accepted input produces
byte-identical output.

## User-flow binding

The sealed value flow is `Prepared -> Previewed -> Confirmed -> Bundle`.
External consumers cannot construct those states or build from an earlier
state. Confirmation requires approval, exact schema and revision binding, and
deep equality with the stored preview. Cancellation returns no bundle and
performs no side effect. Because Go values may be copied, cancellation cannot
revoke an already retained earlier value; future UI session ownership must
enforce that separate lifecycle.

`Preview` exposes only schema, revision, ordered categories, total-entry bucket,
and encoded-size bucket. `Bundle` owns a defensive copy of canonical bytes and
bounded metadata. Neither object conveys lifecycle, fallback, relay, runtime,
operator, or update authority.

## Privacy and capability boundary

No payload, secret, credential, key, raw frame, endpoint, destination, URI,
profile ID, relay ID, client ID, device ID, session ID, timestamp, arbitrary
caller text, or hidden metadata can enter the fixed output vocabulary. The
package imports only Go standard-library validation, ordering, comparison, and
JSON support. It performs no filesystem, environment, process, clock,
randomness, network, DNS, socket, HTTP, telemetry, persistence, goroutine,
Android, cryptographic, operator, transport, relay, or runtime work.

The source-tree consumer fixture demonstrates explicit preview and confirmation
and deterministic output. It is not a published SDK. A future Android adapter
may present a visible preview and write a confirmed bundle to a user-selected
destination, but that capability remains closed.

## Compatibility and rollback

V1 is exact and reject-unknown. Any new category or semantic reinterpretation
requires a separately reviewed contract change. Rollback is removal or revert
of the scoped M6 paths; there is no persistent or external state to migrate.
