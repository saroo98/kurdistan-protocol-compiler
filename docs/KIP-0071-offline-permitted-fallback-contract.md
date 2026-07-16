<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0071: Offline permitted-fallback contract

## Status

- status: implemented offline contract
- version: `permitted-fallback-v1`
- external effects: none

M4 opens only a pure metadata decision. The selector consumes a complete M3
`lifecycle.Admitted` state, a profile-ordered list of permitted carrier-family
identifiers, explicit client support and capabilities, mandatory safety/privacy
floors, and an optional constrained manual preference. It returns either one
eligible family or an explicit blocked result.

## Admission and ranking

Eligibility is intersection-first. The lifecycle state must be admitted and
complete; policy and client versions must both equal v1; the family must be
known, profile-permitted, client-supported and capability-compatible; and all
policy, candidate, safety, and privacy floors must pass. The policy's profile,
scope, evidence reference, and non-zero generation must exactly match the
admitted lifecycle state, so stale or cross-profile policy metadata fails
closed. Only then does profile order rank candidates. Incidental map or
client-list order has no effect.

The carrier-review taxonomy is a safety ceiling, not merely a family-name
registry. A permitted family must have a descriptor that validates and is
default-eligible, synthetic-only, not manual-review-required, and not blocked
by risk. Gated DNS, experimental, domestic-risk, unsafe-control, unknown, and
other non-default families are rejected. Unknown client-supported families are
also rejected rather than silently ignored.

Manual preference can promote only an already-eligible family in the ordered
profile policy. An unlisted, unsupported, capability-blocked, or floor-weakening
preference fails closed instead of silently selecting another family. When no
safe candidate exists without a manual preference, the result is explicitly
blocked and contains no selected family.

## Privacy and capability boundary

Inputs and outputs are bounded metadata. Every externally supplied string field
and list has an explicit size bound, and rejection errors use stable reason text
without echoing rejected values. Results contain only outcome, family, and a
small reason code. They contain no endpoint, destination, payload, secret,
traffic, credential, or stable cross-session detail. The package has no file,
environment, clock, random, socket, DNS, HTTP, process, persistence, telemetry,
runtime, relay, Android, VPN, or TUN behavior.

This contract does not probe, dial, resolve, execute, or measure a fallback. It
does not authorize live networking, relay admission, diagnostics export, app
runtime, production cryptography, deployment, publication, or release.

## Evolution and rollback

V1 accepts only an exact v1 policy/client version. Compatible evolution may add
optional semantics only when older clients retain the same safe interpretation.
Deprecation must be explicit. Removing or reinterpreting an existing field or
lowering a floor requires a later major contract and separate authorization.

A caller may retain its prior last-safe selection when a newer incompatible
request is rejected; rejection never mutates caller state. Repository rollback
is `git revert` of the scoped M4 commit. There is no migration or external state
to undo.
