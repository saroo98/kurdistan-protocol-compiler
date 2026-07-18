<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0079: Phase 8 Canonical Profile Codec and Offline Ingress

## Status and boundary

- status: implementation candidate
- scope: WO-803 deterministic encoding, bounded parsing, and offline normalization
- predecessor: KIP-0077 mandatory suite and KIP-0078 trust/provider boundaries

This codec creates no authority. It performs no signature verification,
recipient opening, activation, Android/camera work, storage, subscription fetch,
or networking. A parsed signed payload remains opaque until a later verifier
consumes its exact received protected-header and payload bytes.

## Canonical inner schema

Version 1 is one deterministic CBOR map with exactly labels 1 through 20:

```cddl
canonical-profile-v1 = {
  1: 1,                                      ; format version
  2: id, 3: id, 4: id, 5: id,               ; content/profile/lineage/provider
  6: id, 7: id, 8: id, 9: id,               ; contract/revocation/snapshot/update
  10: uint, 11: uint,                        ; generation/safety floor
  12: int, 13: int,                          ; validity interval
  14: uint, 15: uint,                        ; root/revocation epochs
  16: tstr, 17: tstr,                        ; optional predecessor IDs
  18: [1*256 id],                            ; sorted unique relay IDs
  19: [1*256 id],                            ; sorted unique strategy IDs
  20: bstr .cbor { 1*128 uint => any }        ; deterministic bounded policy map
}
id = tstr .size (1..128)
```

The policy byte string is independently core-deterministic CBOR, non-empty,
map-shaped, tag-free, and at most 65,536 bytes. Generation, root epoch, and
revocation epoch are limited to `2^32-1`; safety floor is limited to `2^16-1`.
Floating point, indefinite
lengths, duplicate keys, trailing data, non-minimal values, unknown fields,
unsorted or duplicate members, and one-over-bound inputs fail categorically.
Decode followed by encode must reproduce identical bytes.

## Outer opaque parsing

`ParseSignedProfileOpaque` accepts the exact tagged COSE_Sign1 structure frozen
by KIP-0077, validates framing and protected-header schema, and returns isolated
copies of the exact object, protected bytes, payload bytes, and signature bytes.
It does not decode the profile payload or verify the signature.

`ParseSealedProfileOpaque` validates only the deterministic three-element outer
frame and its component bounds. It returns exact frame/protected/encapsulation/
ciphertext copies and never performs recipient resolution or opening.

## One offline ingress normalizer

Every supported representation converges on one opaque byte sequence:

- file and already-fetched subscription inputs supply raw bytes;
- URI and clipboard use exact `kurd://artifact/<unpadded-base64url>`;
- QR uses `KURD1/<one-based-index>/<total>/<unpadded-base64url>` with at most
  64 chunks and 4,096 characters per chunk.

Raw bytes are never trimmed. URI/base64 alternatives, padding, query/fragment
data, duplicate/missing/inconsistent QR chunks, alternate simultaneous input
fields, and oversized assembly fail with stable categories. Legacy metadata
links are explicitly `legacy-untrusted` and cannot be promoted through the
Phase 8 path. Raw/subscription size is checked before cloning, and encoded URI
or clipboard size is checked before base64 decoding. QR index and total fields
must be canonical unsigned decimal text, so signs, whitespace, leading zeroes,
and overflow are rejected before assembly.

## Deterministic fixtures and evidence

Regenerate the checked fixtures from the repository root:

```text
go run ./internal/testkit/phase8fixturegen -out internal/product/envelope/testdata/phase8-codec
```

To prove deterministic generation without touching the checked fixtures, run
the generator twice into two fresh directories and compare the three SHA-256
sets. On PowerShell:

```powershell
$a = Join-Path $env:TEMP 'phase8-fixtures-a'
$b = Join-Path $env:TEMP 'phase8-fixtures-b'
go run ./internal/testkit/phase8fixturegen -out $a
go run ./internal/testkit/phase8fixturegen -out $b
Compare-Object (Get-FileHash "$a\*" | Sort-Object Path | Select-Object -ExpandProperty Hash) (Get-FileHash "$b\*" | Sort-Object Path | Select-Object -ExpandProperty Hash)
```

`Compare-Object` must print nothing, and each directory must contain exactly
the same three generated files. This isolates generator determinism from a
calling harness timeout.

The command writes the canonical positive hex fixture, 44-row malformed report,
and row-level five-representation ingress report. Checked resource evidence
records wall-time, allocation, error-size, and timeout observations for the
profile, signed, sealed, URI, and QR stages. Tests bind every row to executable
behavior and require zero malformed accepts.

The five fuzz boundaries are exercised independently:

```text
go test ./internal/product/envelope -run '^$' -fuzz '^FuzzPhase8ProfileCodec$' -fuzztime 60s
go test ./internal/product/envelope -run '^$' -fuzz '^FuzzPhase8SignedParser$' -fuzztime 60s
go test ./internal/product/envelope -run '^$' -fuzz '^FuzzPhase8SealedParser$' -fuzztime 60s
go test ./internal/product/envelope -run '^$' -fuzz '^FuzzPhase8URIIngress$' -fuzztime 60s
go test ./internal/product/envelope -run '^$' -fuzz '^FuzzPhase8QRIngress$' -fuzztime 60s
```

The checked transcript binds exact commands, Go version, UTC capture time,
execution counts, raw-output SHA-256 values, fuzz-source hash, fixture hash, and
a generic reference-host alias. It contains no username, machine name, absolute
path, payload, profile, key, or environment value.

Capture measured parser resource observations from the repository root:

```text
go run ./internal/testkit/phase8resourcecapture -out internal/product/envelope/testdata/phase8-codec
```

The raw evidence records measured wall time, allocations, error length, and
timeout completion for each parser stage. The report binds that raw file by
SHA-256 and keeps conservative ceilings independent from the observations.

## Remaining gates

WO-803 does not authorize signing, verification, sealing, opening, key-provider
use, issuance, activation, application integration, or service operation. Those
remain later Phase 8 work orders and product phases.
