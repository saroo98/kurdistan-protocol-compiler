<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0077: Phase 8 Standards and Mandatory Classical Suite

## Status and authority

- status: requirements-lock
- last_verified: 2026-07-17
- scope: WO-802 composition, dependencies, interoperability, and randomness
- parent authorization: KIP-0075 and KIP-0076
- toolchain: Go 1.26.5, windows/amd64

This KIP freezes one implementation candidate for later Phase 8 work orders. It
does not implement the full parser, issuer, verifier, sealer, key provider, or
lifecycle. It creates no production key and authorizes no live service.

## Mandatory v1 suite

Suite `0x0001` is the only enabled suite. Suite selection is authenticated and
is never negotiated.

| Function | Mandatory choice | Registered identifier |
|---|---|---|
| Signature object | tagged COSE_Sign1 | CBOR tag 18, RFC 9052 |
| Signature | ES256, ECDSA P-256 with SHA-256 | COSE algorithm -7, RFC 9053 |
| Recipient sealing mode | HPKE Base | mode 0, RFC 9180 |
| HPKE KEM | DHKEM(P-256, HKDF-SHA256) | `0x0010` |
| HPKE KDF | HKDF-SHA256 | `0x0001` |
| HPKE AEAD | AES-256-GCM | `0x0002` |
| Serialization | RFC 8949 core deterministic CBOR | definite length only |

Reserved suite IDs `0x0101` and `0x0102` are placeholders for possible PQ and
hybrid suites. They are unsupported values, not offers, preferences, or
fallbacks. Unknown, reserved, or changed mandatory suite IDs fail closed.

### Why ES256 instead of Ed25519

Both are modern standardized signature choices. ES256 is selected because
P-256 has materially broader Android Keystore, KeyMint, HSM, KMS, attestation,
and FIPS-oriented deployment support. That portability is required by later
Android and operator phases. Ed25519 offers simpler deterministic signatures
but has uneven non-exportable hardware-key support and is disallowed by some
FIPS-only environments.

The ES256 costs are made explicit: production signatures require the secure
random source, COSE uses fixed-width 32-byte `R` followed by 32-byte `S` rather
than ASN.1 DER, and issuance normalizes `S` to the lower half-order. Verification
rejects high-S and non-64-byte encodings. Go 1.26 mixes entropy with the private
key and message for hedged ECDSA, but an entropy read failure still fails the
operation. Deterministic RFC 6979 signatures exist only in independent fixtures;
they are not the production signing mode.

## Exact signed bytes

The signed payload content type is
`application/vnd.kurdistan.profile+cbor`. The tagged object is exactly:

```cddl
kurd-signed-profile = #6.18([
  protected : bstr .cbor {
    1: -7,                                      ; alg = ES256
    2: [-65537, -65538, -65539],                ; crit
    3: "application/vnd.kurdistan.profile+cbor",
    4: bstr .size (8..64),                      ; kid
    -65537: 1,                                  ; profile format version
    -65538: 1,                                  ; suite ID 0x0001
    -65539: bstr .cbor kurd-artifact-metadata   ; issuer-bound metadata
  },
  unprotected : {},
  payload : bstr .size (1..1044480),
  signature : bstr .size 64
])
kurd-artifact-metadata = {
  1: tstr,                                      ; artifact class
  2: tstr,                                      ; audience class
  3: bstr,                                      ; bounded rotating recipient hint
  4: uint                                       ; recipient epoch
}
```

The private labels are in the IANA COSE Header Parameters private-use range
below -65536. All three are critical and protected. The unprotected map is
empty. The canonical metadata bytes bind artifact class, audience, recipient
hint, and recipient epoch to the issuer signature. This issuer binding does not
grant Provider or Registrar authority; those remain separate WO-804 policy and
verification-lifecycle decisions.
The signature input is the RFC 9052 structure encoded as core deterministic
CBOR:

```cddl
[
  "Signature1",
  protected,
  h'6b757264697374616e2d76706e2f70726f66696c652d7369676e61747572652f65787465726e616c2d6161642f7631',
  payload
]
```

The external AAD bytes decode to
`kurdistan-vpn/profile-signature/external-aad/v1`. Verification operates on the
exact received protected bytes and payload bytes. Semantic parsing or
re-encoding cannot precede signature verification.

## Exact optional recipient seal

`signed-public` ends at the signed object. The other three artifact classes may
wrap the complete tagged COSE_Sign1 bytes in one recipient-specific HPKE Base
operation. Sign first, then seal. There is no universal recipient and no
class fallback.

The deterministic outer protected map is:

```cddl
kurd-seal-protected = {
  1: 1,                                          ; seal format version
  2: 1,                                          ; suite ID 0x0001
  3: "application/vnd.kurdistan.profile+cose",  ; exact inner type
  4: bstr .cbor kurd-artifact-metadata           ; exact signed metadata bytes
}
kurd-sealed-profile = [
  protected : bstr .cbor kurd-seal-protected,
  enc : bstr .size 65,
  ciphertext : bstr
]
```

Every dispatch and suite field is therefore in the AEAD-authenticated protected
bytes. `enc` is bound by HPKE decapsulation. The ciphertext authenticates itself
through AES-GCM. The HPKE plaintext is the complete exact signed object.
After opening and issuer-signature verification, the implementation must compare
the canonical metadata bstr in the outer protected map byte-for-byte with the
critical metadata bstr in the COSE protected map. A changed class, audience,
recipient hint, or recipient epoch fails before policy or state use.

HPKE `info` and per-message AAD use independent domain labels and one
unambiguous length-prefixed construction:

```text
info = u16be(len("kurdistan-vpn/profile-seal/hpke-info/v1"))
       || "kurdistan-vpn/profile-seal/hpke-info/v1"
       || u32be(len(outer_protected)) || outer_protected

aad  = u16be(len("kurdistan-vpn/profile-seal/hpke-aad/v1"))
       || "kurdistan-vpn/profile-seal/hpke-aad/v1"
       || u32be(len(outer_protected)) || outer_protected
```

Neither construction includes `enc`, ciphertext, plaintext, or itself, so there
is no circular dependency. Each sealed artifact creates a fresh HPKE sender,
performs exactly one `Seal`, and destroys the context. A second operation is an
exhaustion error. This is stricter than RFC 9180 and avoids relying on the
pinned Go implementation's `uint64` counter without an explicit overflow check.

## Deterministic CBOR and parser floor

The selected encoder is `github.com/fxamacker/cbor/v2` v2.9.2 at commit
`45589abe5c63bea2db4d311e0d0fcc551cd772ae`, using `CoreDetEncOptions`.
The size ceilings are distinct and apply before allocation or semantic use:

| Object | Maximum bytes |
|---|---:|
| profile payload | 1,044,480 |
| complete tagged signed object | 1,048,576 |
| HPKE ciphertext | 1,048,592 |
| complete sealed frame | 1,052,763 |
| generic total CBOR input | 1,052,763 |

Builders enforce both component limits and the final marshaled output size.
Exact-boundary objects are admitted and one-byte-over signed or sealed outputs
fail closed. The later parser must enforce all of the following before
semantics:

- total input at most 1,052,763 bytes, followed by the narrower object-specific
  ceiling;
- definite-length items only;
- duplicate map keys rejected;
- trailing data rejected;
- invalid UTF-8 rejected;
- at most 16 nested levels, 2,048 array elements, and 128 map pairs;
- exact tag, array arity, map labels, types, critical labels, and content types;
- no floats, NaN, infinity, bignums, compression, or unknown critical fields;
- successful decode must reproduce the exact core-deterministic bytes.

The direct module is MIT licensed and has one indirect module,
`github.com/x448/float16` v0.8.4, also MIT licensed. The selected library's
v2.9.2 release records hardened indefinite-length handling and billions of fuzz
executions. Removal requires another implementation to reproduce every checked
fixture and strict-parser negative before the module can be dropped.

`github.com/veraison/go-cose` v1.3.0 was evaluated but not selected. Its generic
COSE API does not eliminate the application adapter needed to enforce this
profile's exact critical headers, empty unprotected map, low-S policy, and
single enabled algorithm. Using the narrowly frozen RFC 9052 structure with the
selected deterministic CBOR library avoids a second production dependency and
keeps algorithm dispatch out of a generic runtime registry. This is standards
framing, not a custom cryptographic primitive.

## Randomness, toolchain, and FIPS wording

The Go 1.26.5 standard library supplies `crypto/hpke`, `crypto/mlkem`,
`crypto/ecdsa`, `crypto/ed25519`, `crypto/fips140`, and
`testing/cryptotest`. Production ECDSA and HPKE use the Go-managed secure random
source. Repeated HPKE encapsulations must be unique. Deterministic global
randomness is permitted only in `_test.go` through `testing/cryptotest`; source
guards reject that import from production files.

On the recorded Windows baseline, `crypto/fips140.Version()` returned `latest`,
`Enabled()` returned false, `Enforced()` returned false, and `GOFIPS140=off`.
P-256, SHA-256, HKDF, ECDSA, and AES-GCM are compatible with FIPS-oriented
designs, but this repository, binary, toolchain invocation, suite decision, and
test result are not a CMVP validation or a claim of FIPS compliance.

A Go toolchain rollback is prohibited after suite activation without rerunning
the independent fixtures, randomness cases, parser negatives, full uncached
gate, and implementation review. CI and contributors must use Go 1.26.5 until a
separate toolchain migration updates this lock and evidence.

## Interoperability and size evidence

Python 3.12 with cbor2 6.1.3, cryptography 46.0.7, and pyhpke 0.6.5 independently
generated six fixtures without importing or sharing any production
encoder/decoder/sign/open code. Go's production `BuildSignedProtectedHeaders`
and `BuildSealProtected` builders reproduced the exact critical `-65539`
metadata-bearing protected bytes. Go also reproduced the Sig_structure, tagged
COSE_Sign1, and sealed-frame bytes, verified the raw ES256 signature, opened
device and backup recipient HPKE fixtures, and checked the issuer/outer metadata
binding on each opened plaintext.

The current-format fixture sizes are 154-byte protected headers, 268-byte
Sig_structure, 276-byte signed object for a 49-byte payload, 474-byte device
sealed frame, and 496-byte backup sealed frame. These are evidence probes, not
a QR capacity guarantee. Later schema and QR work must measure realistic maximum
profiles.

## Backup and PQ disposition

Phase 8 backup confidentiality is recipient-key-only and uses the same mandatory
recipient HPKE suite with class `encrypted-backup`. There is no passphrase,
password KDF, recovery phrase, shared backup key, or automatic recovery path.
Passphrase/recovery-key design remains deferred to Phase 9/13.

Go 1.26.5 exposes ML-KEM and hybrid HPKE functions, but the HPKE PQ identifiers
and composition are documented against an active Internet-Draft. COSE-HPKE is
also not a final RFC. No draft-only format is mandatory in v1. PQ and hybrid
suite IDs remain reserved and rejected until a later migration has stable
standards, cross-implementation vectors, measured Android/operator costs, and
the required review.

## Primary references

- [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [RFC 9052: COSE structures](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC 9053: COSE algorithms](https://www.rfc-editor.org/rfc/rfc9053.html)
- [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)
- [IANA COSE registries](https://www.iana.org/assignments/cose/cose.xhtml)
- [Go 1.26 HPKE documentation](https://pkg.go.dev/crypto/hpke)
- [fxamacker/cbor v2.9.2](https://github.com/fxamacker/cbor/releases/tag/v2.9.2)
- [veraison/go-cose v1.3.0](https://github.com/veraison/go-cose/releases/tag/v1.3.0)

## Gates that remain closed

WO-802 does not authorize the WO-803 parser, WO-804 verification lifecycle,
WO-805 key-provider implementation, WO-806 issuance tooling, production keys,
Android, HSM/KMS, networking, deployment, release, or a production-readiness
claim. Those remain dependent work orders with their own evidence and review.
