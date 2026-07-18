// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func canonicalFixtureProfile() CanonicalProfileV1 {
	return CanonicalProfileV1{
		ContentID: "content.0001", ProfileID: "profile.0001", LineageID: "lineage.0001", ProviderID: "provider.0001",
		ContractVersion: "product-profile-admission-v1", RevocationScope: "revocation.0001", SnapshotMode: "full-snapshot", UpdateKind: "initial",
		Generation: 7, RequiredSafetyFloor: 1, ValidFrom: 1_700_000_000, ValidUntil: 1_800_000_000, RootEpoch: 3, RevocationEpoch: 4,
		RelayIDs: []string{"relay.0001", "relay.0002"}, StrategyIDs: []string{"strategy.0001", "strategy.0002"}, Policy: []byte{0xa1, 0x01, 0xf5},
	}
}

func canonicalProfileMap(profile CanonicalProfileV1) map[uint64]any {
	return map[uint64]any{
		1: CanonicalProfileVersion, 2: profile.ContentID, 3: profile.ProfileID, 4: profile.LineageID, 5: profile.ProviderID,
		6: profile.ContractVersion, 7: profile.RevocationScope, 8: profile.SnapshotMode, 9: profile.UpdateKind,
		10: profile.Generation, 11: profile.RequiredSafetyFloor, 12: profile.ValidFrom, 13: profile.ValidUntil,
		14: profile.RootEpoch, 15: profile.RevocationEpoch, 16: profile.PreviousContentID, 17: profile.PreviousProviderID,
		18: profile.RelayIDs, 19: profile.StrategyIDs, 20: profile.Policy,
	}
}

func TestCanonicalProfileV1RoundTripAndOpaquePayloadPreservation(t *testing.T) {
	profile := canonicalFixtureProfile()
	payload, err := EncodeCanonicalProfileV1(profile)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCanonicalProfileV1(payload)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := EncodeCanonicalProfileV1(decoded)
	if err != nil || !bytes.Equal(payload, reencoded) {
		t.Fatalf("canonical round trip changed bytes: err=%v", err)
	}
	protected, err := BuildSignedProtectedHeaders([]byte("phase8-key-id"), fixturePublicMetadata())
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeRawES256Signature(bigOne(), bigOne())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := BuildTaggedCOSESign1(protected, payload, signature)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSignedProfileOpaque(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.ExactObject, signed) || !bytes.Equal(parsed.Payload, payload) {
		t.Fatal("opaque signed parser changed exact received bytes")
	}
	parsed.Payload[0] ^= 0xff
	if bytes.Equal(parsed.Payload, payload) || !bytes.Equal(parsed.ExactObject, signed) {
		t.Fatal("parsed byte ownership is not isolated")
	}
	outer, err := BuildSealProtected(fixtureDeviceMetadata())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := BuildSealedFrame(outer, make([]byte, HPKEP256EncSize), make([]byte, HPKEAEADTagSize+1))
	if err != nil {
		t.Fatal(err)
	}
	parsedSealed, err := ParseSealedProfileOpaque(sealed)
	if err != nil || !bytes.Equal(parsedSealed.ExactFrame, sealed) || !bytes.Equal(parsedSealed.Protected, outer) {
		t.Fatalf("opaque sealed parse changed bytes: err=%v", err)
	}
}

func TestParseSignedProfileOpaqueRejectsTagsOutsideCOSESign1Envelope(t *testing.T) {
	payload, err := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	if err != nil {
		t.Fatal(err)
	}
	protected, err := BuildSignedProtectedHeaders([]byte("phase8-key-id"), fixturePublicMetadata())
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeRawES256Signature(bigOne(), bigOne())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := BuildTaggedCOSESign1(protected, payload, signature)
	if err != nil {
		t.Fatal(err)
	}
	signatureOffset := len(signed) - len(signature) - 2 // byte-string header 0x58 0x40
	if signatureOffset < 0 || signed[signatureOffset] != 0x58 || signed[signatureOffset+1] != byte(len(signature)) {
		t.Fatal("unexpected canonical signature field encoding")
	}
	taggedSignature := make([]byte, 0, len(signed)+1)
	taggedSignature = append(taggedSignature, signed[:signatureOffset]...)
	taggedSignature = append(taggedSignature, 0xd2) // an illicit nested tag 18
	taggedSignature = append(taggedSignature, signed[signatureOffset:]...)
	if _, err := ParseSignedProfileOpaque(taggedSignature); !CodecErrorIs(err, CodecSignedObject) {
		t.Fatalf("nested tag parse error = %v, want signed-object rejection", err)
	}
}

func TestParseSignedProfileOpaqueRejectsHighSSignatureBeforeVerification(t *testing.T) {
	payload, err := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	if err != nil {
		t.Fatal(err)
	}
	protected, err := BuildSignedProtectedHeaders([]byte("phase8-key-id"), fixturePublicMetadata())
	if err != nil {
		t.Fatal(err)
	}
	highS := new(big.Int).Sub(p256Order(), bigOne())
	signature := make([]byte, ES256RawSignatureSize)
	bigOne().FillBytes(signature[:32])
	highS.FillBytes(signature[32:])
	signed, err := marshalDeterministic(cbor.Tag{Number: COSESign1Tag, Content: []any{
		protected, map[int64]any{}, payload, signature,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSignedProfileOpaque(signed); !CodecErrorIs(err, CodecSignedObject) {
		t.Fatalf("high-S parse error = %v, want signed-object rejection", err)
	}
}

func TestPhase8ProtectedSchemasRejectTaggedAndWrongDirectTypes(t *testing.T) {
	metadata := fixtureDeviceMetadata()
	metadataBytes, err := BuildArtifactMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	keyID := []byte("phase8-key-id")
	signedFields := map[int64]any{
		COSEHeaderAlgorithm:            COSEAlgorithmES256,
		COSEHeaderCritical:             []int64{COSEHeaderProfileFormatVersion, COSEHeaderProfileSuiteID, COSEHeaderArtifactMetadata},
		COSEHeaderContent:              SignedPayloadContentType,
		COSEHeaderKeyID:                keyID,
		COSEHeaderProfileFormatVersion: ProfileFormatVersion,
		COSEHeaderProfileSuiteID:       uint64(SuiteClassicalV1),
		COSEHeaderArtifactMetadata:     metadataBytes,
	}
	signedWrong := map[int64]any{
		COSEHeaderAlgorithm:            "wrong",
		COSEHeaderCritical:             "wrong",
		COSEHeaderContent:              []byte(SignedPayloadContentType),
		COSEHeaderKeyID:                string(keyID),
		COSEHeaderProfileFormatVersion: "wrong",
		COSEHeaderProfileSuiteID:       "wrong",
		COSEHeaderArtifactMetadata:     map[uint64]any{},
	}
	for label, value := range signedFields {
		t.Run(fmt.Sprintf("signed tagged value %d", label), func(t *testing.T) {
			candidate := cloneInt64AnyMap(signedFields)
			candidate[label] = cbor.Tag{Number: COSESign1Tag, Content: value}
			assertSignedProtectedRejected(t, candidate)
		})
		t.Run(fmt.Sprintf("signed wrong type %d", label), func(t *testing.T) {
			candidate := cloneInt64AnyMap(signedFields)
			candidate[label] = signedWrong[label]
			assertSignedProtectedRejected(t, candidate)
		})
		t.Run(fmt.Sprintf("signed tagged key %d", label), func(t *testing.T) {
			candidate := make(map[any]any, len(signedFields))
			for currentLabel, currentValue := range signedFields {
				key := any(currentLabel)
				if currentLabel == label {
					key = cbor.Tag{Number: COSESign1Tag, Content: currentLabel}
				}
				candidate[key] = currentValue
			}
			assertSignedProtectedRejected(t, candidate)
		})
	}
	t.Run("signed tagged root map", func(t *testing.T) {
		assertSignedProtectedRejected(t, cbor.Tag{Number: COSESign1Tag, Content: signedFields})
	})

	outerFields := map[uint64]any{
		1: SealFormatVersion,
		2: uint64(SuiteClassicalV1),
		3: SignedObjectContentType,
		4: metadataBytes,
	}
	outerWrong := map[uint64]any{1: "wrong", 2: "wrong", 3: []byte(SignedObjectContentType), 4: map[uint64]any{}}
	for label, value := range outerFields {
		t.Run(fmt.Sprintf("outer tagged value %d", label), func(t *testing.T) {
			candidate := cloneUint64AnyMap(outerFields)
			candidate[label] = cbor.Tag{Number: COSESign1Tag, Content: value}
			assertOuterProtectedRejected(t, candidate)
		})
		t.Run(fmt.Sprintf("outer wrong type %d", label), func(t *testing.T) {
			candidate := cloneUint64AnyMap(outerFields)
			candidate[label] = outerWrong[label]
			assertOuterProtectedRejected(t, candidate)
		})
		t.Run(fmt.Sprintf("outer tagged key %d", label), func(t *testing.T) {
			candidate := make(map[any]any, len(outerFields))
			for currentLabel, currentValue := range outerFields {
				key := any(currentLabel)
				if currentLabel == label {
					key = cbor.Tag{Number: COSESign1Tag, Content: currentLabel}
				}
				candidate[key] = currentValue
			}
			assertOuterProtectedRejected(t, candidate)
		})
	}
	t.Run("outer tagged root map", func(t *testing.T) {
		assertOuterProtectedRejected(t, cbor.Tag{Number: COSESign1Tag, Content: outerFields})
	})
}

func TestPhase8ArtifactMetadataSchemaRejectsTaggedAndWrongDirectTypesOnSignedAndSealedPaths(t *testing.T) {
	fields := map[uint64]any{
		1: string(fixtureDeviceMetadata().Class),
		2: fixtureDeviceMetadata().AudienceClass,
		3: []byte(fixtureDeviceMetadata().RecipientHint),
		4: fixtureDeviceMetadata().RecipientEpoch,
	}
	wrong := map[uint64]any{1: []byte("wrong"), 2: []byte("wrong"), 3: "wrong", 4: "wrong"}
	for label, value := range fields {
		t.Run(fmt.Sprintf("tagged value %d", label), func(t *testing.T) {
			candidate := cloneUint64AnyMap(fields)
			candidate[label] = cbor.Tag{Number: COSESign1Tag, Content: value}
			assertMetadataRejectedBySignedAndSealedParsers(t, candidate)
		})
		t.Run(fmt.Sprintf("wrong type %d", label), func(t *testing.T) {
			candidate := cloneUint64AnyMap(fields)
			candidate[label] = wrong[label]
			assertMetadataRejectedBySignedAndSealedParsers(t, candidate)
		})
		t.Run(fmt.Sprintf("tagged key %d", label), func(t *testing.T) {
			candidate := make(map[any]any, len(fields))
			for currentLabel, currentValue := range fields {
				key := any(currentLabel)
				if currentLabel == label {
					key = cbor.Tag{Number: COSESign1Tag, Content: currentLabel}
				}
				candidate[key] = currentValue
			}
			assertMetadataRejectedBySignedAndSealedParsers(t, candidate)
		})
	}
	t.Run("tagged root map", func(t *testing.T) {
		assertMetadataRejectedBySignedAndSealedParsers(t, cbor.Tag{Number: COSESign1Tag, Content: fields})
	})
}

func cloneInt64AnyMap(source map[int64]any) map[int64]any {
	clone := make(map[int64]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func cloneUint64AnyMap(source map[uint64]any) map[uint64]any {
	clone := make(map[uint64]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func assertSignedProtectedRejected(t *testing.T, headers any) {
	t.Helper()
	protected, err := marshalDeterministic(headers)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeRawES256Signature(bigOne(), bigOne())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := marshalDeterministic(cbor.Tag{Number: COSESign1Tag, Content: []any{protected, map[int64]any{}, payload, signature}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSignedProfileOpaque(signed); !CodecErrorIs(err, CodecSignedObject) {
		t.Fatalf("error = %v, want signed-object rejection", err)
	}
}

func assertOuterProtectedRejected(t *testing.T, headers any) {
	t.Helper()
	protected, err := marshalDeterministic(headers)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := BuildSealedFrame(protected, make([]byte, HPKEP256EncSize), make([]byte, HPKEAEADTagSize+1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSealedProfileOpaque(frame); !CodecErrorIs(err, CodecSealedFrame) {
		t.Fatalf("error = %v, want sealed-frame rejection", err)
	}
}

func assertMetadataRejectedBySignedAndSealedParsers(t *testing.T, fields any) {
	t.Helper()
	metadata, err := marshalDeterministic(fields)
	if err != nil {
		t.Fatal(err)
	}
	assertSignedProtectedRejected(t, map[int64]any{
		COSEHeaderAlgorithm: COSEAlgorithmES256, COSEHeaderCritical: []int64{COSEHeaderProfileFormatVersion, COSEHeaderProfileSuiteID, COSEHeaderArtifactMetadata},
		COSEHeaderContent: SignedPayloadContentType, COSEHeaderKeyID: []byte("phase8-key-id"), COSEHeaderProfileFormatVersion: ProfileFormatVersion,
		COSEHeaderProfileSuiteID: uint64(SuiteClassicalV1), COSEHeaderArtifactMetadata: metadata,
	})
	assertOuterProtectedRejected(t, map[uint64]any{1: SealFormatVersion, 2: uint64(SuiteClassicalV1), 3: SignedObjectContentType, 4: metadata})
}

func TestPhase8ArtifactFramesRequireDirectCBORFields(t *testing.T) {
	payload, err := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	if err != nil {
		t.Fatal(err)
	}
	protected, err := BuildSignedProtectedHeaders([]byte("phase8-key-id"), fixturePublicMetadata())
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeRawES256Signature(bigOne(), bigOne())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("sign1 admits only its outer tag and a direct array", func(t *testing.T) {
		for name, content := range map[string]any{
			"nested outer tag":          cbor.Tag{Number: COSESign1Tag, Content: []any{protected, map[int64]any{}, payload, signature}},
			"tagged direct protected":   []any{cbor.Tag{Number: COSESign1Tag, Content: protected}, map[int64]any{}, payload, signature},
			"tagged direct unprotected": []any{protected, cbor.Tag{Number: COSESign1Tag, Content: map[int64]any{}}, payload, signature},
			"tagged direct payload":     []any{protected, map[int64]any{}, cbor.Tag{Number: COSESign1Tag, Content: payload}, signature},
			"tagged direct signature":   []any{protected, map[int64]any{}, payload, cbor.Tag{Number: COSESign1Tag, Content: signature}},
		} {
			t.Run(name, func(t *testing.T) {
				encoded, err := marshalDeterministic(cbor.Tag{Number: COSESign1Tag, Content: content})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ParseSignedProfileOpaque(encoded); !CodecErrorIs(err, CodecSignedObject) {
					t.Fatalf("error = %v, want signed-object rejection", err)
				}
			})
		}
	})

	outer, err := BuildSealProtected(fixtureDeviceMetadata())
	if err != nil {
		t.Fatal(err)
	}
	enc := make([]byte, HPKEP256EncSize)
	ciphertext := make([]byte, HPKEAEADTagSize+1)
	t.Run("sealed frame is an untagged array with direct byte strings", func(t *testing.T) {
		for name, frame := range map[string]any{
			"tagged root":          cbor.Tag{Number: COSESign1Tag, Content: []any{outer, enc, ciphertext}},
			"tagged protected":     []any{cbor.Tag{Number: COSESign1Tag, Content: outer}, enc, ciphertext},
			"tagged encapsulation": []any{outer, cbor.Tag{Number: COSESign1Tag, Content: enc}, ciphertext},
			"tagged ciphertext":    []any{outer, enc, cbor.Tag{Number: COSESign1Tag, Content: ciphertext}},
		} {
			t.Run(name, func(t *testing.T) {
				encoded, err := marshalDeterministic(frame)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := ParseSealedProfileOpaque(encoded); !CodecErrorIs(err, CodecSealedFrame) {
					t.Fatalf("error = %v, want sealed-frame rejection", err)
				}
			})
		}
	})
}

func bigOne() *big.Int { return big.NewInt(1) }

func TestParserLimits(t *testing.T) {
	profile := canonicalFixtureProfile()
	profile.ContentID = strings.Repeat("a", MaxCanonicalIDBytes)
	if _, err := EncodeCanonicalProfileV1(profile); err != nil {
		t.Fatalf("ID exact boundary: %v", err)
	}
	profile.ContentID += "a"
	if _, err := EncodeCanonicalProfileV1(profile); !CodecErrorIs(err, CodecInvalidValue) {
		t.Fatalf("ID one-over: %v", err)
	}
	profile = canonicalFixtureProfile()
	profile.RelayIDs = make([]string, MaxCanonicalMembers)
	for i := range profile.RelayIDs {
		profile.RelayIDs[i] = fmt.Sprintf("relay.%03d", i)
	}
	if _, err := EncodeCanonicalProfileV1(profile); err != nil {
		t.Fatalf("member exact boundary: %v", err)
	}
	profile.RelayIDs = append(profile.RelayIDs, "relay.999")
	if _, err := EncodeCanonicalProfileV1(profile); !CodecErrorIs(err, CodecSizeLimit) {
		t.Fatalf("member one-over: %v", err)
	}
	profile = canonicalFixtureProfile()
	profile.Policy, _ = marshalDeterministic(map[uint64]any{1: make([]byte, MaxCanonicalPolicyBytes-5)})
	if len(profile.Policy) != MaxCanonicalPolicyBytes {
		t.Fatalf("policy boundary fixture size=%d", len(profile.Policy))
	}
	if _, err := EncodeCanonicalProfileV1(profile); err != nil {
		t.Fatalf("policy exact boundary: %v", err)
	}
	profile.Policy = append(profile.Policy, 0)
	if _, err := EncodeCanonicalProfileV1(profile); !CodecErrorIs(err, CodecSizeLimit) {
		t.Fatalf("policy one-over: %v", err)
	}
	for name, boundary := range map[string]struct {
		exact, oneOver uint64
		set            func(*CanonicalProfileV1, uint64)
	}{
		"generation":       {MaxCanonicalGeneration, MaxCanonicalGeneration + 1, func(v *CanonicalProfileV1, n uint64) { v.Generation = n }},
		"safety floor":     {MaxCanonicalSafetyFloor, MaxCanonicalSafetyFloor + 1, func(v *CanonicalProfileV1, n uint64) { v.RequiredSafetyFloor = n }},
		"root epoch":       {MaxCanonicalRootEpoch, MaxCanonicalRootEpoch + 1, func(v *CanonicalProfileV1, n uint64) { v.RootEpoch = n }},
		"revocation epoch": {MaxCanonicalRevocationEpoch, MaxCanonicalRevocationEpoch + 1, func(v *CanonicalProfileV1, n uint64) { v.RevocationEpoch = n }},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := canonicalFixtureProfile()
			boundary.set(&candidate, boundary.exact)
			if _, err := EncodeCanonicalProfileV1(candidate); err != nil {
				t.Fatalf("exact boundary: %v", err)
			}
			boundary.set(&candidate, boundary.oneOver)
			if _, err := EncodeCanonicalProfileV1(candidate); !CodecErrorIs(err, CodecInvalidValue) {
				t.Fatalf("one-over boundary: %v", err)
			}
		})
	}
	opaque := bytes.Repeat([]byte{1}, MaxIngressQRChunks)
	chunks, err := EncodeQRChunks(opaque, 1)
	if err != nil || len(chunks) != MaxIngressQRChunks {
		t.Fatalf("QR chunk exact boundary: chunks=%d err=%v", len(chunks), err)
	}
	chunks = append(chunks, "KURD1/65/65/AQ")
	if _, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressQRChunks, Chunks: chunks}); !IngressErrorIs(err, IngressMalformedChunks) {
		t.Fatalf("QR chunk one-over: %v", err)
	}

	t.Run("ingress byte and encoding limits", func(t *testing.T) {
		raw := make([]byte, MaxTotalInputBytes)
		if _, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressFile, Bytes: raw}); err != nil {
			t.Fatalf("total input exact boundary: %v", err)
		}
		if _, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressSubscription, Bytes: make([]byte, MaxTotalInputBytes+1)}); !IngressErrorIs(err, IngressSizeLimit) {
			t.Fatalf("total input one-over: %v", err)
		}
		uri, err := EncodeArtifactURI(raw)
		if err != nil || len(strings.TrimPrefix(uri, artifactURIPrefix)) != MaxIngressEncodedChars {
			t.Fatalf("encoded ingress exact boundary: chars=%d err=%v", len(strings.TrimPrefix(uri, artifactURIPrefix)), err)
		}
		if _, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressURI, Text: uri}); err != nil {
			t.Fatalf("encoded ingress exact normalization: %v", err)
		}
		if _, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressClipboard, Text: artifactURIPrefix + strings.Repeat("A", MaxIngressEncodedChars+1)}); !IngressErrorIs(err, IngressSizeLimit) {
			t.Fatalf("encoded ingress one-over: %v", err)
		}
		chunk := "KURD1/1/1/" + strings.Repeat("A", MaxIngressChunkChars-len("KURD1/1/1/"))
		if _, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressQRChunks, Chunks: []string{chunk}}); err != nil {
			t.Fatalf("QR character exact boundary: %v", err)
		}
		if _, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressQRChunks, Chunks: []string{chunk + "A"}}); !IngressErrorIs(err, IngressMalformedChunks) {
			t.Fatalf("QR character one-over: %v", err)
		}
	})

	t.Run("suite scalar parser limits", func(t *testing.T) {
		for label, maximum := range map[string]int{
			"payload": MaxPayloadBytes, "signed object": MaxSignedObjectBytes,
			"signed protected": MaxSignedProtectedBytes, "metadata": MaxArtifactMetadataBytes,
			"ciphertext": MaxCiphertextBytes, "outer protected": MaxOuterProtectedBytes,
			"sealed frame": MaxSealedFrameBytes, "total input": MaxTotalInputBytes,
		} {
			if err := validateInputSize(label, maximum, maximum); err != nil {
				t.Fatalf("%s exact boundary: %v", label, err)
			}
			if err := validateInputSize(label, maximum+1, maximum); !errors.Is(err, ErrArtifactSizeLimit) {
				t.Fatalf("%s one-over: %v", label, err)
			}
		}
		metadata := fixtureDeviceMetadata()
		if _, err := BuildSignedProtectedHeaders(bytes.Repeat([]byte{'k'}, MinKeyIDBytes), metadata); err != nil {
			t.Fatalf("key ID minimum exact boundary: %v", err)
		}
		if _, err := BuildSignedProtectedHeaders(bytes.Repeat([]byte{'k'}, MinKeyIDBytes-1), metadata); err == nil {
			t.Fatal("key ID minimum one-under accepted")
		}
		if _, err := BuildSignedProtectedHeaders(bytes.Repeat([]byte{'k'}, MaxKeyIDBytes), metadata); err != nil {
			t.Fatalf("key ID exact boundary: %v", err)
		}
		if _, err := BuildSignedProtectedHeaders(bytes.Repeat([]byte{'k'}, MaxKeyIDBytes+1), metadata); err == nil {
			t.Fatal("key ID one-over accepted")
		}
	})

	t.Run("signed and sealed aggregate limits", func(t *testing.T) {
		signature, err := EncodeRawES256Signature(bigOne(), bigOne())
		if err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, MaxPayloadBytes)
		signed, err := BuildTaggedCOSESign1(make([]byte, 4019), payload, signature)
		if err != nil || len(signed) != MaxSignedObjectBytes {
			t.Fatalf("signed object exact boundary: size=%d err=%v", len(signed), err)
		}
		if _, err := ParseSignedProfileOpaque(append(signed, 0)); !CodecErrorIs(err, CodecSizeLimit) {
			t.Fatalf("signed object one-over parser category: %v", err)
		}
		outer := make([]byte, MaxOuterProtectedBytes)
		sealed, err := BuildSealedFrame(outer, make([]byte, HPKEP256EncSize), make([]byte, MaxCiphertextBytes-1))
		if err != nil || len(sealed) != MaxSealedFrameBytes {
			t.Fatalf("sealed frame exact boundary: size=%d err=%v", len(sealed), err)
		}
		if _, err := ParseSealedProfileOpaque(append(sealed, 0)); !CodecErrorIs(err, CodecSizeLimit) {
			t.Fatalf("sealed frame one-over parser category: %v", err)
		}
		if _, err := BuildSealedFrame([]byte{0xa0}, make([]byte, HPKEP256EncSize), make([]byte, MaxCiphertextBytes)); err != nil {
			t.Fatalf("ciphertext exact boundary: %v", err)
		}
		if _, err := BuildSealedFrame([]byte{0xa0}, make([]byte, HPKEP256EncSize), make([]byte, MaxCiphertextBytes+1)); err == nil {
			t.Fatal("ciphertext one-over accepted")
		}
		if _, err := BuildSealedFrame([]byte{0xa0}, make([]byte, HPKEP256EncSize+1), make([]byte, HPKEAEADTagSize+1)); err == nil {
			t.Fatal("encapsulation one-over accepted")
		}
		if _, err := BuildSealedFrame([]byte{0xa0}, make([]byte, HPKEP256EncSize), make([]byte, HPKEAEADTagSize)); err == nil {
			t.Fatal("ciphertext at tag-only minimum accepted")
		}
		if _, err := BuildSealedFrame([]byte{0xa0}, make([]byte, HPKEP256EncSize), make([]byte, HPKEAEADTagSize+1)); err != nil {
			t.Fatalf("ciphertext one-over tag minimum: %v", err)
		}
	})

	t.Run("CBOR structural parser limits", func(t *testing.T) {
		exactNested := append(bytes.Repeat([]byte{0x81}, MaxCBORNestedLevels), 0x00)
		var value any
		if err := unmarshalStrict(exactNested, &value); err != nil {
			t.Fatalf("nested exact: %v", err)
		}
		oneOverNested := append(bytes.Repeat([]byte{0x81}, MaxCBORNestedLevels+1), 0x00)
		if err := unmarshalStrict(oneOverNested, &value); err == nil {
			t.Fatal("nested one-over accepted")
		}
		for _, boundary := range []struct {
			name           string
			exact, oneOver any
		}{
			{"array elements", make([]any, MaxCBORArrayElements), make([]any, MaxCBORArrayElements+1)},
			{"map pairs", func() map[uint64]any {
				m := make(map[uint64]any, MaxCBORMapPairs)
				for i := 0; i < MaxCBORMapPairs; i++ {
					m[uint64(i)] = nil
				}
				return m
			}(), func() map[uint64]any {
				m := make(map[uint64]any, MaxCBORMapPairs+1)
				for i := 0; i < MaxCBORMapPairs+1; i++ {
					m[uint64(i)] = nil
				}
				return m
			}()},
		} {
			exactBytes, err := marshalDeterministic(boundary.exact)
			if err != nil {
				t.Fatal(err)
			}
			if err := unmarshalStrict(exactBytes, &value); err != nil {
				t.Fatalf("%s exact: %v", boundary.name, err)
			}
			overBytes, err := marshalDeterministic(boundary.oneOver)
			if err != nil {
				t.Fatal(err)
			}
			if err := unmarshalStrict(overBytes, &value); err == nil {
				t.Fatalf("%s one-over accepted", boundary.name)
			}
		}
	})
}

func TestQRChunkDecimalsAreCanonical(t *testing.T) {
	for _, value := range []string{"01", "+1", " 1", "1 ", "9999", "18446744073709551616"} {
		chunks := []string{"KURD1/" + value + "/1/AQ"}
		if _, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressQRChunks, Chunks: chunks}); !IngressErrorIs(err, IngressMalformedChunks) {
			t.Fatalf("decimal %q err=%v", value, err)
		}
	}
}

type malformedCodecCase struct {
	name     string
	category CodecErrorCategory
	run      func() error
}

func malformedCodecCases(t *testing.T) []malformedCodecCase {
	t.Helper()
	profile := canonicalFixtureProfile()
	valid, err := EncodeCanonicalProfileV1(profile)
	if err != nil {
		t.Fatal(err)
	}
	encodeMap := func(mutate func(map[uint64]any)) func() error {
		return func() error {
			fields := canonicalProfileMap(profile)
			mutate(fields)
			encoded, err := marshalDeterministic(fields)
			if err != nil {
				return err
			}
			_, err = DecodeCanonicalProfileV1(encoded)
			return err
		}
	}
	encodeProfile := func(mutate func(*CanonicalProfileV1)) func() error {
		return func() error { copy := profile; mutate(&copy); _, err := EncodeCanonicalProfileV1(copy); return err }
	}
	protected, err := BuildSignedProtectedHeaders([]byte("phase8-key-id"), fixturePublicMetadata())
	if err != nil {
		t.Fatal(err)
	}
	signature, err := EncodeRawES256Signature(bigOne(), bigOne())
	if err != nil {
		t.Fatal(err)
	}
	outer, err := BuildSealProtected(fixtureDeviceMetadata())
	if err != nil {
		t.Fatal(err)
	}
	return []malformedCodecCase{
		{"empty input", CodecSizeLimit, func() error { _, err := DecodeCanonicalProfileV1(nil); return err }},
		{"payload one over", CodecSizeLimit, func() error { _, err := DecodeCanonicalProfileV1(make([]byte, MaxPayloadBytes+1)); return err }},
		{"trailing data", CodecNonCanonical, func() error { _, err := DecodeCanonicalProfileV1(append(bytes.Clone(valid), 0)); return err }},
		{"duplicate map key", CodecNonCanonical, func() error { _, err := DecodeCanonicalProfileV1([]byte{0xa2, 0x01, 0x01, 0x01, 0x01}); return err }},
		{"indefinite map", CodecNonCanonical, func() error { _, err := DecodeCanonicalProfileV1([]byte{0xbf, 0x01, 0x01, 0xff}); return err }},
		{"floating value", CodecNonCanonical, func() error { _, err := DecodeCanonicalProfileV1([]byte{0xf9, 0x3c, 0x00}); return err }},
		{"nonminimal integer", CodecNonCanonical, func() error { _, err := DecodeCanonicalProfileV1([]byte{0x18, 0x17}); return err }},
		{"wrong top type", CodecSchema, func() error {
			encoded, _ := marshalDeterministic([]any{})
			_, err := DecodeCanonicalProfileV1(encoded)
			return err
		}},
		{"missing field", CodecSchema, encodeMap(func(v map[uint64]any) { delete(v, 20) })},
		{"extra field", CodecSchema, encodeMap(func(v map[uint64]any) { v[21] = uint64(1) })},
		{"unsupported version", CodecUnsupportedVersion, encodeMap(func(v map[uint64]any) { v[1] = uint64(2) })},
		{"content id wrong type", CodecSchema, encodeMap(func(v map[uint64]any) { v[2] = uint64(1) })},
		{"empty content id", CodecInvalidValue, encodeProfile(func(v *CanonicalProfileV1) { v.ContentID = "" })},
		{"content id whitespace", CodecInvalidValue, encodeProfile(func(v *CanonicalProfileV1) { v.ContentID = " bad" })},
		{"content id oversized", CodecInvalidValue, encodeProfile(func(v *CanonicalProfileV1) { v.ContentID = strings.Repeat("a", MaxCanonicalIDBytes+1) })},
		{"generation zero", CodecInvalidValue, encodeProfile(func(v *CanonicalProfileV1) { v.Generation = 0 })},
		{"safety floor zero", CodecInvalidValue, encodeProfile(func(v *CanonicalProfileV1) { v.RequiredSafetyFloor = 0 })},
		{"valid from zero", CodecInvalidValue, encodeProfile(func(v *CanonicalProfileV1) { v.ValidFrom = 0 })},
		{"validity reversed", CodecInvalidValue, encodeProfile(func(v *CanonicalProfileV1) { v.ValidUntil = v.ValidFrom })},
		{"root epoch zero", CodecInvalidValue, encodeProfile(func(v *CanonicalProfileV1) { v.RootEpoch = 0 })},
		{"revocation epoch zero", CodecInvalidValue, encodeProfile(func(v *CanonicalProfileV1) { v.RevocationEpoch = 0 })},
		{"relay list empty", CodecSizeLimit, encodeProfile(func(v *CanonicalProfileV1) { v.RelayIDs = nil })},
		{"relay list oversized", CodecSizeLimit, encodeProfile(func(v *CanonicalProfileV1) { v.RelayIDs = make([]string, MaxCanonicalMembers+1) })},
		{"relay duplicate", CodecMemberOrder, encodeProfile(func(v *CanonicalProfileV1) { v.RelayIDs = []string{"relay.a", "relay.a"} })},
		{"relay order", CodecMemberOrder, encodeProfile(func(v *CanonicalProfileV1) { v.RelayIDs = []string{"relay.b", "relay.a"} })},
		{"strategy list empty", CodecSizeLimit, encodeProfile(func(v *CanonicalProfileV1) { v.StrategyIDs = nil })},
		{"strategy duplicate", CodecMemberOrder, encodeProfile(func(v *CanonicalProfileV1) { v.StrategyIDs = []string{"strategy.a", "strategy.a"} })},
		{"policy oversized", CodecSizeLimit, encodeProfile(func(v *CanonicalProfileV1) { v.Policy = make([]byte, MaxCanonicalPolicyBytes+1) })},
		{"profile id invalid character", CodecInvalidValue, encodeProfile(func(v *CanonicalProfileV1) { v.ProfileID = "profile/invalid" })},
		{"previous content invalid", CodecInvalidValue, encodeProfile(func(v *CanonicalProfileV1) { v.PreviousContentID = " invalid" })},
		{"signed empty", CodecSizeLimit, func() error { _, err := ParseSignedProfileOpaque(nil); return err }},
		{"signed wrong tag", CodecNonCanonical, func() error {
			encoded, _ := marshalDeterministic(cbor.Tag{Number: 17, Content: []any{}})
			_, err := ParseSignedProfileOpaque(encoded)
			return err
		}},
		{"signed wrong arity", CodecSignedObject, func() error {
			encoded, _ := marshalDeterministic(cbor.Tag{Number: COSESign1Tag, Content: []any{protected, map[int64]any{}, valid}})
			_, err := ParseSignedProfileOpaque(encoded)
			return err
		}},
		{"signed unprotected nonempty", CodecSignedObject, func() error {
			encoded, _ := marshalDeterministic(cbor.Tag{Number: COSESign1Tag, Content: []any{protected, map[int64]any{1: 1}, valid, signature}})
			_, err := ParseSignedProfileOpaque(encoded)
			return err
		}},
		{"signed payload empty", CodecSizeLimit, func() error {
			encoded, _ := marshalDeterministic(cbor.Tag{Number: COSESign1Tag, Content: []any{protected, map[int64]any{}, []byte{}, signature}})
			_, err := ParseSignedProfileOpaque(encoded)
			return err
		}},
		{"signed signature short", CodecSignedObject, func() error {
			encoded, _ := marshalDeterministic(cbor.Tag{Number: COSESign1Tag, Content: []any{protected, map[int64]any{}, valid, make([]byte, ES256RawSignatureSize-1)}})
			_, err := ParseSignedProfileOpaque(encoded)
			return err
		}},
		{"signed protected invalid", CodecSignedObject, func() error {
			encoded, _ := marshalDeterministic(cbor.Tag{Number: COSESign1Tag, Content: []any{[]byte{0xa0}, map[int64]any{}, valid, signature}})
			_, err := ParseSignedProfileOpaque(encoded)
			return err
		}},
		{"signed trailing data", CodecNonCanonical, func() error {
			encoded, _ := BuildTaggedCOSESign1(protected, valid, signature)
			_, err := ParseSignedProfileOpaque(append(encoded, 0))
			return err
		}},
		{"sealed empty", CodecSizeLimit, func() error { _, err := ParseSealedProfileOpaque(nil); return err }},
		{"sealed wrong arity", CodecSealedFrame, func() error {
			encoded, _ := marshalDeterministic([]any{outer, make([]byte, HPKEP256EncSize)})
			_, err := ParseSealedProfileOpaque(encoded)
			return err
		}},
		{"sealed protected invalid", CodecSealedFrame, func() error {
			encoded, _ := marshalDeterministic([]any{[]byte{0xa0}, make([]byte, HPKEP256EncSize), make([]byte, HPKEAEADTagSize+1)})
			_, err := ParseSealedProfileOpaque(encoded)
			return err
		}},
		{"sealed encapsulation short", CodecSealedFrame, func() error {
			encoded, _ := marshalDeterministic([]any{outer, make([]byte, HPKEP256EncSize-1), make([]byte, HPKEAEADTagSize+1)})
			_, err := ParseSealedProfileOpaque(encoded)
			return err
		}},
		{"sealed ciphertext short", CodecSizeLimit, func() error {
			encoded, _ := marshalDeterministic([]any{outer, make([]byte, HPKEP256EncSize), make([]byte, HPKEAEADTagSize)})
			_, err := ParseSealedProfileOpaque(encoded)
			return err
		}},
		{"sealed trailing data", CodecNonCanonical, func() error {
			encoded, _ := BuildSealedFrame(outer, make([]byte, HPKEP256EncSize), make([]byte, HPKEAEADTagSize+1))
			_, err := ParseSealedProfileOpaque(append(encoded, 0))
			return err
		}},
	}
}

func TestMalformedEnvelopeReportHasNoAccepts(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("testdata", "phase8-codec", "malformed-envelope-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Schema  string                            `json:"schema"`
		Cases   []struct{ Name, Category string } `json:"cases"`
		Summary struct{ Accepted, Rejected int }  `json:"summary"`
	}
	if err := json.Unmarshal(content, &report); err != nil {
		t.Fatal(err)
	}
	cases := malformedCodecCases(t)
	if report.Schema != "kurdistan.phase8.malformed-envelope-report.v1" || len(cases) < 25 || len(report.Cases) != len(cases) || report.Summary.Accepted != 0 || report.Summary.Rejected != len(cases) {
		t.Fatalf("invalid malformed report: cases=%d report=%+v", len(cases), report)
	}
	for i, item := range cases {
		if report.Cases[i].Name != item.name || report.Cases[i].Category != string(item.category) {
			t.Fatalf("case %d report mismatch: %+v", i, report.Cases[i])
		}
		if err := item.run(); err == nil || !CodecErrorIs(err, item.category) {
			t.Fatalf("case %q err=%v want category %s", item.name, err, item.category)
		}
	}
}

func TestIngressNormalizationReport(t *testing.T) {
	opaque, err := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	if err != nil {
		t.Fatal(err)
	}
	uri, err := EncodeArtifactURI(opaque)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := EncodeQRChunks(opaque, 97)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []ProfileIngress{{Kind: IngressFile, Bytes: opaque}, {Kind: IngressURI, Text: uri}, {Kind: IngressQRChunks, Chunks: reverseStrings(chunks)}, {Kind: IngressClipboard, Text: uri}, {Kind: IngressSubscription, Bytes: opaque}}
	seen := map[[32]byte]struct{}{}
	for _, input := range inputs {
		got, err := NormalizeProfileIngress(input)
		if err != nil || !bytes.Equal(got, opaque) {
			t.Fatalf("%s normalization: %v", input.Kind, err)
		}
		seen[sha256.Sum256(got)] = struct{}{}
	}
	if len(seen) != 1 {
		t.Fatalf("normalized sequences=%d", len(seen))
	}
	rejections := map[string]struct {
		input    ProfileIngress
		category IngressErrorCategory
	}{
		"padded URI":             {ProfileIngress{Kind: IngressURI, Text: uri + "="}, IngressAmbiguousBase},
		"legacy metadata":        {ProfileIngress{Kind: IngressURI, Text: "kurd://profile/example?exp=1"}, IngressLegacyUntrusted},
		"duplicate QR":           {ProfileIngress{Kind: IngressQRChunks, Chunks: []string{"KURD1/1/2/AQ", "KURD1/1/2/Ag"}}, IngressMalformedChunks},
		"leading-zero QR index":  {ProfileIngress{Kind: IngressQRChunks, Chunks: []string{"KURD1/01/1/AQ"}}, IngressMalformedChunks},
		"plus-sign QR index":     {ProfileIngress{Kind: IngressQRChunks, Chunks: []string{"KURD1/+1/1/AQ"}}, IngressMalformedChunks},
		"oversized URI encoding": {ProfileIngress{Kind: IngressURI, Text: artifactURIPrefix + strings.Repeat("A", MaxIngressEncodedChars+1)}, IngressSizeLimit},
	}
	for name, input := range rejections {
		if _, err := NormalizeProfileIngress(input.input); !IngressErrorIs(err, input.category) {
			t.Fatalf("%s err=%v want %s", name, err, input.category)
		}
	}
	var report struct {
		Schema          string `json:"schema"`
		Representations []struct {
			Name           string `json:"name"`
			Result         string `json:"result"`
			SequenceSHA256 string `json:"sequence_sha256"`
		} `json:"representations"`
		Rejections []struct {
			Name     string `json:"name"`
			Category string `json:"category"`
		} `json:"rejections"`
		Summary struct {
			Accepted            int `json:"accepted"`
			NormalizedSequences int `json:"normalized_sequences"`
			Rejected            int `json:"rejected"`
		} `json:"summary"`
	}
	loadJSON(t, filepath.Join("testdata", "phase8-codec", "ingress-normalization-report.json"), &report)
	if report.Schema != "kurdistan.phase8.ingress-normalization-report.v2" || len(report.Representations) != 5 || len(report.Rejections) != len(rejections) || report.Summary.Accepted != 5 || report.Summary.NormalizedSequences != 1 || report.Summary.Rejected != len(rejections) {
		t.Fatalf("report=%+v", report)
	}
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(opaque))
	for _, row := range report.Representations {
		if row.Result != "accepted" || row.SequenceSHA256 != wantDigest {
			t.Fatalf("representation row=%+v", row)
		}
	}
	for _, row := range report.Rejections {
		want, ok := rejections[row.Name]
		if !ok || row.Category != string(want.category) {
			t.Fatalf("rejection row=%+v", row)
		}
		delete(rejections, row.Name)
	}
	if len(rejections) != 0 {
		t.Fatalf("missing rejection rows=%v", rejections)
	}
}

func TestReferenceHostResourceReport(t *testing.T) {
	encoded, err := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	if err != nil {
		t.Fatal(err)
	}
	protected, _ := BuildSignedProtectedHeaders([]byte("phase8-key-id"), fixturePublicMetadata())
	signature, _ := EncodeRawES256Signature(bigOne(), bigOne())
	signed, _ := BuildTaggedCOSESign1(protected, encoded, signature)
	outer, _ := BuildSealProtected(fixtureDeviceMetadata())
	sealed, _ := BuildSealedFrame(outer, make([]byte, HPKEP256EncSize), make([]byte, HPKEAEADTagSize+1))
	uri, _ := EncodeArtifactURI(encoded)
	qr, _ := EncodeQRChunks(encoded, 97)
	operations := map[string]struct {
		run func()
		err func() error
	}{
		"profile": {func() { _, _ = DecodeCanonicalProfileV1(encoded) }, func() error { _, err := DecodeCanonicalProfileV1([]byte{0xff}); return err }},
		"signed":  {func() { _, _ = ParseSignedProfileOpaque(signed) }, func() error { _, err := ParseSignedProfileOpaque([]byte{0xff}); return err }},
		"sealed":  {func() { _, _ = ParseSealedProfileOpaque(sealed) }, func() error { _, err := ParseSealedProfileOpaque([]byte{0xff}); return err }},
		"uri": {func() { _, _ = NormalizeProfileIngress(ProfileIngress{Kind: IngressURI, Text: uri}) }, func() error {
			_, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressURI, Text: "kurd://artifact/="})
			return err
		}},
		"qr": {func() { _, _ = NormalizeProfileIngress(ProfileIngress{Kind: IngressQRChunks, Chunks: qr}) }, func() error {
			_, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressQRChunks, Chunks: []string{"KURD1/01/1/AQ"}})
			return err
		}},
	}
	var report struct {
		Schema      string `json:"schema"`
		HostAlias   string `json:"host_alias"`
		RawEvidence string `json:"raw_evidence"`
		RawSHA256   string `json:"raw_sha256"`
		Stages      []struct {
			Name                    string `json:"name"`
			WallTimeCeilingMS       int    `json:"wall_time_ceiling_ms"`
			AllocationCeiling       int    `json:"allocation_ceiling"`
			ErrorOutputCeilingBytes int    `json:"error_output_ceiling_bytes"`
			TimeoutCeilingMS        int    `json:"timeout_ceiling_ms"`
			ObservedWallUS          int    `json:"observed_wall_us"`
			ObservedAllocations     int    `json:"observed_allocations"`
			ObservedErrorBytes      int    `json:"observed_error_bytes"`
			ObservedTimeoutWallUS   int    `json:"observed_timeout_wall_us"`
			CompletedBeforeTimeout  bool   `json:"completed_before_timeout"`
		} `json:"stages"`
	}
	loadJSON(t, filepath.Join("testdata", "phase8-codec", "reference-host-resource-report.json"), &report)
	if report.Schema != "kurdistan.phase8.reference-host-resource-report.v3" || report.HostAlias != "reference-windows-amd64" || report.RawEvidence != "reference-host-resource-raw.json" || len(report.Stages) != len(operations) || hostAliasContainsLocalIdentity(report.HostAlias) {
		t.Fatalf("unsafe report identity: %+v", report)
	}
	rawPath := filepath.Join("testdata", "phase8-codec", report.RawEvidence)
	if report.RawSHA256 != fileSHA256(t, rawPath) {
		t.Fatal("resource report raw-evidence SHA drift")
	}
	var raw struct {
		Schema        string          `json:"schema"`
		HostAlias     string          `json:"host_alias"`
		Command       string          `json:"command"`
		GoVersion     string          `json:"go_version"`
		GOOS          string          `json:"goos"`
		GOARCH        string          `json:"goarch"`
		CapturedAtUTC string          `json:"captured_at_utc"`
		SourceSHA256  string          `json:"source_sha256"`
		FixtureSHA256 string          `json:"fixture_sha256"`
		Iterations    int             `json:"iterations"`
		Privacy       map[string]bool `json:"privacy"`
		Stages        []struct {
			Name                   string `json:"name"`
			ObservedWallUS         int    `json:"observed_wall_us"`
			ObservedAllocations    int    `json:"observed_allocations"`
			ObservedErrorBytes     int    `json:"observed_error_bytes"`
			ObservedTimeoutWallUS  int    `json:"observed_timeout_wall_us"`
			CompletedBeforeTimeout bool   `json:"completed_before_timeout"`
		}
	}
	loadJSON(t, rawPath, &raw)
	if raw.Schema != "kurdistan.phase8.reference-host-resource-raw.v1" || raw.HostAlias != report.HostAlias || raw.Command != "go run ./internal/testkit/phase8resourcecapture -out internal/product/envelope/testdata/phase8-codec" || raw.GoVersion != runtime.Version() || raw.GOOS != "windows" || raw.GOARCH != "amd64" || raw.Iterations != 1000 || len(raw.Stages) != len(report.Stages) {
		t.Fatalf("invalid raw resource provenance: %+v", raw)
	}
	if _, err := time.Parse(time.RFC3339, raw.CapturedAtUTC); err != nil {
		t.Fatalf("invalid capture time: %v", err)
	}
	if raw.SourceSHA256 != fileSHA256(t, filepath.Join("..", "..", "testkit", "phase8resourcecapture", "main.go")) || raw.FixtureSHA256 != fileSHA256(t, filepath.Join("testdata", "phase8-codec", "canonical-profile-v1.hex")) {
		t.Fatal("resource capture source/fixture binding drift")
	}
	for field, recorded := range raw.Privacy {
		if recorded {
			t.Fatalf("raw resource evidence recorded private field %s", field)
		}
	}
	rawByName := make(map[string]struct {
		wall, allocations, errorBytes, timeoutWall int
		completed                                  bool
	}, len(raw.Stages))
	for _, stage := range raw.Stages {
		rawByName[stage.Name] = struct {
			wall, allocations, errorBytes, timeoutWall int
			completed                                  bool
		}{stage.ObservedWallUS, stage.ObservedAllocations, stage.ObservedErrorBytes, stage.ObservedTimeoutWallUS, stage.CompletedBeforeTimeout}
	}
	for _, stage := range report.Stages {
		op, ok := operations[stage.Name]
		rawStage, rawOK := rawByName[stage.Name]
		if !ok || !rawOK || stage.WallTimeCeilingMS <= 0 || stage.AllocationCeiling <= 0 || stage.ErrorOutputCeilingBytes <= 0 || stage.TimeoutCeilingMS < stage.WallTimeCeilingMS || stage.ObservedWallUS <= 0 || stage.ObservedAllocations < 0 || stage.ObservedErrorBytes <= 0 || stage.ObservedTimeoutWallUS <= 0 || !stage.CompletedBeforeTimeout || rawStage != (struct {
			wall, allocations, errorBytes, timeoutWall int
			completed                                  bool
		}{stage.ObservedWallUS, stage.ObservedAllocations, stage.ObservedErrorBytes, stage.ObservedTimeoutWallUS, stage.CompletedBeforeTimeout}) {
			t.Fatalf("invalid stage row: %+v", stage)
		}
		start := time.Now()
		allocations := testing.AllocsPerRun(100, op.run)
		elapsed := time.Since(start)
		parseErr := op.err()
		if elapsed > time.Duration(stage.WallTimeCeilingMS)*time.Millisecond || int(allocations) > stage.AllocationCeiling || parseErr == nil || len(parseErr.Error()) > stage.ErrorOutputCeilingBytes || stage.ObservedWallUS > stage.WallTimeCeilingMS*1000 || stage.ObservedAllocations > stage.AllocationCeiling || stage.ObservedErrorBytes > stage.ErrorOutputCeilingBytes || stage.ObservedTimeoutWallUS > stage.TimeoutCeilingMS*1000 {
			t.Fatalf("stage %s wall=%v allocations=%f err=%v row=%+v", stage.Name, elapsed, allocations, parseErr, stage)
		}
		delete(operations, stage.Name)
	}
	if len(operations) != 0 || runtime.GOOS == "" || runtime.GOARCH == "" {
		t.Fatalf("missing stages=%v", operations)
	}
}

func TestWO803FuzzTranscript(t *testing.T) {
	var transcript struct {
		Schema        string `json:"schema"`
		HostAlias     string `json:"host_alias"`
		GoVersion     string `json:"go_version"`
		CapturedAtUTC string `json:"captured_at_utc"`
		Boundaries    []struct {
			Name                string `json:"name"`
			Command             string `json:"command"`
			RawTranscript       string `json:"raw_transcript"`
			RawSHA256           string `json:"raw_sha256"`
			SourceSHA256        string `json:"source_sha256"`
			FixtureSHA256       string `json:"fixture_sha256"`
			ObservedFuzzSeconds int    `json:"observed_fuzz_seconds"`
			Executions          int    `json:"executions"`
			Result              string `json:"result"`
		}
		Privacy map[string]bool
	}
	loadJSON(t, filepath.Join("testdata", "phase8-codec", "fuzz-transcript.json"), &transcript)
	if transcript.Schema != "kurdistan.phase8.codec-fuzz-transcript.v2" || transcript.HostAlias != "reference-windows-amd64" || len(transcript.Boundaries) != 5 {
		t.Fatalf("invalid fuzz transcript identity: %+v", transcript)
	}
	if transcript.GoVersion != runtime.Version() {
		t.Fatalf("fuzz transcript Go version %q != runtime %q", transcript.GoVersion, runtime.Version())
	}
	if _, err := time.Parse(time.RFC3339, transcript.CapturedAtUTC); err != nil {
		t.Fatalf("invalid fuzz transcript UTC timestamp: %v", err)
	}
	sourceHash := fileSHA256(t, "phase8_profile_codec_fuzz_test.go")
	fixtureHash := fileSHA256(t, filepath.Join("testdata", "phase8-codec", "canonical-profile-v1.hex"))
	for _, boundary := range transcript.Boundaries {
		if boundary.Name == "" || !strings.Contains(boundary.Command, "-fuzz '^"+boundary.Name+"$'") || !strings.Contains(boundary.Command, "-fuzztime 60s") || boundary.ObservedFuzzSeconds < 60 || boundary.Executions <= 0 || boundary.Result != "pass" {
			t.Fatalf("invalid fuzz boundary: %+v", boundary)
		}
		if boundary.SourceSHA256 != sourceHash || boundary.FixtureSHA256 != fixtureHash {
			t.Fatalf("fuzz source/fixture binding drift for %s", boundary.Name)
		}
		rawPath := filepath.Join("testdata", "phase8-codec", boundary.RawTranscript)
		raw, err := os.ReadFile(rawPath)
		if err != nil {
			t.Fatal(err)
		}
		if boundary.RawTranscript == "" || bytes.Contains(raw, []byte{'\r'}) || boundary.RawSHA256 != fmt.Sprintf("%x", sha256.Sum256(raw)) {
			t.Fatalf("raw fuzz transcript binding drift for %s", boundary.Name)
		}
	}
	for field, recorded := range transcript.Privacy {
		if recorded {
			t.Fatalf("fuzz transcript recorded private field %s", field)
		}
	}
}

func TestReferenceHostAliasPrivacyCheckIgnoresEmptyEnvironmentValues(t *testing.T) {
	t.Setenv("USERNAME", "")
	t.Setenv("USER", "")
	if hostAliasContainsLocalIdentity("reference-windows-amd64") {
		t.Fatal("empty identity environment values matched every host alias")
	}
	t.Setenv("USER", "reference-windows")
	if !hostAliasContainsLocalIdentity("reference-windows-amd64") {
		t.Fatal("non-empty local identity was not detected in host alias")
	}
}

func hostAliasContainsLocalIdentity(alias string) bool {
	alias = strings.ToLower(alias)
	for _, name := range []string{"USERNAME", "USER"} {
		identity := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
		if identity != "" && strings.Contains(alias, identity) {
			return true
		}
	}
	return false
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func loadJSON(t *testing.T, path string, destination any) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, destination); err != nil {
		t.Fatal(err)
	}
}
func reverseStrings(values []string) []string {
	out := append([]string(nil), values...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func TestCanonicalPositiveFixture(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("testdata", "phase8-codec", "canonical-profile-v1.hex"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(content)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("canonical fixture drift; run documented generator")
	}
}

func TestLegacyMetadataCannotPromoteThroughIngress(t *testing.T) {
	_, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressClipboard, Text: "kurd://legacy?exp=1&rev=r&compat=v&seal=s"})
	if !IngressErrorIs(err, IngressLegacyUntrusted) {
		t.Fatalf("legacy ingress err=%v", err)
	}
	if !errors.Is(PromoteLegacyEnvelope(Envelope{}), ErrLegacyEnvelopeNotPromotable) {
		t.Fatal("legacy promotion sentinel drift")
	}
}
