// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"bytes"
	"runtime"
	"testing"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
)

// Dropping a direct-type/size gate or returning an input alias breaks these tests.
func TestResourcePreflightEnvelopeExtraction(t *testing.T) {
	profile := canonicalFixtureProfile()
	payload, err := EncodeCanonicalProfileV1(profile)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := PreflightCanonicalProfileResourcesV1(payload)
	if err != nil || !bytes.Equal(policy, []byte{0xa1, 1, 0xf5}) {
		t.Fatalf("policy: %v", err)
	}
	policy[0] = 0
	if bytes.Contains(payload, []byte{0, 1, 0xf5}) {
		t.Fatal("policy aliases input")
	}
	protected, _ := BuildSignedProtectedHeaders([]byte("phase8-key-id"), fixtureDeviceMetadata())
	signed, _ := marshalDeterministic(cbor.Tag{Number: 18, Content: []any{protected, map[int64]any{}, payload, make([]byte, 64)}})
	got, err := PreflightSignedProfileResourcesV1(signed)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("signed extraction: %v", err)
	}
	got[0] ^= 1
	if bytes.Equal(got, payload) {
		t.Fatal("payload mutation failed")
	}
	// Scalar signature validity is deliberately left to the original parser.
	if _, err := ParseSignedProfileOpaque(signed); err == nil {
		t.Fatal("zero scalar became valid")
	}
	outer, _ := BuildSealProtected(fixtureDeviceMetadata())
	if err := PreflightSealProtectedResourcesV1(outer); err != nil {
		t.Fatal(err)
	}
	sealed, _ := BuildSealedFrame(outer, make([]byte, 65), make([]byte, 17))
	if err := PreflightSealedProfileResourcesV1(sealed); err != nil {
		t.Fatal(err)
	}
	tagOnly, _ := marshalDeterministic([]any{outer, make([]byte, 65), make([]byte, 16)})
	if err := PreflightSealedProfileResourcesV1(tagOnly); err != nil {
		t.Fatalf("bounded tag-only ciphertext: %v", err)
	}
	if _, err := ParseSealedProfileOpaque(tagOnly); err == nil {
		t.Fatal("resource admission conferred sealed-frame validity")
	}
}

type resourceMeasurementV1 struct {
	InputBytes, TypedLeafBytes, TypedMetadataBytes      uint64
	ReturnedBytes, CanonicalOutputBytes, PeakOwnedBytes uint64
	AllocBytes, AllocObjects                            uint64
}

func TestResourcePreflightEnvelopeCapacityInventory(t *testing.T) {
	for _, count := range []int{256, 2048} {
		p := canonicalFixtureProfile()
		p.RelayIDs = make([]string, count)
		for i := range p.RelayIDs {
			p.RelayIDs[i] = "relay.0001"
		}
		encoded, _ := marshalDeterministic(canonicalProfileMap(p))
		typed, err := decodeCanonicalProfileFieldsV1(encoded, true)
		if err != nil {
			t.Fatal(err)
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		policy, preflightErr := PreflightCanonicalProfileResourcesV1(encoded)
		runtime.ReadMemStats(&after)
		if (count == 256) != (preflightErr == nil) {
			t.Fatalf("cardinality outcome: %v", preflightErr)
		}
		m := resourceMeasurementV1{InputBytes: uint64(len(encoded)), TypedLeafBytes: uint64(cap(typed.Policy)), TypedMetadataBytes: uint64(unsafe.Sizeof(typed)) + uint64(cap(typed.RelayIDs)+cap(typed.StrategyIDs))*uint64(unsafe.Sizeof(string(""))), ReturnedBytes: uint64(cap(policy)), AllocBytes: after.TotalAlloc - before.TotalAlloc, AllocObjects: after.Mallocs - before.Mallocs}
		for _, values := range [][]string{typed.RelayIDs, typed.StrategyIDs} {
			for _, v := range values {
				m.TypedLeafBytes += uint64(len(v))
			}
		}
		for _, v := range [...]string{typed.ContentID, typed.ProfileID, typed.LineageID, typed.ProviderID, typed.ContractVersion, typed.RevocationScope, typed.SnapshotMode, typed.UpdateKind, typed.PreviousContentID, typed.PreviousProviderID} {
			m.TypedLeafBytes += uint64(len(v))
		}
		// This subtotal is observed named backing, not allocator/map overhead or RSS.
		m.PeakOwnedBytes = m.TypedLeafBytes + m.TypedMetadataBytes + m.ReturnedBytes
		t.Logf("%s/%s list=%d first-measured-after-fixture=%+v map-header=%d raw-header=%d", runtime.Version(), runtime.GOARCH, count, m, unsafe.Sizeof(map[uint64]cbor.RawMessage{}), unsafe.Sizeof(cbor.RawMessage{}))
		clear(policy)
		clear(typed.Policy)
	}
}

func TestResourcePreflightMaximumEnvelopeLeaves(t *testing.T) {
	protected, err := BuildSignedProtectedHeaders([]byte("phase8-key-id"), fixtureDeviceMetadata())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := marshalDeterministic(cbor.Tag{Number: 18, Content: []any{protected, map[int64]any{}, make([]byte, MaxPayloadBytes), make([]byte, 64)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []string{"first-measured-after-fixture", "warm"} {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		payload, err := PreflightSignedProfileResourcesV1(encoded)
		runtime.ReadMemStats(&after)
		if err != nil || len(payload) != MaxPayloadBytes {
			t.Fatalf("maximum payload: %v", err)
		}
		if _, err := PreflightCanonicalProfileResourcesV1(payload); err == nil {
			t.Fatal("malformed maximum plaintext admitted as profile")
		}
		t.Logf("%s signed-input=%d returned-payload-cap=%d alloc-bytes=%d alloc-objects=%d", condition, len(encoded), cap(payload), after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs)
		clear(payload)
	}
	// Resource-only preflight may admit a nonminimal spelling; legacy canonical
	// validation remains mandatory and rejects the identical immutable bytes.
	canonical, _ := EncodeCanonicalProfileV1(canonicalFixtureProfile())
	noncanonical := append([]byte{canonical[0], 1, 0x18, 1}, canonical[3:]...)
	policy, err := PreflightCanonicalProfileResourcesV1(noncanonical)
	if err != nil {
		t.Fatal(err)
	}
	clear(policy)
	if _, err := DecodeCanonicalProfileV1(noncanonical); err == nil {
		t.Fatal("resource preflight replaced canonical validation")
	}
}

func TestResourcePreflightEnvelopeRejectsUnboundedShape(t *testing.T) {
	for _, value := range []any{nil, ""} {
		fields := canonicalProfileMap(canonicalFixtureProfile())
		fields[2] = value
		encoded, _ := marshalDeterministic(fields)
		if _, err := PreflightCanonicalProfileResourcesV1(encoded); err == nil {
			t.Fatal("missing required identifier admitted")
		}
	}
	for _, field := range []uint64{2, 18, 20} {
		fields := canonicalProfileMap(canonicalFixtureProfile())
		switch field {
		case 2:
			fields[field] = string(bytes.Repeat([]byte{'x'}, 129))
		case 18:
			fields[field] = make([]string, 257)
		case 20:
			fields[field] = make([]byte, 65537)
		}
		encoded, _ := marshalDeterministic(fields)
		if _, err := PreflightCanonicalProfileResourcesV1(encoded); err == nil {
			t.Fatalf("oversized field %d admitted", field)
		}
	}
	fields := canonicalProfileMap(canonicalFixtureProfile())
	fields[2] = cbor.Tag{Number: 18, Content: "content.0001"}
	encoded, _ := marshalDeterministic(fields)
	if _, err := PreflightCanonicalProfileResourcesV1(encoded); err == nil {
		t.Fatal("tagged profile field admitted")
	}
	outer, _ := BuildSealProtected(fixtureDeviceMetadata())
	for _, value := range []any{
		[]any{outer, make([]byte, 65)},
		[]any{outer, make([]byte, 64), make([]byte, 17)},
		[]any{cbor.Tag{Number: 18, Content: outer}, make([]byte, 65), make([]byte, 17)},
	} {
		encoded, _ := marshalDeterministic(value)
		if err := PreflightSealedProfileResourcesV1(encoded); err == nil {
			t.Fatal("invalid sealed shape admitted")
		}
	}
	metadata, _ := marshalDeterministic(map[uint64]any{1: "device-recipient", 2: "provisioned-device", 3: cbor.Tag{Number: 18, Content: []byte("hint")}, 4: uint64(1)})
	badHeader, _ := marshalDeterministic(map[uint64]any{1: uint64(1), 2: uint64(1), 3: SignedObjectContentType, 4: metadata})
	if err := PreflightSealProtectedResourcesV1(badHeader); err == nil {
		t.Fatal("tagged nested metadata admitted")
	}
}

// Removing a direct byte-string gate must reject neither as a valid resource
// leaf nor by silently converting the original array into different bytes.
func TestResourcePreflightEnvelopeRejectsByteArrayCoercion(t *testing.T) {
	toArray := func(value []byte) []uint64 {
		out := make([]uint64, len(value))
		for i, b := range value {
			out[i] = uint64(b)
		}
		return out
	}
	p := canonicalFixtureProfile()
	fields := canonicalProfileMap(p)
	fields[20] = toArray(p.Policy)
	encoded, _ := marshalDeterministic(fields)
	if _, err := PreflightCanonicalProfileResourcesV1(encoded); err == nil {
		t.Error("array policy admitted as byte leaf")
	}
	protected, _ := BuildSignedProtectedHeaders([]byte("phase8-key-id"), fixtureDeviceMetadata())
	var headers map[int64]cbor.RawMessage
	if err := unmarshalStrict(protected, &headers); err != nil {
		t.Fatal(err)
	}
	headers[COSEHeaderKeyID], _ = marshalDeterministic(toArray([]byte("phase8-key-id")))
	badHeader, _ := marshalDeterministic(headers)
	payload, _ := EncodeCanonicalProfileV1(p)
	signed, _ := marshalDeterministic(cbor.Tag{Number: 18, Content: []any{badHeader, map[int64]any{}, payload, make([]byte, 64)}})
	if _, err := PreflightSignedProfileResourcesV1(signed); err == nil {
		t.Error("array signed key ID admitted as byte leaf")
	}
	outer, _ := BuildSealProtected(fixtureDeviceMetadata())
	var outerFields map[uint64]cbor.RawMessage
	if err := unmarshalStrict(outer, &outerFields); err != nil {
		t.Fatal(err)
	}
	var metadataBytes []byte
	if err := unmarshalStrict(outerFields[4], &metadataBytes); err != nil {
		t.Fatal(err)
	}
	var metadata map[uint64]cbor.RawMessage
	if err := unmarshalStrict(metadataBytes, &metadata); err != nil {
		t.Fatal(err)
	}
	var hint []byte
	if err := unmarshalStrict(metadata[3], &hint); err != nil {
		t.Fatal(err)
	}
	metadata[3], _ = marshalDeterministic(toArray(hint))
	metadataBytes, _ = marshalDeterministic(metadata)
	outerFields[4], _ = marshalDeterministic(metadataBytes)
	badOuter, _ := marshalDeterministic(outerFields)
	if err := PreflightSealProtectedResourcesV1(badOuter); err == nil {
		t.Error("array metadata hint admitted as byte leaf")
	}
}
