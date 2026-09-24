// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import "github.com/fxamacker/cbor/v2"

func clearResourceMapV1[K comparable](fields map[K]cbor.RawMessage) {
	for _, field := range fields {
		clear(field)
	}
}

func clearResourceArrayV1(fields []cbor.RawMessage) {
	for _, field := range fields {
		clear(field)
	}
}

// Resource preflights admit only bounded typed shape. They confer no canonical,
// signature, recipient, policy, time, or lifecycle authority.
func unmarshalResourceV1(encoded []byte, destination any) error {
	if len(encoded) == 0 || encoded[0] == 0xf6 || encoded[0] == 0xf7 {
		return codecError(CodecSchema, "null resource field")
	}
	// Concrete []byte decoding also accepts integer arrays. Admit the original
	// wire type before the maintained decoder can coerce a structured value.
	var major byte
	switch destination.(type) {
	case *[]byte:
		major = 2
	case *string:
		major = 3
	case *uint64:
		major = 0
	case *int64:
		if encoded[0]>>5 > 1 {
			return codecError(CodecSchema, "resource integer type")
		}
		major = encoded[0] >> 5
	case *[]string, *[]int64, *[]cbor.RawMessage:
		major = 4
	case *map[uint64]cbor.RawMessage, *map[int64]cbor.RawMessage:
		major = 5
	default:
		return codecError(CodecSchema, "resource destination type")
	}
	if encoded[0]>>5 != major {
		return codecError(CodecSchema, "resource direct type")
	}
	mode, err := (cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxNestedLevels: MaxCBORNestedLevels,
		MaxArrayElements: MaxCBORArrayElements, MaxMapPairs: MaxCBORMapPairs,
		IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden,
		IntDec: cbor.IntDecConvertNone, UTF8: cbor.UTF8RejectInvalid,
	}).DecMode()
	if err != nil {
		return err
	}
	return mode.Unmarshal(encoded, destination)
}

func PreflightSealedProfileResourcesV1(encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > MaxSealedFrameBytes {
		return codecError(CodecSizeLimit, "sealed frame")
	}
	fields, err := decodeSealedProfileFieldsV1(encoded, true)
	defer clear(fields.Protected)
	defer clear(fields.Encapsulation)
	defer clear(fields.Ciphertext)
	if err != nil {
		return err
	}
	return PreflightSealProtectedResourcesV1(fields.Protected)
}

func PreflightSealProtectedResourcesV1(protected []byte) error {
	metadata, err := outerMetadataBytesWithResources(protected, true)
	clear(metadata)
	return err
}

// PreflightSignedProfileResourcesV1 returns an owned payload field, not a proof.
// The caller must clear it when its next typed preflight has finished.
func PreflightSignedProfileResourcesV1(encoded []byte) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > MaxSignedObjectBytes {
		return nil, codecError(CodecSizeLimit, "signed object")
	}
	fields, err := decodeSignedProfileFieldsV1(encoded, true)
	defer clear(fields.Protected)
	defer clear(fields.Signature)
	if err != nil {
		clear(fields.Payload)
		return nil, err
	}
	metadata, err := signedMetadataBytesWithResources(fields.Protected, true)
	clear(metadata)
	if err != nil {
		clear(fields.Payload)
		return nil, err
	}
	return fields.Payload, nil
}

// PreflightCanonicalProfileResourcesV1 returns the owned policy byte field.
// Embedded policy is intentionally opaque here; runtimepolicy must preflight it
// before a caller enters the legacy generic canonical/profile validators.
func PreflightCanonicalProfileResourcesV1(encoded []byte) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > MaxPayloadBytes {
		return nil, codecError(CodecSizeLimit, "canonical profile bytes")
	}
	p, err := decodeCanonicalProfileFieldsV1(encoded, true)
	if err != nil {
		clear(p.Policy)
		return nil, err
	}
	good := false
	defer func() {
		if !good {
			clear(p.Policy)
		}
	}()
	for i, value := range [...]string{p.ContentID, p.ProfileID, p.LineageID, p.ProviderID, p.ContractVersion, p.RevocationScope, p.SnapshotMode, p.UpdateKind, p.PreviousContentID, p.PreviousProviderID} {
		if len(value) > MaxCanonicalIDBytes || i < 8 && len(value) == 0 {
			return nil, codecError(CodecSizeLimit, "profile identifier")
		}
	}
	if p.Generation == 0 || p.Generation > MaxCanonicalGeneration || p.RequiredSafetyFloor == 0 || p.RequiredSafetyFloor > MaxCanonicalSafetyFloor || p.RootEpoch == 0 || p.RootEpoch > MaxCanonicalRootEpoch || p.RevocationEpoch == 0 || p.RevocationEpoch > MaxCanonicalRevocationEpoch || p.ValidFrom <= 0 || p.ValidUntil <= p.ValidFrom {
		return nil, codecError(CodecInvalidValue, "epochs or validity")
	}
	for _, members := range [][]string{p.RelayIDs, p.StrategyIDs} {
		if len(members) == 0 || len(members) > MaxCanonicalMembers {
			return nil, codecError(CodecSizeLimit, "profile members")
		}
		for _, member := range members {
			if len(member) == 0 || len(member) > MaxCanonicalIDBytes {
				return nil, codecError(CodecSizeLimit, "profile member")
			}
		}
	}
	if len(p.Policy) == 0 || len(p.Policy) > MaxCanonicalPolicyBytes {
		return nil, codecError(CodecSizeLimit, "policy")
	}
	good = true
	return p.Policy, nil
}
