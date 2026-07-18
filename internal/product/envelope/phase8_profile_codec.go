// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

const (
	CanonicalProfileVersion     uint64 = 1
	MaxCanonicalIDBytes                = 128
	MaxCanonicalMembers                = 256
	MaxCanonicalPolicyBytes            = 64 << 10
	MaxCanonicalGeneration      uint64 = 1<<32 - 1
	MaxCanonicalSafetyFloor     uint64 = 1<<16 - 1
	MaxCanonicalRootEpoch       uint64 = 1<<32 - 1
	MaxCanonicalRevocationEpoch uint64 = 1<<32 - 1
	canonicalProfileFieldCount         = 20

	// CanonicalProfileV1CDDL is the normative equivalent schema for the
	// deterministic inner profile. Policy is a deterministic, non-empty CBOR
	// map carried as an embedded CBOR byte string so its exact bytes survive
	// issuer signing and verification.
	CanonicalProfileV1CDDL = `canonical-profile-v1 = {
  1: 1,
  2: id, 3: id, 4: id, 5: id,
  6: id, 7: id, 8: id, 9: id,
  10: uint, 11: uint,
  12: int, 13: int,
  14: uint, 15: uint,
  16: tstr, 17: tstr,
  18: [1*256 id], 19: [1*256 id],
  20: bstr .cbor policy-map
}
id = tstr .size (1..128)
policy-map = { 1*128 uint => any }
`
)

type CodecErrorCategory string

const (
	CodecInvalidValue       CodecErrorCategory = "invalid-value"
	CodecSizeLimit          CodecErrorCategory = "size-limit"
	CodecNonCanonical       CodecErrorCategory = "non-canonical"
	CodecSchema             CodecErrorCategory = "schema"
	CodecUnsupportedVersion CodecErrorCategory = "unsupported-version"
	CodecMemberOrder        CodecErrorCategory = "member-order"
	CodecSignedObject       CodecErrorCategory = "signed-object"
	CodecSealedFrame        CodecErrorCategory = "sealed-frame"
)

type CodecError struct {
	Category CodecErrorCategory
	Detail   string
}

func (e *CodecError) Error() string { return "envelope codec: " + string(e.Category) + ": " + e.Detail }

func codecError(category CodecErrorCategory, detail string) error {
	return &CodecError{Category: category, Detail: detail}
}

func CodecErrorIs(err error, category CodecErrorCategory) bool {
	var target *CodecError
	return errors.As(err, &target) && target.Category == category
}

// CanonicalProfileV1 is the complete deterministic inner profile snapshot.
// DecodeCanonicalProfileV1 is intentionally separate from signed-object parsing:
// callers must preserve and verify ParsedSignedProfile.Payload before decoding it.
type CanonicalProfileV1 struct {
	ContentID, ProfileID, LineageID, ProviderID string
	ContractVersion, RevocationScope            string
	SnapshotMode, UpdateKind                    string
	Generation, RequiredSafetyFloor             uint64
	ValidFrom, ValidUntil                       int64
	RootEpoch, RevocationEpoch                  uint64
	PreviousContentID, PreviousProviderID       string
	RelayIDs, StrategyIDs                       []string
	Policy                                      []byte
}

func EncodeCanonicalProfileV1(profile CanonicalProfileV1) ([]byte, error) {
	if err := validateCanonicalProfileV1(profile); err != nil {
		return nil, err
	}
	return marshalDeterministicBounded(map[uint64]any{
		1: CanonicalProfileVersion, 2: profile.ContentID, 3: profile.ProfileID,
		4: profile.LineageID, 5: profile.ProviderID, 6: profile.ContractVersion,
		7: profile.RevocationScope, 8: profile.SnapshotMode, 9: profile.UpdateKind,
		10: profile.Generation, 11: profile.RequiredSafetyFloor, 12: profile.ValidFrom,
		13: profile.ValidUntil, 14: profile.RootEpoch, 15: profile.RevocationEpoch,
		16: profile.PreviousContentID, 17: profile.PreviousProviderID,
		18: append([]string(nil), profile.RelayIDs...), 19: append([]string(nil), profile.StrategyIDs...),
		20: append([]byte(nil), profile.Policy...),
	}, MaxPayloadBytes, "canonical profile")
}

func DecodeCanonicalProfileV1(encoded []byte) (CanonicalProfileV1, error) {
	if len(encoded) == 0 || len(encoded) > MaxPayloadBytes {
		return CanonicalProfileV1{}, codecError(CodecSizeLimit, "canonical profile bytes")
	}
	if err := ValidateCoreDeterministicCBOR(encoded); err != nil {
		return CanonicalProfileV1{}, codecError(CodecNonCanonical, err.Error())
	}
	var fields map[uint64]cbor.RawMessage
	if err := unmarshalStrict(encoded, &fields); err != nil || len(fields) != canonicalProfileFieldCount {
		return CanonicalProfileV1{}, codecError(CodecSchema, "canonical profile map")
	}
	for label := uint64(1); label <= canonicalProfileFieldCount; label++ {
		if _, ok := fields[label]; !ok {
			return CanonicalProfileV1{}, codecError(CodecSchema, fmt.Sprintf("missing field %d", label))
		}
	}
	var version uint64
	var profile CanonicalProfileV1
	values := []any{&version, &profile.ContentID, &profile.ProfileID, &profile.LineageID, &profile.ProviderID,
		&profile.ContractVersion, &profile.RevocationScope, &profile.SnapshotMode, &profile.UpdateKind,
		&profile.Generation, &profile.RequiredSafetyFloor, &profile.ValidFrom, &profile.ValidUntil,
		&profile.RootEpoch, &profile.RevocationEpoch, &profile.PreviousContentID, &profile.PreviousProviderID,
		&profile.RelayIDs, &profile.StrategyIDs, &profile.Policy}
	for i, destination := range values {
		if err := unmarshalStrict(fields[uint64(i+1)], destination); err != nil {
			return CanonicalProfileV1{}, codecError(CodecSchema, fmt.Sprintf("field %d type", i+1))
		}
	}
	if version != CanonicalProfileVersion {
		return CanonicalProfileV1{}, codecError(CodecUnsupportedVersion, fmt.Sprintf("profile version %d", version))
	}
	if err := validateCanonicalProfileV1(profile); err != nil {
		return CanonicalProfileV1{}, err
	}
	reencoded, err := EncodeCanonicalProfileV1(profile)
	if err != nil {
		return CanonicalProfileV1{}, err
	}
	if !bytes.Equal(encoded, reencoded) {
		return CanonicalProfileV1{}, codecError(CodecNonCanonical, "profile round-trip changed bytes")
	}
	return profile, nil
}

func validateCanonicalProfileV1(profile CanonicalProfileV1) error {
	for name, value := range map[string]string{
		"content_id": profile.ContentID, "profile_id": profile.ProfileID, "lineage_id": profile.LineageID,
		"provider_id": profile.ProviderID, "contract_version": profile.ContractVersion,
		"revocation_scope": profile.RevocationScope, "snapshot_mode": profile.SnapshotMode, "update_kind": profile.UpdateKind,
	} {
		if !canonicalID(value, false) {
			return codecError(CodecInvalidValue, name)
		}
	}
	for name, value := range map[string]string{"previous_content_id": profile.PreviousContentID, "previous_provider_id": profile.PreviousProviderID} {
		if !canonicalID(value, true) {
			return codecError(CodecInvalidValue, name)
		}
	}
	if profile.Generation == 0 || profile.Generation > MaxCanonicalGeneration ||
		profile.RequiredSafetyFloor == 0 || profile.RequiredSafetyFloor > MaxCanonicalSafetyFloor ||
		profile.RootEpoch == 0 || profile.RootEpoch > MaxCanonicalRootEpoch ||
		profile.RevocationEpoch == 0 || profile.RevocationEpoch > MaxCanonicalRevocationEpoch ||
		profile.ValidFrom <= 0 || profile.ValidUntil <= profile.ValidFrom {
		return codecError(CodecInvalidValue, "epochs or validity")
	}
	if len(profile.Policy) == 0 || len(profile.Policy) > MaxCanonicalPolicyBytes {
		return codecError(CodecSizeLimit, "policy")
	}
	if err := validateCanonicalPolicy(profile.Policy); err != nil {
		return err
	}
	if err := validateCanonicalMembers("relay", profile.RelayIDs); err != nil {
		return err
	}
	return validateCanonicalMembers("strategy", profile.StrategyIDs)
}

func validateCanonicalPolicy(policy []byte) error {
	if err := ValidateCoreDeterministicCBOR(policy); err != nil {
		return codecError(CodecNonCanonical, "policy: "+err.Error())
	}
	var fields map[uint64]cbor.RawMessage
	if err := unmarshalStrict(policy, &fields); err != nil || len(fields) == 0 {
		return codecError(CodecSchema, "policy map")
	}
	var decoded any
	if err := unmarshalStrict(policy, &decoded); err != nil {
		return codecError(CodecSchema, "policy value")
	}
	if policyContainsTag(decoded) {
		return codecError(CodecSchema, "policy tags are not admitted")
	}
	return nil
}

func policyContainsTag(value any) bool {
	switch value := value.(type) {
	case cbor.Tag:
		return true
	case []any:
		for _, item := range value {
			if policyContainsTag(item) {
				return true
			}
		}
	case map[any]any:
		for key, item := range value {
			if policyContainsTag(key) || policyContainsTag(item) {
				return true
			}
		}
	}
	return false
}

func canonicalID(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	if value != strings.TrimSpace(value) || len(value) > MaxCanonicalIDBytes {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r == '.' || r == ':' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validateCanonicalMembers(label string, members []string) error {
	if len(members) == 0 || len(members) > MaxCanonicalMembers {
		return codecError(CodecSizeLimit, label+" member count")
	}
	for i, member := range members {
		if !canonicalID(member, false) {
			return codecError(CodecInvalidValue, label+" member")
		}
		if i > 0 && members[i-1] >= member {
			return codecError(CodecMemberOrder, label+" members must be unique and sorted")
		}
	}
	return nil
}

// ParsedSignedProfile preserves the exact received object and exact payload.
// Parsing performs no signature verification and no semantic payload decoding.
type ParsedSignedProfile struct {
	ExactObject, Protected, Payload, Signature []byte
}

func ParseSignedProfileOpaque(encoded []byte) (ParsedSignedProfile, error) {
	if len(encoded) == 0 || len(encoded) > MaxSignedObjectBytes {
		return ParsedSignedProfile{}, codecError(CodecSizeLimit, "signed object")
	}
	if err := ValidateCoreDeterministicCBOR(encoded); err != nil {
		return ParsedSignedProfile{}, codecError(CodecNonCanonical, err.Error())
	}
	var tagged cbor.RawTag
	if err := unmarshalStrict(encoded, &tagged); err != nil || tagged.Number != COSESign1Tag {
		return ParsedSignedProfile{}, codecError(CodecSignedObject, "tag")
	}
	if !hasCBORMajorType(tagged.Content, 4) {
		return ParsedSignedProfile{}, codecError(CodecSignedObject, "tag content must be a direct array")
	}
	var fields []cbor.RawMessage
	if err := unmarshalStrict(tagged.Content, &fields); err != nil || len(fields) != 4 {
		return ParsedSignedProfile{}, codecError(CodecSignedObject, "array arity")
	}
	// COSE_Sign1 permits one tag, the outer tag 18.  Each direct array member
	// must use its untagged CBOR major type so an alternative tagged spelling
	// cannot authenticate the same signed bytes under a different artifact.
	if !hasCBORMajorType(fields[0], 2) || !hasCBORMajorType(fields[1], 5) || !hasCBORMajorType(fields[2], 2) || !hasCBORMajorType(fields[3], 2) {
		return ParsedSignedProfile{}, codecError(CodecSignedObject, "tagged or invalid direct field")
	}
	var protected, payload, signature []byte
	var unprotected map[int64]cbor.RawMessage
	if err := unmarshalStrict(fields[0], &protected); err != nil || len(protected) == 0 || len(protected) > MaxSignedProtectedBytes {
		return ParsedSignedProfile{}, codecError(CodecSignedObject, "protected headers")
	}
	if err := unmarshalStrict(fields[1], &unprotected); err != nil || len(unprotected) != 0 {
		return ParsedSignedProfile{}, codecError(CodecSignedObject, "unprotected headers")
	}
	if err := unmarshalStrict(fields[2], &payload); err != nil || len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return ParsedSignedProfile{}, codecError(CodecSizeLimit, "signed payload")
	}
	if err := unmarshalStrict(fields[3], &signature); err != nil || len(signature) != ES256RawSignatureSize {
		return ParsedSignedProfile{}, codecError(CodecSignedObject, "signature encoding")
	}
	if _, _, err := DecodeRawES256Signature(signature); err != nil {
		return ParsedSignedProfile{}, codecError(CodecSignedObject, "signature encoding")
	}
	if _, err := signedMetadataBytes(protected); err != nil {
		return ParsedSignedProfile{}, codecError(CodecSignedObject, err.Error())
	}
	return ParsedSignedProfile{ExactObject: bytes.Clone(encoded), Protected: bytes.Clone(protected), Payload: bytes.Clone(payload), Signature: bytes.Clone(signature)}, nil
}

func hasCBORMajorType(encoded []byte, majorType byte) bool {
	return len(encoded) != 0 && encoded[0]>>5 == majorType
}

type ParsedSealedProfile struct {
	ExactFrame, Protected, Encapsulation, Ciphertext []byte
}

func ParseSealedProfileOpaque(encoded []byte) (ParsedSealedProfile, error) {
	if len(encoded) == 0 || len(encoded) > MaxSealedFrameBytes {
		return ParsedSealedProfile{}, codecError(CodecSizeLimit, "sealed frame")
	}
	if err := ValidateCoreDeterministicCBOR(encoded); err != nil {
		return ParsedSealedProfile{}, codecError(CodecNonCanonical, err.Error())
	}
	if !hasCBORMajorType(encoded, 4) {
		return ParsedSealedProfile{}, codecError(CodecSealedFrame, "frame must be an untagged direct array")
	}
	var fields []cbor.RawMessage
	if err := unmarshalStrict(encoded, &fields); err != nil || len(fields) != 3 {
		return ParsedSealedProfile{}, codecError(CodecSealedFrame, "array arity")
	}
	for _, field := range fields {
		if !hasCBORMajorType(field, 2) {
			return ParsedSealedProfile{}, codecError(CodecSealedFrame, "tagged or invalid direct field")
		}
	}
	var protected, enc, ciphertext []byte
	if err := unmarshalStrict(fields[0], &protected); err != nil || len(protected) == 0 || len(protected) > MaxOuterProtectedBytes {
		return ParsedSealedProfile{}, codecError(CodecSealedFrame, "protected metadata")
	}
	if err := unmarshalStrict(fields[1], &enc); err != nil || len(enc) != HPKEP256EncSize {
		return ParsedSealedProfile{}, codecError(CodecSealedFrame, "encapsulation")
	}
	if err := unmarshalStrict(fields[2], &ciphertext); err != nil || len(ciphertext) <= HPKEAEADTagSize || len(ciphertext) > MaxCiphertextBytes {
		return ParsedSealedProfile{}, codecError(CodecSizeLimit, "ciphertext")
	}
	if _, err := outerMetadataBytes(protected); err != nil {
		return ParsedSealedProfile{}, codecError(CodecSealedFrame, err.Error())
	}
	return ParsedSealedProfile{ExactFrame: bytes.Clone(encoded), Protected: bytes.Clone(protected), Encapsulation: bytes.Clone(enc), Ciphertext: bytes.Clone(ciphertext)}, nil
}
