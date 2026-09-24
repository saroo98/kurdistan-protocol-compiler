// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimepolicy

import (
	"bytes"
	"crypto/sha256"
	"time"

	"github.com/fxamacker/cbor/v2"
	"kurdistan/internal/product/envelope"
)

const SchemaVersionV3 uint64 = 3

func EncodeV3(p PolicyV2) ([]byte, error)       { return EncodeV3At(p, time.Now()) }
func DecodeV3(encoded []byte) (PolicyV2, error) { return DecodeV3At(encoded, time.Now()) }
func ValidateV3(p PolicyV2) error               { return ValidateV3At(p, time.Now()) }
func RelayAdmissionDigestV3(p PolicyV2) ([32]byte, error) {
	return RelayAdmissionDigestV3At(p, time.Now())
}

func EncodeV3At(p PolicyV2, now time.Time) ([]byte, error) {
	return encodeV3AtDiagnostic(p, now, nil)
}

func encodeV3AtDiagnostic(p PolicyV2, now time.Time, diagnostic *RuntimeDiagnostic) ([]byte, error) {
	if err := validateV3AtDiagnostic(p, now, diagnostic); err != nil {
		return nil, err
	}
	return marshalPolicyV3(p, true)
}

func DecodeV3At(encoded []byte, now time.Time) (PolicyV2, error) {
	return decodeV3AtDiagnostic(encoded, now, nil)
}

func decodeV3AtDiagnostic(encoded []byte, now time.Time, diagnostic *RuntimeDiagnostic) (PolicyV2, error) {
	if len(encoded) == 0 || len(encoded) > MaxEncodedBytes {
		return PolicyV2{}, fail(ErrorSize)
	}
	if validateCore(encoded) != nil {
		return PolicyV2{}, fail(ErrorNonCanonical)
	}
	fields, err := rawMap(encoded, 26)
	if err != nil {
		return PolicyV2{}, err
	}
	var p PolicyV2
	if err := decodePolicy(fields, &p); err != nil {
		return PolicyV2{}, err
	}
	if p.Services, err = decodeServices(fields[26]); err != nil {
		return PolicyV2{}, err
	}
	reencoded, err := encodeV3AtDiagnostic(p, now, diagnostic)
	if err != nil {
		return PolicyV2{}, err
	}
	if !bytes.Equal(encoded, reencoded) {
		return PolicyV2{}, fail(ErrorNonCanonical)
	}
	return p.Clone(), nil
}

func ValidateV3At(p PolicyV2, now time.Time) error {
	return validateV3AtDiagnostic(p, now, nil)
}

func validateV3AtDiagnostic(p PolicyV2, now time.Time, diagnostic *RuntimeDiagnostic) error {
	if err := validatePolicyV3AtDiagnostic(p, now, diagnostic); err != nil {
		return err
	}
	encoded, err := marshalPolicyV3(p, false)
	if err != nil {
		return err
	}
	if sha256.Sum256(encoded) != p.RelayAdmissionDigest {
		return fail(ErrorBinding)
	}
	return nil
}

func RelayAdmissionDigestV3At(p PolicyV2, now time.Time) ([32]byte, error) {
	if err := validatePolicyV3At(p, now); err != nil {
		return [32]byte{}, err
	}
	encoded, err := marshalPolicyV3(p, false)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func validatePolicyV3At(p PolicyV2, now time.Time) error {
	return validatePolicyV3AtDiagnostic(p, now, nil)
}

func validatePolicyV3AtDiagnostic(p PolicyV2, now time.Time, diagnostic *RuntimeDiagnostic) error {
	if p.SchemaVersion != SchemaVersionV3 || p.Services == nil {
		return fail(ErrorInvalid)
	}
	if err := validateCommonPolicyAtDiagnostic(p, now, diagnostic); err != nil {
		return err
	}
	if err := validateServices(p.Services, len(p.ClientIPv4) > 0, len(p.ClientIPv6) > 0); err != nil {
		return err
	}
	program, err := validateLiveProgram(p.LiveProgram, p.LiveProgramSHA256)
	if err != nil {
		return err
	}
	// The verified model has exactly one bidirectional data message. Select by
	// semantic so this gate never confuses a padding limit with data authority.
	found := false
	for _, message := range program.Messages {
		if message.Semantic == "data" {
			found = true
			if message.MinPayloadBytes > 8 || min(program.Limits.MaxPayloadBytes, message.MaxPayloadBytes) < max(272, int(p.MTU)) {
				return fail(ErrorInvalid)
			}
		}
	}
	if !found {
		return fail(ErrorInvalid)
	}
	// Digest issuance and validation also enforce the full policy size, including
	// the 32-byte digest that the admission preimage deliberately omits.
	_, err = marshalPolicyV3(p, true)
	return err
}

func marshalPolicyV3(p PolicyV2, includeDigest bool) ([]byte, error) {
	m := policyMap(p, includeDigest)
	// V2 historically emits null for absent optional address slices. V3 has no
	// null representation: retain byte-string types with canonical empty bstr.
	for _, label := range []uint64{14, 15, 16, 17} {
		if b, ok := m[label].([]byte); ok && len(b) == 0 {
			m[label] = []byte{}
		}
	}
	m[26] = servicesMap(p.Services)
	encoded, err := marshal(m)
	if err != nil {
		return nil, fail(ErrorNonCanonical)
	}
	if len(encoded) > MaxEncodedBytes {
		return nil, fail(ErrorSize)
	}
	return encoded, nil
}

// Runtime entry points select exactly one strict version. Unknown versions
// never fall back to another decoder or reinterpret signed authority.
func EncodeRuntimeAt(p PolicyV2, now time.Time) ([]byte, error) {
	switch p.SchemaVersion {
	case SchemaVersionV2:
		return EncodeV2At(p, now)
	case SchemaVersionV3:
		return EncodeV3At(p, now)
	default:
		return nil, fail(ErrorSchema)
	}
}

func DecodeRuntimeAt(encoded []byte, now time.Time) (PolicyV2, error) {
	return decodeRuntimeAtDiagnostic(encoded, now, nil)
}

// RuntimeDiagnostic reports only the first actual TLS-time predicate failure.
// It grants no authentication or authority and retains no input data.
type RuntimeDiagnostic uint8

const (
	RuntimeDiagnosticNone            RuntimeDiagnostic = 0
	RuntimeDiagnosticTLSValidityTime RuntimeDiagnostic = 1
)

func DecodeRuntimeAtWithDiagnostic(encoded []byte, now time.Time) (PolicyV2, RuntimeDiagnostic, error) {
	var diagnostic RuntimeDiagnostic
	p, err := decodeRuntimeAtDiagnostic(encoded, now, &diagnostic)
	return p, diagnostic, err
}

func decodeRuntimeAtDiagnostic(encoded []byte, now time.Time, diagnostic *RuntimeDiagnostic) (PolicyV2, error) {
	if len(encoded) == 0 || len(encoded) > MaxEncodedBytes {
		return PolicyV2{}, fail(ErrorSize)
	}
	if validateCore(encoded) != nil {
		return PolicyV2{}, fail(ErrorNonCanonical)
	}
	var fields map[uint64]cbor.RawMessage
	if decode(encoded, &fields) != nil || len(fields) < 1 || len(fields) > 26 {
		return PolicyV2{}, fail(ErrorSchema)
	}
	var version uint64
	if serviceField(fields[1], &version) != nil {
		return PolicyV2{}, fail(ErrorSchema)
	}
	switch version {
	case SchemaVersionV2:
		return decodeV2AtDiagnostic(encoded, now, diagnostic)
	case SchemaVersionV3:
		return decodeV3AtDiagnostic(encoded, now, diagnostic)
	default:
		return PolicyV2{}, fail(ErrorSchema)
	}
}

func ValidateRuntimeAt(p PolicyV2, now time.Time) error {
	switch p.SchemaVersion {
	case SchemaVersionV2:
		return ValidateV2At(p, now)
	case SchemaVersionV3:
		return ValidateV3At(p, now)
	default:
		return fail(ErrorSchema)
	}
}

func RelayAdmissionDigestRuntimeAt(p PolicyV2, now time.Time) ([32]byte, error) {
	switch p.SchemaVersion {
	case SchemaVersionV2:
		return RelayAdmissionDigestV2At(p, now)
	case SchemaVersionV3:
		return RelayAdmissionDigestV3At(p, now)
	default:
		return [32]byte{}, fail(ErrorSchema)
	}
}

func ValidateRuntimeAgainstEnvelopeAt(p PolicyV2, profile envelope.CanonicalProfileV1, now time.Time) error {
	encoded, err := EncodeRuntimeAt(p, now)
	if err != nil || !bytes.Equal(encoded, profile.Policy) {
		return fail(ErrorBinding)
	}
	if p.Services != nil && p.Services.Update != nil && p.Services.Update.ProfileID != profile.ProfileID {
		return fail(ErrorBinding)
	}
	return nil
}
