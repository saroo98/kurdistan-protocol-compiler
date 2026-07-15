// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"kurdistan/internal/protocol/ir"
)

const (
	HandshakeVersionV1      = "kurdistan-handshake-v1"
	PolicyEncodingVersionV1 = "policy-v1"
	RecordVersionV1         = "record-v1"
	Version                 = ir.SupportedSecurityVersion

	SuiteKDFHKDFSHA256      = "kdf_hkdf_sha256"
	SuiteAEADAES256GCM      = "aead_aes_256_gcm"
	SuiteMACHMACSHA256      = "mac_hmac_sha256"
	SuiteTranscriptSHA256V1 = "transcript_sha256_v1"
)

type SecurityContext struct {
	ProfileID      string `json:"profile_id"`
	ProfileHash    string `json:"profile_hash"`
	SessionID      string `json:"session_id"`
	TranscriptHash string `json:"transcript_hash"`
	CapabilityHash string `json:"capability_hash"`
	CarrierBinding string `json:"carrier_binding"`
	StreamBinding  string `json:"stream_binding"`
	ProxyBinding   string `json:"proxy_binding"`
	Suite          Suite  `json:"suite"`
}

type Suite struct {
	KDF        string `json:"kdf"`
	AEAD       string `json:"aead"`
	MAC        string `json:"mac"`
	Transcript string `json:"transcript"`
}

var ErrInvalidContextIdentity = errors.New("invalid security context identity")

type ContextIdentityField string

const (
	ContextIdentityProfileID      ContextIdentityField = "profile_id"
	ContextIdentityProfileHash    ContextIdentityField = "profile_hash"
	ContextIdentitySessionID      ContextIdentityField = "session_id"
	ContextIdentityTranscriptHash ContextIdentityField = "transcript_hash"
	ContextIdentityCapabilityHash ContextIdentityField = "capability_hash"
	ContextIdentityCarrier        ContextIdentityField = "carrier_binding"
	ContextIdentityStream         ContextIdentityField = "stream_binding"
	ContextIdentityProxy          ContextIdentityField = "proxy_binding"
	ContextIdentitySuite          ContextIdentityField = "suite"
	ContextIdentityDirection      ContextIdentityField = "direction"
	ContextIdentitySemantic       ContextIdentityField = "semantic"
)

type ContextIdentityError struct {
	Field  ContextIdentityField
	Reason string
}

func (e *ContextIdentityError) Error() string {
	return fmt.Sprintf("invalid security context identity: %s %s", e.Field, e.Reason)
}

func (e *ContextIdentityError) Unwrap() error {
	return ErrInvalidContextIdentity
}

func contextIdentityError(field ContextIdentityField, reason string) error {
	return &ContextIdentityError{Field: field, Reason: reason}
}

type TranscriptInput struct {
	ProfileID            string            `json:"profile_id"`
	ProfileHash          string            `json:"profile_hash"`
	CompilerHash         string            `json:"compiler_hash"`
	SemanticMappingHash  string            `json:"semantic_mapping_hash"`
	FSMPolicy            string            `json:"fsm_policy"`
	FramingPolicy        string            `json:"framing_policy"`
	SchedulerPolicy      string            `json:"scheduler_policy"`
	PaddingPolicy        string            `json:"padding_policy"`
	StreamPolicy         string            `json:"stream_policy"`
	ProxyPolicy          string            `json:"proxy_policy"`
	CarrierPolicy        string            `json:"carrier_policy"`
	Capabilities         []string          `json:"capabilities"`
	SessionNonce         []byte            `json:"session_nonce"`
	Suite                Suite             `json:"suite"`
	OrderedStatePath     []string          `json:"ordered_state_path,omitempty"`
	AdditionalPolicyData map[string]string `json:"additional_policy_data,omitempty"`
}

func DefaultSuite() Suite {
	return Suite{
		KDF:        SuiteKDFHKDFSHA256,
		AEAD:       SuiteAEADAES256GCM,
		MAC:        SuiteMACHMACSHA256,
		Transcript: SuiteTranscriptSHA256V1,
	}
}

func SuiteSupported(s Suite) bool {
	return s == DefaultSuite()
}

func ProfileHash(p *ir.Profile) (string, error) {
	return ir.CanonicalHash(p)
}

func BuildContext(input TranscriptInput) (SecurityContext, error) {
	if err := validateIdentityText(ContextIdentityProfileID, input.ProfileID); err != nil {
		return SecurityContext{}, err
	}
	if err := validateHashIdentity(ContextIdentityProfileHash, input.ProfileHash); err != nil {
		return SecurityContext{}, err
	}
	for _, identity := range []struct {
		field ContextIdentityField
		value string
	}{
		{ContextIdentityCarrier, input.CarrierPolicy},
		{ContextIdentityStream, input.StreamPolicy},
		{ContextIdentityProxy, input.ProxyPolicy},
	} {
		if err := validateIdentityText(identity.field, identity.value); err != nil {
			return SecurityContext{}, err
		}
	}
	if !SuiteSupported(input.Suite) {
		return SecurityContext{}, contextIdentityError(ContextIdentitySuite, "unknown")
	}
	transcriptHash, err := TranscriptHash(input)
	if err != nil {
		return SecurityContext{}, err
	}
	capabilityHash, err := (CapabilitySet{Features: input.Capabilities}).Hash()
	if err != nil {
		return SecurityContext{}, err
	}
	ctx := SecurityContext{
		ProfileID:      input.ProfileID,
		ProfileHash:    input.ProfileHash,
		TranscriptHash: transcriptHash,
		CapabilityHash: capabilityHash,
		CarrierBinding: input.CarrierPolicy,
		StreamBinding:  input.StreamPolicy,
		ProxyBinding:   input.ProxyPolicy,
		Suite:          input.Suite,
	}
	sessionID, err := contextSessionID(ctx)
	if err != nil {
		return SecurityContext{}, err
	}
	ctx.SessionID = sessionID
	if err := ValidateContextIdentity(ctx); err != nil {
		return SecurityContext{}, err
	}
	return ctx, nil
}

func ValidateContextIdentity(ctx SecurityContext) error {
	if err := validateIdentityText(ContextIdentityProfileID, ctx.ProfileID); err != nil {
		return err
	}
	for _, identity := range []struct {
		field ContextIdentityField
		value string
	}{
		{ContextIdentityProfileHash, ctx.ProfileHash},
		{ContextIdentitySessionID, ctx.SessionID},
		{ContextIdentityTranscriptHash, ctx.TranscriptHash},
		{ContextIdentityCapabilityHash, ctx.CapabilityHash},
	} {
		if err := validateHashIdentity(identity.field, identity.value); err != nil {
			return err
		}
	}
	for _, identity := range []struct {
		field ContextIdentityField
		value string
	}{
		{ContextIdentityCarrier, ctx.CarrierBinding},
		{ContextIdentityStream, ctx.StreamBinding},
		{ContextIdentityProxy, ctx.ProxyBinding},
	} {
		if err := validateIdentityText(identity.field, identity.value); err != nil {
			return err
		}
	}
	if !SuiteSupported(ctx.Suite) {
		return contextIdentityError(ContextIdentitySuite, "unknown")
	}
	want, err := contextSessionID(ctx)
	if err != nil {
		return contextIdentityError(ContextIdentitySessionID, "unavailable")
	}
	if !identityEqual(ctx.SessionID, want) {
		return contextIdentityError(ContextIdentitySessionID, "inconsistent")
	}
	return nil
}

func contextSessionID(ctx SecurityContext) (string, error) {
	return hashStrings(
		"kurdistan-session-v1",
		ctx.ProfileID,
		ctx.ProfileHash,
		ctx.TranscriptHash,
		ctx.CapabilityHash,
		ctx.CarrierBinding,
		ctx.StreamBinding,
		ctx.ProxyBinding,
		ctx.Suite.KDF,
		ctx.Suite.AEAD,
		ctx.Suite.MAC,
		ctx.Suite.Transcript,
	)
}

func validateHashIdentity(field ContextIdentityField, value string) error {
	if value == "" {
		return contextIdentityError(field, "empty")
	}
	if len(value) != 64 {
		return contextIdentityError(field, "wrong_length")
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return contextIdentityError(field, "malformed")
	}
	canonical := hex.EncodeToString(raw)
	if !identityEqual(value, canonical) {
		return contextIdentityError(field, "malformed")
	}
	var nonzero byte
	for _, b := range raw {
		nonzero |= b
	}
	if nonzero == 0 {
		return contextIdentityError(field, "all_zero")
	}
	return nil
}

func validateIdentityText(field ContextIdentityField, value string) error {
	if value == "" {
		return contextIdentityError(field, "empty")
	}
	if len(value) > 512 {
		return contextIdentityError(field, "wrong_length")
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return contextIdentityError(field, "malformed")
		}
	}
	return nil
}

func identityEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
