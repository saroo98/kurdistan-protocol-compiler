// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"kurdistan/internal/ir"
)

const (
	Version = "0.12.0-lab"

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
	transcriptHash, err := TranscriptHash(input)
	if err != nil {
		return SecurityContext{}, err
	}
	capabilityHash, err := (CapabilitySet{Features: input.Capabilities}).Hash()
	if err != nil {
		return SecurityContext{}, err
	}
	sessionID, err := hashStrings("kurdistan-session-v1", input.ProfileID, transcriptHash, capabilityHash)
	if err != nil {
		return SecurityContext{}, err
	}
	return SecurityContext{
		ProfileID:      input.ProfileID,
		ProfileHash:    input.ProfileHash,
		SessionID:      sessionID,
		TranscriptHash: transcriptHash,
		CapabilityHash: capabilityHash,
		CarrierBinding: input.CarrierPolicy,
		StreamBinding:  input.StreamPolicy,
		ProxyBinding:   input.ProxyPolicy,
		Suite:          input.Suite,
	}, nil
}
