// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

const transcriptDomain = "kurdistan-transcript-v1"

type transcriptKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type canonicalTranscript struct {
	Version             string         `json:"version"`
	Domain              string         `json:"domain"`
	ProfileID           string         `json:"profile_id"`
	ProfileHash         string         `json:"profile_hash"`
	CompilerHash        string         `json:"compiler_hash"`
	SemanticMappingHash string         `json:"semantic_mapping_hash"`
	FSMPolicy           string         `json:"fsm_policy"`
	FramingPolicy       string         `json:"framing_policy"`
	SchedulerPolicy     string         `json:"scheduler_policy"`
	PaddingPolicy       string         `json:"padding_policy"`
	StreamPolicy        string         `json:"stream_policy"`
	ProxyPolicy         string         `json:"proxy_policy"`
	CarrierPolicy       string         `json:"carrier_policy"`
	Capabilities        []string       `json:"capabilities"`
	SessionNonceHex     string         `json:"session_nonce_hex"`
	Suite               Suite          `json:"suite"`
	OrderedStatePath    []string       `json:"ordered_state_path,omitempty"`
	Additional          []transcriptKV `json:"additional_policy_data,omitempty"`
}

func CanonicalTranscript(input TranscriptInput) ([]byte, error) {
	if input.ProfileID == "" || input.ProfileHash == "" || len(input.SessionNonce) == 0 {
		return nil, fmt.Errorf("%w: missing profile, hash, or nonce", ErrInvalidTranscript)
	}
	caps, err := canonicalCapabilities(input.Capabilities)
	if err != nil {
		return nil, err
	}
	additional := make([]transcriptKV, 0, len(input.AdditionalPolicyData))
	keys := make([]string, 0, len(input.AdditionalPolicyData))
	for key := range input.AdditionalPolicyData {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		additional = append(additional, transcriptKV{Key: key, Value: input.AdditionalPolicyData[key]})
	}
	c := canonicalTranscript{
		Version:             Version,
		Domain:              transcriptDomain,
		ProfileID:           input.ProfileID,
		ProfileHash:         input.ProfileHash,
		CompilerHash:        input.CompilerHash,
		SemanticMappingHash: input.SemanticMappingHash,
		FSMPolicy:           input.FSMPolicy,
		FramingPolicy:       input.FramingPolicy,
		SchedulerPolicy:     input.SchedulerPolicy,
		PaddingPolicy:       input.PaddingPolicy,
		StreamPolicy:        input.StreamPolicy,
		ProxyPolicy:         input.ProxyPolicy,
		CarrierPolicy:       input.CarrierPolicy,
		Capabilities:        caps,
		SessionNonceHex:     hex.EncodeToString(input.SessionNonce),
		Suite:               input.Suite,
		OrderedStatePath:    append([]string(nil), input.OrderedStatePath...),
		Additional:          additional,
	}
	return json.Marshal(c)
}

func TranscriptHash(input TranscriptInput) (string, error) {
	raw, err := CanonicalTranscript(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func hashStrings(parts ...string) (string, error) {
	raw, err := json.Marshal(parts)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
