// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"kurdistan/internal/protocol/ir"
)

const transcriptDomain = "kurdistan-transcript-v1"

const (
	TranscriptCanonicalV1      = "canonical_v1"
	TranscriptCapabilitiesV1   = "canonical_with_capabilities_v1"
	TranscriptCarrierBindingV1 = "canonical_with_carrier_binding_v1"
	TranscriptFullBindingV1    = "canonical_full_binding_v1"
)

// HandshakeModeBinding is profile-derived metadata committed by the
// authenticated profile hash. It is canonicalized locally before a handshake;
// it is not an extra, unversioned wire field in kurdistan-handshake-v1.
type HandshakeModeBinding struct {
	ClientOptional         []string
	ServerOptional         []string
	FeatureVectors         []string
	CarrierFamily          string
	CarrierPolicyHash      [32]byte
	EnvelopeLimit          uint32
	MaxFrameBytes          uint32
	LocalAdapterClass      string
	FramingPolicyHash      [32]byte
	StateMachinePolicyHash [32]byte
	SchedulerPolicyHash    [32]byte
	PaddingPolicyHash      [32]byte
	StreamPolicyHash       [32]byte
	ProxyPolicyHash        [32]byte
	CarrierContextHash     [32]byte
	CompatibilityBlock     CompatibilityBlockV1
	CompatibilityBlockHash [32]byte
	LimitBlock             LimitBlockV1
	LimitBlockHash         [32]byte
	ConfigSourceBlock      ConfigSourceBlockV1
	ConfigSourceBlockHash  [32]byte
}

// CanonicalHandshakeModeBinding implements the four frozen local ModeBindingV1
// validation shapes. Its fields are derived from data committed by the signed
// profile hash and/or signed offer/floor bytes. The returned local bytes are not
// serialized or appended to TH2, TH3, TH4, confirmation, or KDF inputs.
func CanonicalHandshakeModeBinding(mode string, binding HandshakeModeBinding) ([]byte, error) {
	var out bytes.Buffer
	writeLP(&out, []byte("kurdistan/transcript/v1/"+mode))
	writeCapabilities := func() error {
		if len(binding.FeatureVectors) == 0 {
			return fmt.Errorf("%w: missing compatibility feature vectors", ErrInvalidTranscript)
		}
		for _, values := range [][]string{binding.ClientOptional, binding.ServerOptional, binding.FeatureVectors} {
			raw, err := EncodeStringListV1(values)
			if err != nil {
				return err
			}
			writeLP(&out, raw)
		}
		return nil
	}
	writeCarrier := func() error {
		if err := validateASCII(binding.CarrierFamily); err != nil {
			return err
		}
		if err := validateASCII(binding.LocalAdapterClass); err != nil {
			return err
		}
		knownCarrier := knownCarrierFamilyV1(binding.CarrierFamily)
		knownAdapter := false
		for _, adapter := range []string{"one_flow_one_stream", "priority_mapped_stream", "metadata_bound_stream", "state_derived_mapping"} {
			knownAdapter = knownAdapter || binding.LocalAdapterClass == adapter
		}
		if !knownCarrier || !knownAdapter || allZero32(binding.CarrierPolicyHash) || binding.EnvelopeLimit == 0 || binding.MaxFrameBytes == 0 || binding.EnvelopeLimit > binding.MaxFrameBytes || binding.MaxFrameBytes > 1<<20 {
			return fmt.Errorf("%w: invalid carrier binding", ErrInvalidTranscript)
		}
		writeLP(&out, []byte(binding.CarrierFamily))
		out.Write(binding.CarrierPolicyHash[:])
		writeU32(&out, binding.EnvelopeLimit)
		writeLP(&out, []byte(binding.LocalAdapterClass))
		return nil
	}
	switch mode {
	case TranscriptCanonicalV1:
		// The mandatory Hello core is the complete binding for this mode.
	case TranscriptCapabilitiesV1:
		if err := writeCapabilities(); err != nil {
			return nil, err
		}
	case TranscriptCarrierBindingV1:
		if err := writeCarrier(); err != nil {
			return nil, err
		}
	case TranscriptFullBindingV1:
		if err := writeCapabilities(); err != nil {
			return nil, err
		}
		if err := writeCarrier(); err != nil {
			return nil, err
		}
		for _, value := range [][32]byte{
			binding.FramingPolicyHash,
			binding.StateMachinePolicyHash,
			binding.SchedulerPolicyHash,
			binding.PaddingPolicyHash,
			binding.StreamPolicyHash,
			binding.ProxyPolicyHash,
			binding.CarrierContextHash,
		} {
			if allZero32(value) {
				return nil, fmt.Errorf("%w: invalid full binding", ErrInvalidTranscript)
			}
			out.Write(value[:])
		}
	default:
		return nil, fmt.Errorf("%w: unknown transcript mode", ErrInvalidTranscript)
	}
	return out.Bytes(), nil
}

func knownCarrierFamilyV1(value string) bool {
	return value == "tls13-tcp" || slices.Contains(ir.CarrierFamilies(), value)
}

// EncodePolicyV1 returns the exact frozen PolicyV1 field order.
func EncodePolicyV1(policy ir.EffectiveSecurityPolicy) ([]byte, error) {
	if err := ir.ValidateEffectiveSecurityPolicy(policy); err != nil {
		return nil, fmt.Errorf("%w: invalid effective policy", ErrInvalidTranscript)
	}
	var out bytes.Buffer
	for _, value := range []string{
		policy.SecurityVersion,
		policy.TranscriptMode,
		policy.KDFSuite,
		policy.AEADSuite,
		policy.MACSuite,
		policy.NonceMode,
		policy.ReplayPolicy,
	} {
		writeLP(&out, []byte(value))
	}
	writeU32(&out, uint32(policy.ReplayWindowSize))
	for _, value := range []string{
		policy.DowngradePolicy,
		policy.CapabilityNegotiationPolicy,
		policy.ProfileCompatibilityPolicy,
		policy.KeyRotationPolicy,
		policy.ConfigValidationPolicy,
		policy.SecureEnvelopeMode,
	} {
		writeLP(&out, []byte(value))
	}
	var fixed [8]byte
	binary.BigEndian.PutUint64(fixed[:], uint64(policy.MaxSessionMessages))
	out.Write(fixed[:])
	binary.BigEndian.PutUint64(fixed[:], uint64(policy.MaxKeyLifetimeMessages))
	out.Write(fixed[:])
	return out.Bytes(), nil
}

// EncodeStringListV1 enforces unique ASCII items sorted by raw byte order.
func EncodeStringListV1(values []string) ([]byte, error) {
	canonical := append([]string(nil), values...)
	sort.Strings(canonical)
	for i, value := range canonical {
		if err := validateASCII(value); err != nil {
			return nil, err
		}
		if i > 0 && value == canonical[i-1] {
			return nil, fmt.Errorf("%w: duplicate list item", ErrInvalidTranscript)
		}
	}
	var out bytes.Buffer
	writeU32(&out, uint32(len(canonical)))
	for _, value := range canonical {
		writeLP(&out, []byte(value))
	}
	return out.Bytes(), nil
}

func writeLP(out *bytes.Buffer, value []byte) {
	writeU32(out, uint32(len(value)))
	out.Write(value)
}

func writeU32(out *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	out.Write(raw[:])
}

func validateASCII(value string) error {
	if value == "" {
		return fmt.Errorf("%w: empty canonical value", ErrInvalidTranscript)
	}
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7e {
			return fmt.Errorf("%w: non-ascii canonical value", ErrInvalidTranscript)
		}
	}
	return nil
}

func allZero32(value [32]byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

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
