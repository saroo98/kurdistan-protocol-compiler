// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
)

const strictConfigHashDomainV1 = "kurdistan/runtime/v1/config-policy"

type advancedPolicyWitnessInventoryV1 struct {
	nonce, replay, profile, rotation, config, envelope map[string]string
}

// advancedPolicyWitnessesV1 is code-owned evidence routing, not mutable
// provisioning. Each value is backed by an owning runtime/security test.
func advancedPolicyWitnessesV1() advancedPolicyWitnessInventoryV1 {
	return advancedPolicyWitnessInventoryV1{
		nonce:    map[string]string{"counter_append_base": "internal/crypto/security/nonce_v1_test.go:TestNonceV1LegacyCharacterization", "counter_xor_base": "internal/crypto/security/nonce_v1_test.go:TestNonceV1LegacyCharacterization", "directional_counter": "internal/crypto/security/nonce_v1_test.go:TestNonceV1LegacyCharacterization", "stream_partitioned_counter": "internal/crypto/security/nonce_v1_test.go:TestNonceV1LegacyCharacterization"},
		replay:   map[string]string{"bounded_reorder": "internal/crypto/security/replay_v1_test.go:TestReplayV1LegacyCharacterization", "ordered_only": "internal/crypto/security/replay_v1_test.go:TestReplayV1LegacyCharacterization", "windowed_replay": "internal/crypto/security/replay_v1_test.go:TestReplayV1LegacyCharacterization"},
		profile:  map[string]string{"full_policy_binding": "internal/runtime/implementation_support_test.go:TestAdvancedPolicySupportFullPolicyBindingV1", "schema_and_feature": "internal/runtime/implementation_support_test.go:TestAdvancedPolicySupportSchemaAndFeatureV1", "strict_schema": "internal/runtime/implementation_support_test.go:TestProfileAuthorizationV1ProfileDeclaredRequiredAuthenticRetainedRequirementRejectsBeforeEntropy"},
		rotation: map[string]string{"message_lifetime_bound": "internal/runtime/lifecycle_test.go:TestLifetimeSessionOnlyAndSessionMessageLimitV1", "profile_lifetime_bound": "internal/runtime/lifecycle_test.go:TestProfileGenerationLifecycleCommitLinearizationV1", "session_only": "internal/runtime/lifecycle_test.go:TestLifetimeSessionOnlyAndSessionMessageLimitV1"},
		config:   map[string]string{"strict_profile_bound": "internal/runtime/config_v1_test.go:TestConfigValidationV1StrictProfileBound", "strict_required": "internal/runtime/config_v1_test.go:TestConfigValidationV1StrictProfileBound", "strict_with_redaction": "internal/runtime/config_v1_test.go:TestConfigValidationV1RedactionCertificate"},
		envelope: map[string]string{"full_context_bound_envelope": "internal/crypto/security/replay_policy_test.go:TestEnvelopeModeFullContextTamperV1", "metadata_authenticated": "internal/crypto/security/replay_policy_test.go:TestReplayPolicyAuthenticationBeforeLazyCommitV1", "synthetic_aead_test": "internal/crypto/security/envelope_v1_test.go:TestEnvelopeModeAndErrorPathV1"},
	}
}

// StrictSessionConfigV1 is the value-only configuration admitted after an
// authenticated strict handshake. ConfigPolicyHash commits every preceding
// field in the order declared here.
type StrictSessionConfigV1 struct {
	ProfileID              string
	ProfileHash            [32]byte
	SelectedSuite          security.SelectedSuiteV1
	EffectivePolicyHash    [32]byte
	SelectedCapabilityHash [32]byte
	ReplayWindowSize       uint32
	MaxSessionMessages     uint64
	MaxKeyLifetimeMessages uint64
	MaxConcurrentStreams   uint32
	MaxFrameBytes          uint32
	MaxEnvelopeBytes       uint32
	ConfigPolicyHash       [32]byte
}

// ClientStrictSessionConfigV1 and RelayStrictSessionConfigV1 are deliberately
// role-distinct opaque wrappers. They prevent accidental role substitution at
// the authenticated-pair boundary.
type ClientStrictSessionConfigV1 struct{ value StrictSessionConfigV1 }
type RelayStrictSessionConfigV1 struct{ value StrictSessionConfigV1 }

func NewClientStrictSessionConfigV1(value StrictSessionConfigV1) (ClientStrictSessionConfigV1, error) {
	if err := validateStrictSessionConfigV1(value); err != nil {
		return ClientStrictSessionConfigV1{}, err
	}
	return ClientStrictSessionConfigV1{value: value}, nil
}

func NewRelayStrictSessionConfigV1(value StrictSessionConfigV1) (RelayStrictSessionConfigV1, error) {
	if err := validateStrictSessionConfigV1(value); err != nil {
		return RelayStrictSessionConfigV1{}, err
	}
	return RelayStrictSessionConfigV1{value: value}, nil
}

// ConfigPolicyHashV1 returns the domain-separated hash of the strict config,
// excluding ConfigPolicyHash itself.
func ConfigPolicyHashV1(value StrictSessionConfigV1) ([32]byte, error) {
	raw, err := canonicalStrictSessionConfigV1(value)
	if err != nil {
		return [32]byte{}, err
	}
	var input bytes.Buffer
	writeStrictConfigLPV1(&input, []byte(strictConfigHashDomainV1))
	writeStrictConfigLPV1(&input, raw)
	return sha256.Sum256(input.Bytes()), nil
}

func validateStrictSessionConfigV1(value StrictSessionConfigV1) error {
	want, err := ConfigPolicyHashV1(value)
	if err != nil || want != value.ConfigPolicyHash {
		return ErrConfigInvalid
	}
	return nil
}

func canonicalStrictSessionConfigV1(value StrictSessionConfigV1) ([]byte, error) {
	if !validStrictRuntimeTextV1(value.ProfileID) || zeroStrictConfigHashV1(value.ProfileHash) ||
		zeroStrictConfigHashV1(value.EffectivePolicyHash) || zeroStrictConfigHashV1(value.SelectedCapabilityHash) ||
		value.ReplayWindowSize < 2 || value.ReplayWindowSize > 4096 ||
		value.MaxSessionMessages == 0 || value.MaxSessionMessages > 1<<24 ||
		value.MaxKeyLifetimeMessages == 0 || value.MaxKeyLifetimeMessages > value.MaxSessionMessages ||
		value.MaxConcurrentStreams == 0 || value.MaxConcurrentStreams > 65535 ||
		value.MaxFrameBytes == 0 || value.MaxFrameBytes > 1<<20 ||
		value.MaxEnvelopeBytes == 0 || value.MaxEnvelopeBytes > value.MaxFrameBytes {
		return nil, ErrConfigInvalid
	}
	suite, err := security.CanonicalSelectedSuiteV1(value.SelectedSuite)
	if err != nil {
		return nil, ErrConfigInvalid
	}
	var out bytes.Buffer
	writeStrictConfigLPV1(&out, []byte(value.ProfileID))
	out.Write(value.ProfileHash[:])
	writeStrictConfigLPV1(&out, suite)
	out.Write(value.EffectivePolicyHash[:])
	out.Write(value.SelectedCapabilityHash[:])
	writeStrictConfigU32V1(&out, value.ReplayWindowSize)
	writeStrictConfigU64V1(&out, value.MaxSessionMessages)
	writeStrictConfigU64V1(&out, value.MaxKeyLifetimeMessages)
	writeStrictConfigU32V1(&out, value.MaxConcurrentStreams)
	writeStrictConfigU32V1(&out, value.MaxFrameBytes)
	writeStrictConfigU32V1(&out, value.MaxEnvelopeBytes)
	return out.Bytes(), nil
}

func writeStrictConfigLPV1(out *bytes.Buffer, value []byte) {
	writeStrictConfigU32V1(out, uint32(len(value)))
	out.Write(value)
}

func writeStrictConfigU32V1(out *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	out.Write(raw[:])
}

func writeStrictConfigU64V1(out *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	out.Write(raw[:])
}

func validStrictRuntimeTextV1(value string) bool {
	if value == "" || uint64(len(value)) > uint64(^uint32(0)) {
		return false
	}
	for _, b := range []byte(value) {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

func zeroStrictConfigHashV1(value [32]byte) bool {
	var combined byte
	for _, b := range value {
		combined |= b
	}
	return combined == 0
}

type RuntimeConfig struct {
	Role             Role     `json:"role"`
	ProfilePath      string   `json:"profile_path,omitempty"`
	ProfileID        string   `json:"profile_id,omitempty"`
	ProfileHash      string   `json:"profile_hash,omitempty"`
	RuntimeID        string   `json:"runtime_id"`
	RequiredFeatures []string `json:"required_features,omitempty"`
	SecuritySecret   []byte   `json:"-"`
	MaxSessions      int      `json:"max_sessions"`
	MaxStreams       int      `json:"max_streams"`
	MaxEvents        int      `json:"max_events"`
	TraceEnabled     bool     `json:"trace_enabled"`
}

type PolicyBoundRuntimeConfig struct {
	config RuntimeConfig
	policy ir.EffectiveSecurityPolicy
}

func BindEffectivePolicy(cfg RuntimeConfig, policy ir.EffectiveSecurityPolicy) (PolicyBoundRuntimeConfig, error) {
	if err := ir.ValidateEffectiveSecurityPolicy(policy); err != nil {
		return PolicyBoundRuntimeConfig{}, fmt.Errorf("%w: effective policy", ErrInvalidConfig)
	}
	if cfg.ProfileID == "" {
		cfg.ProfileID = policy.ProfileID
	}
	if cfg.ProfileHash == "" {
		cfg.ProfileHash = policy.ProfileHash
	}
	if cfg.ProfileHash != policy.ProfileHash {
		return PolicyBoundRuntimeConfig{}, ErrInvalidConfig
	}
	bound := PolicyBoundRuntimeConfig{config: cloneRuntimeConfig(cfg), policy: policy.Clone()}
	if err := ValidatePolicyBoundConfig(bound); err != nil {
		return PolicyBoundRuntimeConfig{}, err
	}
	return bound, nil
}

func ValidatePolicyBoundConfig(bound PolicyBoundRuntimeConfig) error {
	if err := ValidateConfig(bound.config); err != nil {
		return err
	}
	if err := ir.ValidateEffectiveSecurityPolicy(bound.policy); err != nil {
		return fmt.Errorf("%w: effective policy", ErrInvalidConfig)
	}
	if bound.config.ProfileID != bound.policy.ProfileID {
		return fmt.Errorf("%w: effective policy profile", ErrInvalidConfig)
	}
	required := map[string]bool{}
	for _, capability := range bound.config.RequiredFeatures {
		required[capability] = true
	}
	for _, capability := range bound.policy.SelectedCapabilities {
		if !required[capability] {
			return fmt.Errorf("%w: effective policy capability", ErrInvalidConfig)
		}
	}
	return nil
}

func (c PolicyBoundRuntimeConfig) Config() RuntimeConfig {
	return cloneRuntimeConfig(c.config)
}

func (c PolicyBoundRuntimeConfig) EffectivePolicy() ir.EffectiveSecurityPolicy {
	return c.policy.Clone()
}

func cloneRuntimeConfig(cfg RuntimeConfig) RuntimeConfig {
	cfg.RequiredFeatures = append([]string(nil), cfg.RequiredFeatures...)
	cfg.SecuritySecret = append([]byte(nil), cfg.SecuritySecret...)
	return cfg
}

func DefaultConfig(role Role, runtimeID string, secret []byte) RuntimeConfig {
	// Legacy compatibility constructor: secret material is caller supplied and
	// validated; this is not a product identity, trust, or secret default.
	return RuntimeConfig{
		Role:             role,
		RuntimeID:        runtimeID,
		RequiredFeatures: security.DefaultCapabilities().Features,
		SecuritySecret:   append([]byte(nil), secret...),
		MaxSessions:      4,
		MaxStreams:       16,
		MaxEvents:        4096,
		TraceEnabled:     true,
	}
}

func ValidateConfig(cfg RuntimeConfig) error {
	if err := ValidateRole(cfg.Role); err != nil {
		return err
	}
	if cfg.RuntimeID == "" {
		return fmt.Errorf("%w: missing runtime id", ErrInvalidConfig)
	}
	if cfg.ProfileHash != "" && !validRuntimeProfileHashV1(cfg.ProfileHash) {
		return ErrInvalidConfig
	}
	if len(cfg.SecuritySecret) == 0 {
		return fmt.Errorf("%w: missing security secret", ErrInvalidConfig)
	}
	if bytes.Equal(cfg.SecuritySecret, make([]byte, len(cfg.SecuritySecret))) {
		return fmt.Errorf("%w: all-zero security secret", ErrInvalidConfig)
	}
	if cfg.MaxSessions <= 0 || cfg.MaxSessions > 64 {
		return fmt.Errorf("%w: max sessions", ErrInvalidConfig)
	}
	if cfg.MaxStreams <= 0 || cfg.MaxStreams > 256 {
		return fmt.Errorf("%w: max streams", ErrInvalidConfig)
	}
	if cfg.MaxEvents <= 0 || cfg.MaxEvents > 1<<20 {
		return fmt.Errorf("%w: max events", ErrInvalidConfig)
	}
	if len(cfg.RequiredFeatures) == 0 {
		return fmt.Errorf("%w: missing required features", ErrInvalidConfig)
	}
	if _, err := (security.CapabilitySet{Features: cfg.RequiredFeatures}).Hash(); err != nil {
		return err
	}
	return nil
}

func validRuntimeProfileHashV1(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	var combined byte
	for _, b := range raw {
		combined |= b
	}
	return combined != 0
}

func RedactConfig(cfg RuntimeConfig) map[string]any {
	return map[string]any{
		"role":              cfg.Role,
		"profile_path":      cfg.ProfilePath,
		"profile_id":        cfg.ProfileID,
		"profile_hash_set":  cfg.ProfileHash != "",
		"runtime_id":        cfg.RuntimeID,
		"required_features": append([]string(nil), cfg.RequiredFeatures...),
		"security_secret":   json.RawMessage(`"<redacted>"`),
		"max_sessions":      cfg.MaxSessions,
		"max_streams":       cfg.MaxStreams,
		"max_events":        cfg.MaxEvents,
		"trace_enabled":     cfg.TraceEnabled,
	}
}
