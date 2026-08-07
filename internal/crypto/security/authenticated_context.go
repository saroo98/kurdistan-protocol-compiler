// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"

	"kurdistan/internal/protocol/ir"
)

// CompatibilityBlockV1 retains the validated compatibility source committed
// by a profile. Lists must already be in strict raw-byte canonical order.
type CompatibilityBlockV1 struct {
	SchemaVersion            string
	CompilerSecurityVersion  string
	MinimumRuntimeVersion    string
	SupportedSecuritySuites  []string
	RequiredCapabilities     []string
	SupportedCarrierFamilies []string
	SupportedProxyFeatures   []string
	SupportedStreamFeatures  []string
	MaxEnvelopeBytes         uint32
	MaxStreamCount           uint32
	MaxReplayWindow          uint32
}

// LimitBlockV1 retains protocol, carrier, and stream limits from the same
// validated profile source.
type LimitBlockV1 struct {
	MaxFrameBytes               uint32
	MaxPayloadBytes             uint32
	MaxStates                   uint32
	MaxTransitions              uint32
	MaxSessionMillis            uint64
	CarrierMaxEnvelopeBytes     uint32
	CarrierMaxQueueDepth        uint32
	SessionMaxConcurrentStreams uint32
}

// SelectedSuiteV1 is deliberately distinct from Suite: transcript mode is
// committed by PolicyV1 and the authenticated mode-binding encoding.
type SelectedSuiteV1 struct {
	KDFSuite  string
	AEADSuite string
	MACSuite  string
}

// ConfigSourceBlockV1 retains the exact profile and policy source identities
// used to configure a peer.
type ConfigSourceBlockV1 struct {
	ProfileID              string
	ProfileHash            [32]byte
	SecurityVersion        string
	SelectedSuite          SelectedSuiteV1
	EffectivePolicyHash    [32]byte
	SelectedCapabilityHash [32]byte
	AdapterClass           string
	CompatibilityBlockHash [32]byte
	LimitBlockHash         [32]byte
}

// AuthenticatedContextHashInputV1 is a value-only input to ContextHashV1. It
// carries no provenance; only the auth package may establish provenance.
type AuthenticatedContextHashInputV1 struct {
	EffectivePolicy        ir.EffectiveSecurityPolicy
	EffectivePolicyHash    [32]byte
	TranscriptHash         [32]byte
	SelectedSuite          SelectedSuiteV1
	SelectedCapabilityHash [32]byte
	ClientProfileHash      [32]byte
	ServerProfileHash      [32]byte
	ClientModeBinding      HandshakeModeBinding
	ServerModeBinding      HandshakeModeBinding
}

func (v CompatibilityBlockV1) Clone() CompatibilityBlockV1 {
	v.SupportedSecuritySuites = slices.Clone(v.SupportedSecuritySuites)
	v.RequiredCapabilities = slices.Clone(v.RequiredCapabilities)
	v.SupportedCarrierFamilies = slices.Clone(v.SupportedCarrierFamilies)
	v.SupportedProxyFeatures = slices.Clone(v.SupportedProxyFeatures)
	v.SupportedStreamFeatures = slices.Clone(v.SupportedStreamFeatures)
	return v
}

func (v HandshakeModeBinding) Clone() HandshakeModeBinding {
	v.ClientOptional = slices.Clone(v.ClientOptional)
	v.ServerOptional = slices.Clone(v.ServerOptional)
	v.FeatureVectors = slices.Clone(v.FeatureVectors)
	v.CompatibilityBlock = v.CompatibilityBlock.Clone()
	return v
}

func ValidateCompatibilityBlockV1(v CompatibilityBlockV1) error {
	for _, value := range []string{v.SchemaVersion, v.CompilerSecurityVersion, v.MinimumRuntimeVersion} {
		if err := validateASCII(value); err != nil {
			return err
		}
	}
	for i, values := range [][]string{
		v.SupportedSecuritySuites,
		v.RequiredCapabilities,
		v.SupportedCarrierFamilies,
		v.SupportedProxyFeatures,
		v.SupportedStreamFeatures,
	} {
		if i < 3 && len(values) == 0 {
			return fmt.Errorf("%w: missing required compatibility list", ErrInvalidTranscript)
		}
		if _, err := encodeStrictStringListV1(values); err != nil {
			return err
		}
	}
	if v.MaxEnvelopeBytes == 0 || v.MaxStreamCount == 0 || v.MaxReplayWindow == 0 {
		return fmt.Errorf("%w: invalid compatibility ceiling", ErrInvalidTranscript)
	}
	return nil
}

func CanonicalCompatibilityBlockV1(v CompatibilityBlockV1) ([]byte, error) {
	if err := ValidateCompatibilityBlockV1(v); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for _, value := range []string{v.SchemaVersion, v.CompilerSecurityVersion, v.MinimumRuntimeVersion} {
		writeLP(&out, []byte(value))
	}
	for _, values := range [][]string{
		v.SupportedSecuritySuites,
		v.RequiredCapabilities,
		v.SupportedCarrierFamilies,
		v.SupportedProxyFeatures,
		v.SupportedStreamFeatures,
	} {
		raw, _ := encodeStrictStringListV1(values)
		writeLP(&out, raw)
	}
	writeU32(&out, v.MaxEnvelopeBytes)
	writeU32(&out, v.MaxStreamCount)
	writeU32(&out, v.MaxReplayWindow)
	return out.Bytes(), nil
}

func CompatibilityBlockHashV1(v CompatibilityBlockV1) ([32]byte, error) {
	raw, err := CanonicalCompatibilityBlockV1(v)
	if err != nil {
		return [32]byte{}, err
	}
	return contextHash("kurdistan/context/v1/compatibility-block", raw), nil
}

func ValidateLimitBlockV1(v LimitBlockV1) error {
	if v.MaxFrameBytes == 0 || v.MaxPayloadBytes == 0 || v.MaxStates == 0 ||
		v.MaxTransitions == 0 || v.MaxSessionMillis == 0 ||
		v.CarrierMaxEnvelopeBytes == 0 || v.CarrierMaxQueueDepth == 0 ||
		v.SessionMaxConcurrentStreams == 0 || v.CarrierMaxEnvelopeBytes > v.MaxFrameBytes {
		return fmt.Errorf("%w: invalid retained limit", ErrInvalidTranscript)
	}
	return nil
}

func CanonicalLimitBlockV1(v LimitBlockV1) ([]byte, error) {
	if err := ValidateLimitBlockV1(v); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	writeU32(&out, v.MaxFrameBytes)
	writeU32(&out, v.MaxPayloadBytes)
	writeU32(&out, v.MaxStates)
	writeU32(&out, v.MaxTransitions)
	writeU64Context(&out, v.MaxSessionMillis)
	writeU32(&out, v.CarrierMaxEnvelopeBytes)
	writeU32(&out, v.CarrierMaxQueueDepth)
	writeU32(&out, v.SessionMaxConcurrentStreams)
	return out.Bytes(), nil
}

func LimitBlockHashV1(v LimitBlockV1) ([32]byte, error) {
	raw, err := CanonicalLimitBlockV1(v)
	if err != nil {
		return [32]byte{}, err
	}
	return contextHash("kurdistan/context/v1/limit-block", raw), nil
}

func ValidateSelectedSuiteV1(v SelectedSuiteV1) error {
	for _, value := range []string{v.KDFSuite, v.AEADSuite, v.MACSuite} {
		if err := validateASCII(value); err != nil {
			return err
		}
	}
	return nil
}

func CanonicalSelectedSuiteV1(v SelectedSuiteV1) ([]byte, error) {
	if err := ValidateSelectedSuiteV1(v); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	writeLP(&out, []byte(v.KDFSuite))
	writeLP(&out, []byte(v.AEADSuite))
	writeLP(&out, []byte(v.MACSuite))
	return out.Bytes(), nil
}

func ValidateConfigSourceBlockV1(v ConfigSourceBlockV1) error {
	if err := validateASCII(v.ProfileID); err != nil {
		return err
	}
	if err := validateASCII(v.SecurityVersion); err != nil {
		return err
	}
	if err := ValidateSelectedSuiteV1(v.SelectedSuite); err != nil {
		return err
	}
	if err := validateASCII(v.AdapterClass); err != nil {
		return err
	}
	for _, value := range [][32]byte{
		v.ProfileHash,
		v.EffectivePolicyHash,
		v.SelectedCapabilityHash,
		v.CompatibilityBlockHash,
		v.LimitBlockHash,
	} {
		if allZero32(value) {
			return fmt.Errorf("%w: zero config-source hash", ErrInvalidTranscript)
		}
	}
	return nil
}

func CanonicalConfigSourceBlockV1(v ConfigSourceBlockV1) ([]byte, error) {
	if err := ValidateConfigSourceBlockV1(v); err != nil {
		return nil, err
	}
	suite, _ := CanonicalSelectedSuiteV1(v.SelectedSuite)
	var out bytes.Buffer
	writeLP(&out, []byte(v.ProfileID))
	out.Write(v.ProfileHash[:])
	writeLP(&out, []byte(v.SecurityVersion))
	writeLP(&out, suite)
	out.Write(v.EffectivePolicyHash[:])
	out.Write(v.SelectedCapabilityHash[:])
	writeLP(&out, []byte(v.AdapterClass))
	out.Write(v.CompatibilityBlockHash[:])
	out.Write(v.LimitBlockHash[:])
	return out.Bytes(), nil
}

func ConfigSourceBlockHashV1(v ConfigSourceBlockV1) ([32]byte, error) {
	raw, err := CanonicalConfigSourceBlockV1(v)
	if err != nil {
		return [32]byte{}, err
	}
	return contextHash("kurdistan/context/v1/config-source-block", raw), nil
}

// EffectivePolicyHashV1 deliberately hashes only the public PolicyV1 bytes.
func EffectivePolicyHashV1(policy ir.EffectiveSecurityPolicy) ([32]byte, error) {
	raw, err := EncodePolicyV1(policy)
	if err != nil {
		return [32]byte{}, err
	}
	return contextHash("kurdistan/policy/v1/effective", raw), nil
}

// SelectedCapabilityHashV1 preserves the existing compact-JSON
// CapabilitySet.Hash vector while requiring a canonical selected set.
func SelectedCapabilityHashV1(values []string) ([32]byte, error) {
	if len(values) == 0 {
		return [32]byte{}, fmt.Errorf("%w: empty selected capability set", ErrInvalidTranscript)
	}
	if _, err := encodeStrictStringListV1(values); err != nil {
		return [32]byte{}, err
	}
	encoded, err := (CapabilitySet{Features: slices.Clone(values)}).Hash()
	if err != nil || len(encoded) != sha256.Size*2 {
		return [32]byte{}, fmt.Errorf("%w: invalid selected capability set", ErrInvalidTranscript)
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != sha256.Size {
		return [32]byte{}, fmt.Errorf("%w: invalid selected capability hash", ErrInvalidTranscript)
	}
	var out [32]byte
	copy(out[:], raw)
	if allZero32(out) {
		return [32]byte{}, fmt.Errorf("%w: zero selected capability hash", ErrInvalidTranscript)
	}
	return out, nil
}

// CanonicalAuthenticatedModeBindingV1 is context-only. It is never used by
// CanonicalHandshakeModeBinding or any handshake wire/transcript/KDF path.
func CanonicalAuthenticatedModeBindingV1(mode string, binding HandshakeModeBinding) ([]byte, error) {
	if !knownTranscriptModeV1(mode) {
		return nil, fmt.Errorf("%w: unknown transcript mode", ErrInvalidTranscript)
	}
	if err := validateASCII(binding.CarrierFamily); err != nil {
		return nil, err
	}
	if err := validateASCII(binding.LocalAdapterClass); err != nil {
		return nil, err
	}
	knownCarrier := knownCarrierFamilyV1(binding.CarrierFamily)
	knownAdapter := slices.Contains([]string{"one_flow_one_stream", "priority_mapped_stream", "metadata_bound_stream", "state_derived_mapping"}, binding.LocalAdapterClass)
	if len(binding.FeatureVectors) == 0 || binding.EnvelopeLimit == 0 || binding.MaxFrameBytes == 0 ||
		binding.EnvelopeLimit > binding.MaxFrameBytes || binding.MaxFrameBytes > 1<<20 || !knownCarrier || !knownAdapter {
		return nil, fmt.Errorf("%w: invalid authenticated mode binding", ErrInvalidTranscript)
	}
	if binding.EnvelopeLimit != binding.LimitBlock.CarrierMaxEnvelopeBytes ||
		binding.MaxFrameBytes != binding.LimitBlock.MaxFrameBytes {
		return nil, fmt.Errorf("%w: contradictory retained limits", ErrInvalidTranscript)
	}
	for _, values := range [][]string{binding.ClientOptional, binding.ServerOptional, binding.FeatureVectors} {
		if _, err := encodeStrictStringListV1(values); err != nil {
			return nil, err
		}
	}
	for _, value := range [][32]byte{
		binding.CarrierPolicyHash,
		binding.FramingPolicyHash,
		binding.StateMachinePolicyHash,
		binding.SchedulerPolicyHash,
		binding.PaddingPolicyHash,
		binding.StreamPolicyHash,
		binding.ProxyPolicyHash,
		binding.CarrierContextHash,
		binding.CompatibilityBlockHash,
		binding.LimitBlockHash,
		binding.ConfigSourceBlockHash,
	} {
		if allZero32(value) {
			return nil, fmt.Errorf("%w: zero authenticated binding hash", ErrInvalidTranscript)
		}
	}
	compatibilityRaw, err := CanonicalCompatibilityBlockV1(binding.CompatibilityBlock)
	if err != nil {
		return nil, err
	}
	wantCompatibilityHash, _ := CompatibilityBlockHashV1(binding.CompatibilityBlock)
	if wantCompatibilityHash != binding.CompatibilityBlockHash {
		return nil, fmt.Errorf("%w: compatibility hash mismatch", ErrInvalidTranscript)
	}
	limitRaw, err := CanonicalLimitBlockV1(binding.LimitBlock)
	if err != nil {
		return nil, err
	}
	wantLimitHash, _ := LimitBlockHashV1(binding.LimitBlock)
	if wantLimitHash != binding.LimitBlockHash {
		return nil, fmt.Errorf("%w: limit hash mismatch", ErrInvalidTranscript)
	}
	configRaw, err := CanonicalConfigSourceBlockV1(binding.ConfigSourceBlock)
	if err != nil {
		return nil, err
	}
	wantConfigHash, _ := ConfigSourceBlockHashV1(binding.ConfigSourceBlock)
	if wantConfigHash != binding.ConfigSourceBlockHash ||
		binding.ConfigSourceBlock.CompatibilityBlockHash != binding.CompatibilityBlockHash ||
		binding.ConfigSourceBlock.LimitBlockHash != binding.LimitBlockHash ||
		binding.ConfigSourceBlock.AdapterClass != binding.LocalAdapterClass {
		return nil, fmt.Errorf("%w: config-source binding mismatch", ErrInvalidTranscript)
	}

	var out bytes.Buffer
	writeLP(&out, []byte(mode))
	for _, values := range [][]string{binding.ClientOptional, binding.ServerOptional, binding.FeatureVectors} {
		raw, _ := encodeStrictStringListV1(values)
		writeLP(&out, raw)
	}
	writeLP(&out, []byte(binding.CarrierFamily))
	out.Write(binding.CarrierPolicyHash[:])
	writeU32(&out, binding.EnvelopeLimit)
	writeU32(&out, binding.MaxFrameBytes)
	writeLP(&out, []byte(binding.LocalAdapterClass))
	for _, value := range [][32]byte{
		binding.FramingPolicyHash,
		binding.StateMachinePolicyHash,
		binding.SchedulerPolicyHash,
		binding.PaddingPolicyHash,
		binding.StreamPolicyHash,
		binding.ProxyPolicyHash,
		binding.CarrierContextHash,
	} {
		out.Write(value[:])
	}
	writeLP(&out, compatibilityRaw)
	out.Write(binding.CompatibilityBlockHash[:])
	writeLP(&out, limitRaw)
	out.Write(binding.LimitBlockHash[:])
	writeLP(&out, configRaw)
	out.Write(binding.ConfigSourceBlockHash[:])
	return out.Bytes(), nil
}

func ContextHashV1(input AuthenticatedContextHashInputV1) ([32]byte, error) {
	policyRaw, err := EncodePolicyV1(input.EffectivePolicy)
	if err != nil {
		return [32]byte{}, err
	}
	wantPolicyHash, _ := EffectivePolicyHashV1(input.EffectivePolicy)
	if wantPolicyHash != input.EffectivePolicyHash || allZero32(input.TranscriptHash) ||
		allZero32(input.SelectedCapabilityHash) || allZero32(input.ClientProfileHash) ||
		allZero32(input.ServerProfileHash) {
		return [32]byte{}, fmt.Errorf("%w: invalid authenticated context identity", ErrInvalidTranscript)
	}
	profileRaw, err := hex.DecodeString(input.EffectivePolicy.ProfileHash)
	if err != nil || len(profileRaw) != sha256.Size {
		return [32]byte{}, fmt.Errorf("%w: invalid effective profile hash", ErrInvalidTranscript)
	}
	var policyProfileHash [32]byte
	copy(policyProfileHash[:], profileRaw)
	if allZero32(policyProfileHash) || input.ClientProfileHash != policyProfileHash || input.ServerProfileHash != policyProfileHash {
		return [32]byte{}, fmt.Errorf("%w: authenticated profile hash mismatch", ErrInvalidTranscript)
	}
	suiteRaw, err := CanonicalSelectedSuiteV1(input.SelectedSuite)
	if err != nil {
		return [32]byte{}, err
	}
	wantCapabilities, err := SelectedCapabilityHashV1(input.EffectivePolicy.SelectedCapabilities)
	if err != nil || wantCapabilities != input.SelectedCapabilityHash {
		return [32]byte{}, fmt.Errorf("%w: selected capability hash mismatch", ErrInvalidTranscript)
	}
	if input.SelectedSuite != (SelectedSuiteV1{
		KDFSuite:  input.EffectivePolicy.KDFSuite,
		AEADSuite: input.EffectivePolicy.AEADSuite,
		MACSuite:  input.EffectivePolicy.MACSuite,
	}) {
		return [32]byte{}, fmt.Errorf("%w: selected suite mismatch", ErrInvalidTranscript)
	}
	clientMode, err := validateContextBindingV1(input, input.ClientModeBinding, input.ClientProfileHash)
	if err != nil {
		return [32]byte{}, err
	}
	serverMode, err := validateContextBindingV1(input, input.ServerModeBinding, input.ServerProfileHash)
	if err != nil {
		return [32]byte{}, err
	}
	clientCompatibility, _ := CanonicalCompatibilityBlockV1(input.ClientModeBinding.CompatibilityBlock)
	serverCompatibility, _ := CanonicalCompatibilityBlockV1(input.ServerModeBinding.CompatibilityBlock)
	clientLimit, _ := CanonicalLimitBlockV1(input.ClientModeBinding.LimitBlock)
	serverLimit, _ := CanonicalLimitBlockV1(input.ServerModeBinding.LimitBlock)
	clientConfig, _ := CanonicalConfigSourceBlockV1(input.ClientModeBinding.ConfigSourceBlock)
	serverConfig, _ := CanonicalConfigSourceBlockV1(input.ServerModeBinding.ConfigSourceBlock)
	var version [2]byte
	binary.BigEndian.PutUint16(version[:], 1)
	return contextHash("kurdistan/context/v1/authenticated",
		version[:],
		policyRaw,
		input.EffectivePolicyHash[:],
		input.TranscriptHash[:],
		suiteRaw,
		input.SelectedCapabilityHash[:],
		input.ClientProfileHash[:],
		input.ServerProfileHash[:],
		clientCompatibility,
		input.ClientModeBinding.CompatibilityBlockHash[:],
		serverCompatibility,
		input.ServerModeBinding.CompatibilityBlockHash[:],
		clientLimit,
		input.ClientModeBinding.LimitBlockHash[:],
		serverLimit,
		input.ServerModeBinding.LimitBlockHash[:],
		clientConfig,
		input.ClientModeBinding.ConfigSourceBlockHash[:],
		serverConfig,
		input.ServerModeBinding.ConfigSourceBlockHash[:],
		clientMode,
		serverMode,
	), nil
}

func validateContextBindingV1(input AuthenticatedContextHashInputV1, binding HandshakeModeBinding, profileHash [32]byte) ([]byte, error) {
	if binding.CompatibilityBlock.MaxReplayWindow < uint32(input.EffectivePolicy.ReplayWindowSize) ||
		binding.CompatibilityBlock.MaxStreamCount < binding.LimitBlock.SessionMaxConcurrentStreams ||
		binding.CompatibilityBlock.MaxEnvelopeBytes < binding.LimitBlock.CarrierMaxEnvelopeBytes {
		return nil, fmt.Errorf("%w: effective value exceeds compatibility ceiling", ErrInvalidTranscript)
	}
	config := binding.ConfigSourceBlock
	compatibility := binding.CompatibilityBlock
	if config.ProfileID != input.EffectivePolicy.ProfileID || config.ProfileHash != profileHash ||
		config.SecurityVersion != input.EffectivePolicy.SecurityVersion || config.SelectedSuite != input.SelectedSuite ||
		config.EffectivePolicyHash != input.EffectivePolicyHash || config.SelectedCapabilityHash != input.SelectedCapabilityHash ||
		compatibility.SchemaVersion != input.EffectivePolicy.SchemaVersion ||
		compatibility.CompilerSecurityVersion != input.EffectivePolicy.CompilerSecurityVersion ||
		compatibility.MinimumRuntimeVersion != input.EffectivePolicy.MinimumRuntimeVersion {
		return nil, fmt.Errorf("%w: context source mismatch", ErrInvalidTranscript)
	}
	return CanonicalAuthenticatedModeBindingV1(input.EffectivePolicy.TranscriptMode, binding)
}

func encodeStrictStringListV1(values []string) ([]byte, error) {
	for i, value := range values {
		if err := validateASCII(value); err != nil {
			return nil, err
		}
		if i > 0 && values[i-1] >= value {
			return nil, fmt.Errorf("%w: noncanonical list", ErrInvalidTranscript)
		}
	}
	var out bytes.Buffer
	writeU32(&out, uint32(len(values)))
	for _, value := range values {
		writeLP(&out, []byte(value))
	}
	return out.Bytes(), nil
}

func knownTranscriptModeV1(mode string) bool {
	switch mode {
	case TranscriptCanonicalV1, TranscriptCapabilitiesV1, TranscriptCarrierBindingV1, TranscriptFullBindingV1:
		return true
	default:
		return false
	}
}

func contextHash(label string, parts ...[]byte) [32]byte {
	var input bytes.Buffer
	writeLP(&input, []byte(label))
	for _, part := range parts {
		writeLP(&input, part)
	}
	return sha256.Sum256(input.Bytes())
}

func writeU64Context(out *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	out.Write(raw[:])
}
