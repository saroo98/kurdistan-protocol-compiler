// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auth

import (
	"encoding/hex"
	"encoding/json"
	"sort"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
)

const projectedCarrierTLS13TCPV1 = "tls13-tcp"

// NewProjectedProcessHandshakeConfigV1 constructs both role-separated peers
// from one validated product-safe live program. Callers cannot supply an
// independent policy or mode binding beside the signed projection.
func NewProjectedProcessHandshakeConfigV1(clientIdentityID, relayIdentityID string, program liveprogram.ProgramV1, carrierFamily string) (ProcessHandshakeConfigV1, error) {
	if clientIdentityID == "" || relayIdentityID == "" || len(clientIdentityID) > 128 || len(relayIdentityID) > 128 ||
		clientIdentityID == relayIdentityID || carrierFamily != projectedCarrierTLS13TCPV1 || liveprogram.ValidateV1(program) != nil {
		return ProcessHandshakeConfigV1{}, fail(FailureProfileMismatch)
	}
	policy, err := projectedEffectivePolicyV1(program)
	if err != nil {
		return ProcessHandshakeConfigV1{}, err
	}
	binding, err := projectedModeBindingV1(program, policy, carrierFamily)
	if err != nil {
		return ProcessHandshakeConfigV1{}, err
	}
	client, err := projectedPeerParametersV1(clientIdentityID, program, policy, binding, program.Security.ClientMandatoryCapabilities)
	if err != nil {
		return ProcessHandshakeConfigV1{}, err
	}
	relay, err := projectedPeerParametersV1(relayIdentityID, program, policy, binding, program.Security.RelayMandatoryCapabilities)
	if err != nil {
		return ProcessHandshakeConfigV1{}, err
	}
	return NewProcessHandshakeConfigV1(client, relay, policy, program.Security.SelectedCapabilities)
}

func projectedEffectivePolicyV1(program liveprogram.ProgramV1) (ir.EffectiveSecurityPolicy, error) {
	securityPolicy := program.Security.Policy
	policy, err := ir.BuildEffectiveSecurityPolicyFromProjectionV1(
		program.ProgramID,
		program.SourceGenerationHash,
		program.Security.CompilerSecurityVersion,
		program.Security.MinimumRuntimeVersion,
		ir.SecurityPolicy{
			SecurityVersion: securityPolicy.SecurityVersion, TranscriptMode: securityPolicy.TranscriptMode,
			KDFSuite: securityPolicy.KDFSuite, AEADSuite: securityPolicy.AEADSuite, MACSuite: securityPolicy.MACSuite,
			NonceMode: securityPolicy.NonceMode, ReplayPolicy: securityPolicy.ReplayPolicy, ReplayWindowSize: securityPolicy.ReplayWindowSize,
			DowngradePolicy: securityPolicy.DowngradePolicy, CapabilityNegotiationPolicy: securityPolicy.CapabilityNegotiationPolicy,
			ProfileCompatibilityPolicy: securityPolicy.ProfileCompatibilityPolicy, KeyRotationPolicy: securityPolicy.KeyRotationPolicy,
			ConfigValidationPolicy: securityPolicy.ConfigValidationPolicy, SecureEnvelopeMode: securityPolicy.SecureEnvelopeMode,
			MaxSessionMessages: securityPolicy.MaxSessionMessages, MaxKeyLifetimeMessages: securityPolicy.MaxKeyLifetimeMessages,
		},
		program.Security.ClientMandatoryCapabilities,
		program.Security.RelayMandatoryCapabilities,
		program.Security.SelectedCapabilities,
	)
	if err != nil {
		return ir.EffectiveSecurityPolicy{}, fail(FailurePolicyMismatch)
	}
	return policy, nil
}

func projectedPeerParametersV1(identityID string, program liveprogram.ProgramV1, policy ir.EffectiveSecurityPolicy, binding security.HandshakeModeBinding, required []string) (PeerParameters, error) {
	offered, err := normalizeCapabilitySet(program.Security.SelectedCapabilities)
	if err != nil {
		return PeerParameters{}, fail(FailurePolicyMismatch)
	}
	floor, err := normalizeCapabilitySet(required)
	if err != nil {
		return PeerParameters{}, fail(FailurePolicyFloorRejected)
	}
	peer := PeerParameters{
		IdentityID:  identityID,
		ProfileID:   hex.EncodeToString(program.ProgramID[:]),
		ProfileHash: program.SourceGenerationHash,
		OfferPolicy: policy.Clone(), FloorPolicy: policy.Clone(),
		OfferedCapabilities: offered, RequiredCapabilities: floor,
		modeBinding: binding.Clone(),
	}
	peer.seal, err = sealPeerParameters(peer)
	if err != nil {
		return PeerParameters{}, fail(FailureProfileMismatch)
	}
	return peer, nil
}

func projectedModeBindingV1(program liveprogram.ProgramV1, policy ir.EffectiveSecurityPolicy, carrierFamily string) (security.HandshakeModeBinding, error) {
	hashJSON := func(domain string, value any) ([32]byte, error) {
		raw, err := json.Marshal(value)
		if err != nil {
			return [32]byte{}, err
		}
		return protocolHash(domain, raw), nil
	}
	carrierPolicyHash, err := hashJSON("kurdistan/live-program/v1/carrier-policy", struct {
		Family          string
		MaxFrameBytes   int
		MaxPayloadBytes int
	}{carrierFamily, program.Limits.MaxFrameBytes, program.Limits.MaxPayloadBytes})
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	framingHash, err := hashJSON("kurdistan/live-program/v1/framing-policy", program.Frame)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	stateHash, err := hashJSON("kurdistan/live-program/v1/message-policy", program.Messages)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	schedulerHash, err := hashJSON("kurdistan/live-program/v1/scheduler-policy", program.Scheduler)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	paddingHash, err := hashJSON("kurdistan/live-program/v1/padding-policy", program.Padding)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	streamHash, err := hashJSON("kurdistan/live-program/v1/stream-policy", program.Stream)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	proxyHash, err := hashJSON("kurdistan/live-program/v1/proxy-policy", program.Security.SelectedCapabilities)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	carrierContextHash, err := hashJSON("kurdistan/live-program/v1/carrier-context", struct {
		Family    string
		ProgramID [16]byte
		Source    [32]byte
	}{carrierFamily, program.ProgramID, program.SourceGenerationHash})
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}

	suites := []string{policy.AEADSuite, policy.KDFSuite, policy.MACSuite}
	sort.Strings(suites)
	proxyFeatures := []string{}
	for _, capability := range program.Security.SelectedCapabilities {
		if capability == "proxy_semantics" {
			proxyFeatures = []string{capability}
		}
	}
	compatibility := security.CompatibilityBlockV1{
		SchemaVersion: policy.SchemaVersion, CompilerSecurityVersion: policy.CompilerSecurityVersion,
		MinimumRuntimeVersion: policy.MinimumRuntimeVersion, SupportedSecuritySuites: suites,
		RequiredCapabilities:     append([]string(nil), program.Security.SelectedCapabilities...),
		SupportedCarrierFamilies: []string{carrierFamily}, SupportedProxyFeatures: proxyFeatures,
		SupportedStreamFeatures: []string{program.Stream.IDEncodingMode},
		MaxEnvelopeBytes:        uint32(program.Limits.MaxFrameBytes), MaxStreamCount: uint32(program.Stream.MaxConcurrentStreams),
		MaxReplayWindow: uint32(policy.ReplayWindowSize),
	}
	compatibilityHash, err := security.CompatibilityBlockHashV1(compatibility)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	limits := security.LimitBlockV1{
		MaxFrameBytes: uint32(program.Limits.MaxFrameBytes), MaxPayloadBytes: uint32(program.Limits.MaxPayloadBytes),
		MaxStates: uint32(len(program.Messages)), MaxTransitions: uint32(len(program.Messages) * 2),
		MaxSessionMillis: uint64(program.Limits.MaxSessionMillis), CarrierMaxEnvelopeBytes: uint32(program.Limits.MaxFrameBytes),
		CarrierMaxQueueDepth: uint32(program.Scheduler.MaxInFlightFrames), SessionMaxConcurrentStreams: uint32(program.Stream.MaxConcurrentStreams),
	}
	limitHash, err := security.LimitBlockHashV1(limits)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	effectiveHash, err := security.EffectivePolicyHashV1(policy)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailurePolicyMismatch)
	}
	capabilityHash, err := security.SelectedCapabilityHashV1(policy.SelectedCapabilities)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailurePolicyFloorRejected)
	}
	config := security.ConfigSourceBlockV1{
		ProfileID: policy.ProfileID, ProfileHash: program.SourceGenerationHash, SecurityVersion: policy.SecurityVersion,
		SelectedSuite:       security.SelectedSuiteV1{KDFSuite: policy.KDFSuite, AEADSuite: policy.AEADSuite, MACSuite: policy.MACSuite},
		EffectivePolicyHash: effectiveHash, SelectedCapabilityHash: capabilityHash, AdapterClass: "metadata_bound_stream",
		CompatibilityBlockHash: compatibilityHash, LimitBlockHash: limitHash,
	}
	configHash, err := security.ConfigSourceBlockHashV1(config)
	if err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	features := []string{
		"carrier:" + carrierFamily,
		"frame:" + program.Frame.FragmentationMode,
		"scheduler:" + program.Scheduler.Mode,
		"stream:" + program.Stream.IDEncodingMode,
	}
	for _, capability := range program.Security.SelectedCapabilities {
		features = append(features, "capability:"+capability)
	}
	sort.Strings(features)
	binding := security.HandshakeModeBinding{
		FeatureVectors: features, CarrierFamily: carrierFamily, CarrierPolicyHash: carrierPolicyHash,
		EnvelopeLimit: uint32(program.Limits.MaxFrameBytes), MaxFrameBytes: uint32(program.Limits.MaxFrameBytes),
		LocalAdapterClass: "metadata_bound_stream", FramingPolicyHash: framingHash, StateMachinePolicyHash: stateHash,
		SchedulerPolicyHash: schedulerHash, PaddingPolicyHash: paddingHash, StreamPolicyHash: streamHash,
		ProxyPolicyHash: proxyHash, CarrierContextHash: carrierContextHash,
		CompatibilityBlock: compatibility, CompatibilityBlockHash: compatibilityHash,
		LimitBlock: limits, LimitBlockHash: limitHash, ConfigSourceBlock: config, ConfigSourceBlockHash: configHash,
	}
	if _, err := security.CanonicalAuthenticatedModeBindingV1(policy.TranscriptMode, binding); err != nil {
		return security.HandshakeModeBinding{}, fail(FailureProfileMismatch)
	}
	return binding, nil
}
