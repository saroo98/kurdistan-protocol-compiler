// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"sort"
	"strings"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
)

const (
	implementationSupportListCapacityV1 = 256
	profileAuthorizationCapacityV1      = 512
)

var (
	ErrImplementationSupportInvalid = errors.New("implementation_support_invalid")
	ErrProfileAuthorizationInvalid  = errors.New("profile_authorization_invalid")
	ErrPolicyInvalid                = errors.New("policy_invalid")
	ErrProfileMismatch              = errors.New("profile_mismatch")
	ErrTranscriptMismatch           = errors.New("transcript_mismatch")
	ErrCapabilityTranscriptInvalid  = errors.New("capability_transcript_invalid")
	ErrCarrierBindingInvalid        = errors.New("carrier_binding_invalid")
	ErrFullBindingInvalid           = errors.New("full_binding_invalid")
	ErrDowngradeRejected            = errors.New("downgrade_rejected")
	ErrCapabilityRejected           = errors.New("capability_rejected")
	ErrProfileIncompatible          = errors.New("profile_incompatible")
)

type implementationRoleV1 uint8

const (
	implementationRoleClientV1 implementationRoleV1 = iota + 1
	implementationRoleRelayV1
)

type selectedSuiteTranscriptV1 struct {
	suite          security.SelectedSuiteV1
	transcriptMode string
}

// ImplementationSupportV1 is deliberately opaque. Strict runtimes receive
// only package-owned defaults; the unexported strict test seam is the sole
// place where a different descriptor can be supplied.
type ImplementationSupportV1 struct {
	role                     implementationRoleV1
	redaction                redactionCertificateV1
	schemaVersions           []string
	compilerSecurityVersions []string
	minimumRuntimeVersions   []string
	securityVersions         []string
	suites                   []security.SelectedSuiteV1
	securitySuiteIDs         []string
	transcriptModes          []string
	capabilities             []string
	featureVectors           []string
	carrierFamilies          []string
	carrierPolicyHashes      [][32]byte
	proxyFeatures            []string
	streamFeatures           []string
	adapterClasses           []string
	nonceModes               []string
	replayPolicies           []string
	downgradePolicies        []string
	capabilityPolicies       []string
	profilePolicies          []string
	rotationPolicies         []string
	configPolicies           []string
	envelopeModes            []string
	maxEnvelopeBytes         uint32
	maxFrameBytes            uint32
	maxQueueDepth            uint32
	maxStreams               uint32
	maxReplayWindow          uint32
	maxSessionMessages       uint64
	maxKeyLifetimeMessages   uint64
	suiteTranscriptPairs     []selectedSuiteTranscriptV1
}

// ClientProfileAuthorizationEntryV1 is the client owner's immutable registry
// input. Its relay counterpart is a distinct type so role conversion is never
// implicit.
type ClientProfileAuthorizationEntryV1 struct {
	clientRole               clientProfileAuthorizationEntryRoleV1
	ProfileHash              [32]byte
	EffectivePolicyHash      [32]byte
	ReplayWindowSize         uint32
	MaxConcurrentStreams     uint32
	MaxFrameBytes            uint32
	MaxEnvelopeBytes         uint32
	FramingPolicyHash        [32]byte
	StateMachinePolicyHash   [32]byte
	SchedulerPolicyHash      [32]byte
	PaddingPolicyHash        [32]byte
	StreamPolicyHash         [32]byte
	ProxyPolicyHash          [32]byte
	CarrierContextPolicyHash [32]byte
}

// RelayProfileAuthorizationEntryV1 is the relay owner's immutable registry
// input. It cannot be substituted for a client entry or registry.
type RelayProfileAuthorizationEntryV1 struct {
	relayRole                relayProfileAuthorizationEntryRoleV1
	ProfileHash              [32]byte
	EffectivePolicyHash      [32]byte
	ReplayWindowSize         uint32
	MaxConcurrentStreams     uint32
	MaxFrameBytes            uint32
	MaxEnvelopeBytes         uint32
	FramingPolicyHash        [32]byte
	StateMachinePolicyHash   [32]byte
	SchedulerPolicyHash      [32]byte
	PaddingPolicyHash        [32]byte
	StreamPolicyHash         [32]byte
	ProxyPolicyHash          [32]byte
	CarrierContextPolicyHash [32]byte
}

type profileAuthorizationEntryV1 struct {
	profileHash              [32]byte
	effectivePolicyHash      [32]byte
	replayWindowSize         uint32
	maxConcurrentStreams     uint32
	maxFrameBytes            uint32
	maxEnvelopeBytes         uint32
	framingPolicyHash        [32]byte
	stateMachinePolicyHash   [32]byte
	schedulerPolicyHash      [32]byte
	paddingPolicyHash        [32]byte
	streamPolicyHash         [32]byte
	proxyPolicyHash          [32]byte
	carrierContextPolicyHash [32]byte
}

type clientProfileAuthorizationEntryRoleV1 struct{ clientOnly byte }
type relayProfileAuthorizationEntryRoleV1 struct{ relayOnly byte }
type clientProfileAuthorizationEntriesV1 []profileAuthorizationEntryV1
type relayProfileAuthorizationEntriesV1 []profileAuthorizationEntryV1

type clientProfileAuthorizationRegistryRoleV1 struct{ clientOnly byte }
type relayProfileAuthorizationRegistryRoleV1 struct{ relayOnly byte }

// ClientProfileAuthorizationRegistryV1 has no exported fields, accessor, or
// registration method. Construction and strict-runtime ownership each clone
// the canonical table.
type ClientProfileAuthorizationRegistryV1 struct {
	clientRole clientProfileAuthorizationRegistryRoleV1
	entries    clientProfileAuthorizationEntriesV1
}

// RelayProfileAuthorizationRegistryV1 is role-distinct from the client
// registry and exposes no conversion or mutation surface.
type RelayProfileAuthorizationRegistryV1 struct {
	relayRole relayProfileAuthorizationRegistryRoleV1
	entries   relayProfileAuthorizationEntriesV1
}

func NewClientProfileAuthorizationRegistryV1(entries []ClientProfileAuthorizationEntryV1) (ClientProfileAuthorizationRegistryV1, error) {
	converted := make([]profileAuthorizationEntryV1, len(entries))
	for i, entry := range entries {
		converted[i] = profileAuthorizationEntryV1{
			profileHash: entry.ProfileHash, effectivePolicyHash: entry.EffectivePolicyHash,
			replayWindowSize: entry.ReplayWindowSize, maxConcurrentStreams: entry.MaxConcurrentStreams,
			maxFrameBytes: entry.MaxFrameBytes, maxEnvelopeBytes: entry.MaxEnvelopeBytes,
			framingPolicyHash: entry.FramingPolicyHash, stateMachinePolicyHash: entry.StateMachinePolicyHash,
			schedulerPolicyHash: entry.SchedulerPolicyHash, paddingPolicyHash: entry.PaddingPolicyHash,
			streamPolicyHash: entry.StreamPolicyHash, proxyPolicyHash: entry.ProxyPolicyHash,
			carrierContextPolicyHash: entry.CarrierContextPolicyHash,
		}
	}
	if err := validateProfileAuthorizationEntriesV1(converted); err != nil {
		return ClientProfileAuthorizationRegistryV1{}, err
	}
	return ClientProfileAuthorizationRegistryV1{entries: clientProfileAuthorizationEntriesV1(cloneProfileAuthorizationEntriesV1(converted))}, nil
}

func NewRelayProfileAuthorizationRegistryV1(entries []RelayProfileAuthorizationEntryV1) (RelayProfileAuthorizationRegistryV1, error) {
	converted := make([]profileAuthorizationEntryV1, len(entries))
	for i, entry := range entries {
		converted[i] = profileAuthorizationEntryV1{
			profileHash: entry.ProfileHash, effectivePolicyHash: entry.EffectivePolicyHash,
			replayWindowSize: entry.ReplayWindowSize, maxConcurrentStreams: entry.MaxConcurrentStreams,
			maxFrameBytes: entry.MaxFrameBytes, maxEnvelopeBytes: entry.MaxEnvelopeBytes,
			framingPolicyHash: entry.FramingPolicyHash, stateMachinePolicyHash: entry.StateMachinePolicyHash,
			schedulerPolicyHash: entry.SchedulerPolicyHash, paddingPolicyHash: entry.PaddingPolicyHash,
			streamPolicyHash: entry.StreamPolicyHash, proxyPolicyHash: entry.ProxyPolicyHash,
			carrierContextPolicyHash: entry.CarrierContextPolicyHash,
		}
	}
	if err := validateProfileAuthorizationEntriesV1(converted); err != nil {
		return RelayProfileAuthorizationRegistryV1{}, err
	}
	return RelayProfileAuthorizationRegistryV1{entries: relayProfileAuthorizationEntriesV1(cloneProfileAuthorizationEntriesV1(converted))}, nil
}

func cloneProfileAuthorizationEntriesV1(entries []profileAuthorizationEntryV1) []profileAuthorizationEntryV1 {
	return append([]profileAuthorizationEntryV1(nil), entries...)
}

func validateProfileAuthorizationEntriesV1(entries []profileAuthorizationEntryV1) error {
	if len(entries) == 0 || len(entries) > profileAuthorizationCapacityV1 {
		return ErrProfileAuthorizationInvalid
	}
	for i, entry := range entries {
		if zero32V1(entry.profileHash) || zero32V1(entry.effectivePolicyHash) ||
			entry.replayWindowSize < 2 || entry.replayWindowSize > 4096 ||
			entry.maxConcurrentStreams == 0 || entry.maxConcurrentStreams > 65535 ||
			entry.maxFrameBytes == 0 || entry.maxFrameBytes > 1<<20 ||
			entry.maxEnvelopeBytes == 0 || entry.maxEnvelopeBytes > 1<<20 ||
			entry.maxEnvelopeBytes > entry.maxFrameBytes {
			return ErrProfileAuthorizationInvalid
		}
		for _, hash := range [][32]byte{
			entry.framingPolicyHash, entry.stateMachinePolicyHash,
			entry.schedulerPolicyHash, entry.paddingPolicyHash,
			entry.streamPolicyHash, entry.proxyPolicyHash,
			entry.carrierContextPolicyHash,
		} {
			if zero32V1(hash) {
				return ErrProfileAuthorizationInvalid
			}
		}
		if i > 0 && bytes.Compare(entries[i-1].profileHash[:], entry.profileHash[:]) >= 0 {
			return ErrProfileAuthorizationInvalid
		}
	}
	return nil
}

func (r ClientProfileAuthorizationRegistryV1) clone() ClientProfileAuthorizationRegistryV1 {
	return ClientProfileAuthorizationRegistryV1{entries: clientProfileAuthorizationEntriesV1(cloneProfileAuthorizationEntriesV1(r.entries))}
}

func (r RelayProfileAuthorizationRegistryV1) clone() RelayProfileAuthorizationRegistryV1 {
	return RelayProfileAuthorizationRegistryV1{entries: relayProfileAuthorizationEntriesV1(cloneProfileAuthorizationEntriesV1(r.entries))}
}

func (r ClientProfileAuthorizationRegistryV1) valid() bool {
	return validateProfileAuthorizationEntriesV1(r.entries) == nil
}

func (r RelayProfileAuthorizationRegistryV1) valid() bool {
	return validateProfileAuthorizationEntriesV1(r.entries) == nil
}

func findProfileAuthorizationEntryV1(entries []profileAuthorizationEntryV1, profileHash [32]byte) (profileAuthorizationEntryV1, bool) {
	i := sort.Search(len(entries), func(i int) bool {
		return bytes.Compare(entries[i].profileHash[:], profileHash[:]) >= 0
	})
	if i >= len(entries) || !equal32V1(entries[i].profileHash, profileHash) {
		return profileAuthorizationEntryV1{}, false
	}
	return entries[i], true
}

var (
	reviewedClientImplementationSupportV1 = reviewedImplementationSupportV1(implementationRoleClientV1)
	reviewedRelayImplementationSupportV1  = reviewedImplementationSupportV1(implementationRoleRelayV1)
)

func reviewedImplementationSupportV1(role implementationRoleV1) ImplementationSupportV1 {
	suite := security.SelectedSuiteV1{
		KDFSuite: "kdf_hkdf_sha256", AEADSuite: "aead_aes_256_gcm", MACSuite: "mac_hmac_sha256",
	}
	transcripts := []string{
		security.TranscriptCanonicalV1,
		security.TranscriptCapabilitiesV1,
		security.TranscriptCarrierBindingV1,
		security.TranscriptFullBindingV1,
	}
	sort.Strings(transcripts)
	pairs := make([]selectedSuiteTranscriptV1, 0, len(transcripts))
	for _, mode := range transcripts {
		pairs = append(pairs, selectedSuiteTranscriptV1{suite: suite, transcriptMode: mode})
	}
	proxy := append([]string(nil), ir.ProxySemantics()...)
	stream := []string{"close_stream", "data", "open_stream", "reset_stream", "session_close", "window_update"}
	carriers := append([]string(nil), ir.CarrierFamilies()...)
	sort.Strings(proxy)
	sort.Strings(carriers)
	features := make([]string, 0, len(proxy)+len(stream)+len(carriers))
	for _, value := range carriers {
		features = append(features, "carrier:"+value)
	}
	for _, value := range proxy {
		features = append(features, "proxy:"+value)
	}
	for _, value := range stream {
		features = append(features, "stream:"+value)
	}
	sort.Strings(features)
	capabilities := append([]string(nil), ir.SecurityCapabilities()...)
	sort.Strings(capabilities)
	certificate := redactionCertificateV1{version: redactionCertificateVersionV1, role: role, marker: clientRedactionMarkerV1}
	if role == implementationRoleRelayV1 {
		certificate.marker = relayRedactionMarkerV1
	}
	return ImplementationSupportV1{
		role:                     role,
		redaction:                certificate,
		schemaVersions:           []string{ir.SupportedVersion},
		compilerSecurityVersions: []string{security.Version},
		minimumRuntimeVersions:   []string{security.Version},
		securityVersions:         []string{security.Version},
		suites:                   []security.SelectedSuiteV1{suite},
		securitySuiteIDs:         []string{ir.SecuritySuiteString()},
		transcriptModes:          transcripts,
		capabilities:             capabilities,
		featureVectors:           features,
		carrierFamilies:          carriers,
		carrierPolicyHashes: [][32]byte{{
			0xc8, 0x36, 0xfa, 0x4b, 0xf6, 0x62, 0x31, 0xd6,
			0xf6, 0x6d, 0x6f, 0x18, 0x81, 0x51, 0x1c, 0x64,
			0x31, 0x59, 0xae, 0x99, 0x8d, 0xf6, 0x90, 0x94,
			0x5e, 0xea, 0xf5, 0x41, 0x74, 0x0b, 0x50, 0xad,
		}},
		proxyFeatures:          proxy,
		streamFeatures:         stream,
		adapterClasses:         []string{"metadata_bound_stream", "one_flow_one_stream", "priority_mapped_stream", "state_derived_mapping"},
		nonceModes:             []string{"counter_append_base", "counter_xor_base", "directional_counter", "stream_partitioned_counter"},
		replayPolicies:         []string{"bounded_reorder", "ordered_only", "windowed_replay"},
		downgradePolicies:      []string{"strict_capabilities", "strict_suite_and_capabilities", "suite_bound_transcript"},
		capabilityPolicies:     []string{"intersection_with_required", "profile_declared_required", "strict_required"},
		profilePolicies:        []string{"full_policy_binding", "schema_and_feature", "strict_schema"},
		rotationPolicies:       []string{"message_lifetime_bound", "profile_lifetime_bound", "session_only"},
		configPolicies:         []string{"strict_profile_bound", "strict_required", "strict_with_redaction"},
		envelopeModes:          []string{"full_context_bound_envelope", "metadata_authenticated", "synthetic_aead_test"},
		maxEnvelopeBytes:       1 << 20,
		maxFrameBytes:          1 << 20,
		maxQueueDepth:          256,
		maxStreams:             16,
		maxReplayWindow:        4096,
		maxSessionMessages:     1 << 24,
		maxKeyLifetimeMessages: 1 << 24,
		suiteTranscriptPairs:   pairs,
	}
}

func (s ImplementationSupportV1) clone() ImplementationSupportV1 {
	s.schemaVersions = append([]string(nil), s.schemaVersions...)
	s.compilerSecurityVersions = append([]string(nil), s.compilerSecurityVersions...)
	s.minimumRuntimeVersions = append([]string(nil), s.minimumRuntimeVersions...)
	s.securityVersions = append([]string(nil), s.securityVersions...)
	s.suites = append([]security.SelectedSuiteV1(nil), s.suites...)
	s.securitySuiteIDs = append([]string(nil), s.securitySuiteIDs...)
	s.transcriptModes = append([]string(nil), s.transcriptModes...)
	s.capabilities = append([]string(nil), s.capabilities...)
	s.featureVectors = append([]string(nil), s.featureVectors...)
	s.carrierFamilies = append([]string(nil), s.carrierFamilies...)
	s.carrierPolicyHashes = append([][32]byte(nil), s.carrierPolicyHashes...)
	s.proxyFeatures = append([]string(nil), s.proxyFeatures...)
	s.streamFeatures = append([]string(nil), s.streamFeatures...)
	s.adapterClasses = append([]string(nil), s.adapterClasses...)
	s.nonceModes = append([]string(nil), s.nonceModes...)
	s.replayPolicies = append([]string(nil), s.replayPolicies...)
	s.downgradePolicies = append([]string(nil), s.downgradePolicies...)
	s.capabilityPolicies = append([]string(nil), s.capabilityPolicies...)
	s.profilePolicies = append([]string(nil), s.profilePolicies...)
	s.rotationPolicies = append([]string(nil), s.rotationPolicies...)
	s.configPolicies = append([]string(nil), s.configPolicies...)
	s.envelopeModes = append([]string(nil), s.envelopeModes...)
	s.suiteTranscriptPairs = append([]selectedSuiteTranscriptV1(nil), s.suiteTranscriptPairs...)
	return s
}

func validateImplementationSupportV1(s ImplementationSupportV1, role implementationRoleV1) error {
	if s.role != role || s.maxEnvelopeBytes == 0 || s.maxFrameBytes == 0 ||
		s.maxEnvelopeBytes > s.maxFrameBytes || s.maxFrameBytes > 1<<20 ||
		s.maxQueueDepth == 0 || s.maxQueueDepth > 256 || s.maxStreams == 0 ||
		s.maxStreams > 65535 || s.maxReplayWindow < 2 || s.maxReplayWindow > 4096 ||
		s.maxSessionMessages == 0 || s.maxSessionMessages > 1<<24 ||
		s.maxKeyLifetimeMessages == 0 || s.maxKeyLifetimeMessages > s.maxSessionMessages {
		return ErrImplementationSupportInvalid
	}
	for _, values := range [][]string{
		s.schemaVersions, s.compilerSecurityVersions, s.minimumRuntimeVersions,
		s.securityVersions, s.securitySuiteIDs, s.transcriptModes, s.capabilities,
		s.featureVectors, s.carrierFamilies, s.proxyFeatures, s.streamFeatures,
		s.adapterClasses, s.nonceModes, s.replayPolicies, s.downgradePolicies,
		s.capabilityPolicies, s.profilePolicies, s.rotationPolicies,
		s.configPolicies, s.envelopeModes,
	} {
		if !canonicalNonemptyStringsV1(values) {
			return ErrImplementationSupportInvalid
		}
	}
	if len(s.suites) == 0 || len(s.suites) > implementationSupportListCapacityV1 ||
		len(s.carrierPolicyHashes) == 0 || len(s.carrierPolicyHashes) > implementationSupportListCapacityV1 ||
		len(s.suiteTranscriptPairs) == 0 || len(s.suiteTranscriptPairs) > implementationSupportListCapacityV1 {
		return ErrImplementationSupportInvalid
	}
	var previousSuite []byte
	for i, suite := range s.suites {
		raw, err := security.CanonicalSelectedSuiteV1(suite)
		if err != nil || (i > 0 && bytes.Compare(previousSuite, raw) >= 0) {
			return ErrImplementationSupportInvalid
		}
		previousSuite = raw
	}
	for i, hash := range s.carrierPolicyHashes {
		if zero32V1(hash) || (i > 0 && bytes.Compare(s.carrierPolicyHashes[i-1][:], hash[:]) >= 0) {
			return ErrImplementationSupportInvalid
		}
	}
	var previousPair []byte
	for i, pair := range s.suiteTranscriptPairs {
		suiteRaw, err := security.CanonicalSelectedSuiteV1(pair.suite)
		if err != nil || !containsSuiteV1(s.suites, pair.suite) ||
			!containsStringV1(s.transcriptModes, pair.transcriptMode) {
			return ErrImplementationSupportInvalid
		}
		raw := append(append([]byte(nil), suiteRaw...), 0)
		raw = append(raw, pair.transcriptMode...)
		if i > 0 && bytes.Compare(previousPair, raw) >= 0 {
			return ErrImplementationSupportInvalid
		}
		previousPair = raw
	}
	return nil
}

func advertisedSupportMatchesWitnessV1(s ImplementationSupportV1) bool {
	witnesses := advancedPolicyWitnessesV1()
	return equalStringsV1(s.nonceModes, witnessValuesV1(witnesses.nonce)) && equalStringsV1(s.replayPolicies, witnessValuesV1(witnesses.replay)) &&
		equalStringsV1(s.profilePolicies, witnessValuesV1(witnesses.profile)) && equalStringsV1(s.rotationPolicies, witnessValuesV1(witnesses.rotation)) &&
		equalStringsV1(s.configPolicies, witnessValuesV1(witnesses.config)) && equalStringsV1(s.envelopeModes, witnessValuesV1(witnesses.envelope))
}

func witnessValuesV1(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func canonicalNonemptyStringsV1(values []string) bool {
	if len(values) == 0 || len(values) > implementationSupportListCapacityV1 {
		return false
	}
	for i, value := range values {
		if value == "" || !printableASCIIV1(value) || (i > 0 && values[i-1] >= value) {
			return false
		}
	}
	return true
}

func printableASCIIV1(value string) bool {
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func containsStringV1(values []string, value string) bool {
	i := sort.SearchStrings(values, value)
	return i < len(values) && values[i] == value
}

func containsSuiteV1(values []security.SelectedSuiteV1, value security.SelectedSuiteV1) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsTupleV1(values []selectedSuiteTranscriptV1, suite security.SelectedSuiteV1, mode string) bool {
	for _, candidate := range values {
		if candidate.suite == suite && candidate.transcriptMode == mode {
			return true
		}
	}
	return false
}

type supportAuthorizationInputV1 struct {
	policies             []ir.EffectiveSecurityPolicy
	selectedCapabilities []string
	clientProfileHash    [32]byte
	relayProfileHash     [32]byte
	clientBinding        security.HandshakeModeBinding
	relayBinding         security.HandshakeModeBinding
	clientOffered        []string
	clientRequired       []string
	relayOffered         []string
	relayRequired        []string
}

func (r *HandshakeRuntime) verifySupportAndAuthorizationPreflightV1(snapshot auth.FirstContactInput, view auth.FirstContactPreflightViewV1) error {
	return r.verifySupportAndAuthorizationV1(supportAuthorizationInputV1{
		policies: []ir.EffectiveSecurityPolicy{
			view.ClientOfferPolicy, view.ClientFloorPolicy, view.ServerOfferPolicy,
			view.ServerFloorPolicy, view.SelectedPolicy,
		},
		selectedCapabilities: append([]string(nil), view.SelectedCapabilities...),
		clientProfileHash:    snapshot.Client.ProfileHash,
		relayProfileHash:     snapshot.Server.ProfileHash,
		clientBinding:        view.ClientModeBinding.Clone(), relayBinding: view.ServerModeBinding.Clone(),
		clientOffered:  append([]string(nil), view.ClientOfferedCapabilities...),
		clientRequired: append([]string(nil), view.ClientRequiredCapabilities...),
		relayOffered:   append([]string(nil), view.ServerOfferedCapabilities...),
		relayRequired:  append([]string(nil), view.ServerRequiredCapabilities...),
	})
}

func (r *HandshakeRuntime) verifySupportAndAuthorizationContextV1(snapshot auth.AuthenticatedContextSnapshotV1) error {
	clientRequired := append([]string(nil), snapshot.EffectivePolicy.ClientMandatoryCapabilities...)
	relayRequired := append([]string(nil), snapshot.EffectivePolicy.ServerMandatoryCapabilities...)
	return r.verifySupportAndAuthorizationV1(supportAuthorizationInputV1{
		policies:             []ir.EffectiveSecurityPolicy{snapshot.EffectivePolicy.Clone()},
		selectedCapabilities: append([]string(nil), snapshot.EffectivePolicy.SelectedCapabilities...),
		clientProfileHash:    snapshot.ClientProfileHash, relayProfileHash: snapshot.ServerProfileHash,
		clientBinding: snapshot.ClientModeBinding.Clone(), relayBinding: snapshot.ServerModeBinding.Clone(),
		clientOffered:  unionStringsV1(clientRequired, snapshot.ClientModeBinding.ClientOptional),
		clientRequired: clientRequired,
		relayOffered:   unionStringsV1(relayRequired, snapshot.ServerModeBinding.ServerOptional),
		relayRequired:  relayRequired,
	})
}

func (r *HandshakeRuntime) verifySupportAndAuthorizationV1(input supportAuthorizationInputV1) error {
	if r == nil || !r.strict || len(input.policies) == 0 {
		return ErrImplementationSupportInvalid
	}
	selectedPolicy := input.policies[len(input.policies)-1]
	policyHash, err := security.EffectivePolicyHashV1(selectedPolicy)
	if err != nil {
		return ErrProfileMismatch
	}
	clientEntry, clientOK := findProfileAuthorizationEntryV1(r.clientRegistry.entries, input.clientProfileHash)
	relayEntry, relayOK := findProfileAuthorizationEntryV1(r.relayRegistry.entries, input.relayProfileHash)
	if !clientOK || !relayOK || !equal32V1(clientEntry.effectivePolicyHash, policyHash) || !equal32V1(relayEntry.effectivePolicyHash, policyHash) {
		return ErrProfileMismatch
	}
	if err := verifyFiveCopyPolicyV1(input.policies); err != nil {
		return ErrDowngradeRejected
	}
	for _, support := range []ImplementationSupportV1{r.clientSupport, r.relaySupport} {
		if err := verifyUniversalSupportV1(support, selectedPolicy, input.selectedCapabilities, input.clientBinding, input.relayBinding); err != nil {
			return err
		}
	}
	if err := verifyDowngradeSupportV1(r.clientSupport, r.relaySupport, selectedPolicy, input.clientRequired, input.relayRequired); err != nil {
		return err
	}
	if len(input.clientOffered) != 0 || len(input.relayOffered) != 0 {
		if err := verifyCapabilitySelectionV1(selectedPolicy, input); err != nil {
			return err
		}
	}
	if selectedPolicy.CapabilityNegotiationPolicy == "profile_declared_required" {
		if !containsAllV1(input.selectedCapabilities, input.clientBinding.CompatibilityBlock.RequiredCapabilities) ||
			!containsAllV1(input.selectedCapabilities, input.relayBinding.CompatibilityBlock.RequiredCapabilities) {
			return ErrCapabilityRejected
		}
	}
	mode := selectedPolicy.TranscriptMode
	if mode == security.TranscriptCapabilitiesV1 || mode == security.TranscriptFullBindingV1 {
		if !verifyCapabilityTranscriptV1(r.clientSupport, input.clientBinding, input.relayBinding) ||
			!verifyCapabilityTranscriptV1(r.relaySupport, input.clientBinding, input.relayBinding) {
			return ErrCapabilityTranscriptInvalid
		}
	}
	if mode == security.TranscriptCarrierBindingV1 || mode == security.TranscriptFullBindingV1 {
		if !verifyCarrierBindingV1(r.clientSupport, input.clientBinding, input.relayBinding) ||
			!verifyCarrierBindingV1(r.relaySupport, input.clientBinding, input.relayBinding) {
			return ErrCarrierBindingInvalid
		}
	}
	if mode == security.TranscriptFullBindingV1 {
		if !matchesFullAuthorizationV1(clientEntry, input.clientBinding) ||
			!matchesFullAuthorizationV1(relayEntry, input.relayBinding) {
			return ErrFullBindingInvalid
		}
	}
	if selectedPolicy.ProfileCompatibilityPolicy == "schema_and_feature" || selectedPolicy.ProfileCompatibilityPolicy == "full_policy_binding" {
		for _, support := range []ImplementationSupportV1{r.clientSupport, r.relaySupport} {
			if !verifySchemaAndFeatureV1(support, input.selectedCapabilities, input.clientBinding) ||
				!verifySchemaAndFeatureV1(support, input.selectedCapabilities, input.relayBinding) {
				return ErrProfileIncompatible
			}
		}
	}
	if selectedPolicy.ProfileCompatibilityPolicy == "full_policy_binding" {
		if !matchesFullPolicyAuthorizationV1(clientEntry, input.clientBinding) || !matchesFullPolicyAuthorizationV1(relayEntry, input.relayBinding) {
			return ErrProfileIncompatible
		}
	}
	return nil
}

func verifySchemaAndFeatureV1(s ImplementationSupportV1, selected []string, binding security.HandshakeModeBinding) bool {
	descriptorCapabilities := unionStringsV1(binding.CompatibilityBlock.RequiredCapabilities, unionStringsV1(binding.ClientOptional, binding.ServerOptional))
	if !containsAllV1(s.capabilities, selected) || !containsAllV1(descriptorCapabilities, selected) ||
		!containsStringV1(s.carrierFamilies, binding.CarrierFamily) || !containsStringV1(binding.CompatibilityBlock.SupportedCarrierFamilies, binding.CarrierFamily) ||
		!containsStringV1(s.adapterClasses, binding.LocalAdapterClass) || binding.ConfigSourceBlock.AdapterClass != binding.LocalAdapterClass {
		return false
	}
	for _, feature := range binding.FeatureVectors {
		switch {
		case strings.HasPrefix(feature, "carrier:"):
			value := strings.TrimPrefix(feature, "carrier:")
			if !containsStringV1(s.carrierFamilies, value) || !containsStringV1(binding.CompatibilityBlock.SupportedCarrierFamilies, value) {
				return false
			}
		case strings.HasPrefix(feature, "proxy:"):
			value := strings.TrimPrefix(feature, "proxy:")
			if !containsStringV1(s.proxyFeatures, value) || !containsStringV1(binding.CompatibilityBlock.SupportedProxyFeatures, value) {
				return false
			}
		case strings.HasPrefix(feature, "stream:"):
			value := strings.TrimPrefix(feature, "stream:")
			if !containsStringV1(s.streamFeatures, value) || !containsStringV1(binding.CompatibilityBlock.SupportedStreamFeatures, value) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func verifyFiveCopyPolicyV1(policies []ir.EffectiveSecurityPolicy) error {
	if len(policies) == 1 {
		_, err := security.EncodePolicyV1(policies[0])
		return err
	}
	want, err := security.EncodePolicyV1(policies[len(policies)-1])
	if err != nil {
		return err
	}
	for _, policy := range policies[:len(policies)-1] {
		raw, err := security.EncodePolicyV1(policy)
		if err != nil || !bytes.Equal(raw, want) {
			return ErrDowngradeRejected
		}
	}
	return nil
}

func verifyUniversalSupportV1(s ImplementationSupportV1, policy ir.EffectiveSecurityPolicy, selected []string, client, relay security.HandshakeModeBinding) error {
	suite := security.SelectedSuiteV1{KDFSuite: policy.KDFSuite, AEADSuite: policy.AEADSuite, MACSuite: policy.MACSuite}
	if !containsStringV1(s.schemaVersions, policy.SchemaVersion) ||
		!containsStringV1(s.compilerSecurityVersions, policy.CompilerSecurityVersion) ||
		!containsStringV1(s.minimumRuntimeVersions, policy.MinimumRuntimeVersion) ||
		!containsStringV1(s.securityVersions, policy.SecurityVersion) || !containsSuiteV1(s.suites, suite) ||
		!containsStringV1(s.securitySuiteIDs, ir.SecuritySuiteString()) {
		return ErrProfileIncompatible
	}
	if !containsStringV1(s.transcriptModes, policy.TranscriptMode) {
		return ErrTranscriptMismatch
	}
	if !containsStringV1(s.downgradePolicies, policy.DowngradePolicy) {
		return ErrDowngradeRejected
	}
	if !containsStringV1(s.capabilityPolicies, policy.CapabilityNegotiationPolicy) {
		return ErrCapabilityRejected
	}
	if !containsStringV1(s.nonceModes, policy.NonceMode) || !containsStringV1(s.replayPolicies, policy.ReplayPolicy) ||
		!containsStringV1(s.profilePolicies, policy.ProfileCompatibilityPolicy) ||
		!containsStringV1(s.rotationPolicies, policy.KeyRotationPolicy) ||
		!containsStringV1(s.configPolicies, policy.ConfigValidationPolicy) ||
		!containsStringV1(s.envelopeModes, policy.SecureEnvelopeMode) {
		return ErrProfileIncompatible
	}
	if policy.ReplayWindowSize < 2 || uint64(policy.ReplayWindowSize) > uint64(s.maxReplayWindow) ||
		policy.MaxSessionMessages <= 0 || uint64(policy.MaxSessionMessages) > s.maxSessionMessages ||
		policy.MaxKeyLifetimeMessages <= 0 || uint64(policy.MaxKeyLifetimeMessages) > s.maxKeyLifetimeMessages ||
		policy.MaxKeyLifetimeMessages > policy.MaxSessionMessages {
		return ErrProfileIncompatible
	}
	if !canonicalNonemptyStringsV1(selected) || !allSupportedStringsV1(s.capabilities, selected) {
		return ErrCapabilityRejected
	}
	for _, binding := range []security.HandshakeModeBinding{client, relay} {
		if binding.CompatibilityBlock.SchemaVersion != policy.SchemaVersion ||
			binding.CompatibilityBlock.CompilerSecurityVersion != policy.CompilerSecurityVersion ||
			binding.CompatibilityBlock.MinimumRuntimeVersion != policy.MinimumRuntimeVersion ||
			!containsStringV1(s.schemaVersions, binding.CompatibilityBlock.SchemaVersion) ||
			!containsStringV1(s.compilerSecurityVersions, binding.CompatibilityBlock.CompilerSecurityVersion) ||
			!containsStringV1(s.minimumRuntimeVersions, binding.CompatibilityBlock.MinimumRuntimeVersion) ||
			binding.ConfigSourceBlock.SecurityVersion != policy.SecurityVersion ||
			binding.ConfigSourceBlock.SelectedSuite != suite {
			return ErrProfileIncompatible
		}
		carrierComponentInvalid := !containsStringV1(s.carrierFamilies, binding.CarrierFamily) ||
			!containsStringV1(s.adapterClasses, binding.LocalAdapterClass) ||
			binding.EnvelopeLimit == 0 || binding.EnvelopeLimit > s.maxEnvelopeBytes ||
			binding.MaxFrameBytes == 0 || binding.MaxFrameBytes > s.maxFrameBytes ||
			binding.EnvelopeLimit > binding.MaxFrameBytes ||
			binding.LimitBlock.SessionMaxConcurrentStreams == 0 || binding.LimitBlock.SessionMaxConcurrentStreams > s.maxStreams ||
			binding.LimitBlock.MaxFrameBytes != binding.MaxFrameBytes ||
			binding.LimitBlock.CarrierMaxEnvelopeBytes != binding.EnvelopeLimit
		if carrierComponentInvalid && policy.TranscriptMode != security.TranscriptCarrierBindingV1 && policy.TranscriptMode != security.TranscriptFullBindingV1 {
			return ErrProfileIncompatible
		}
		// The selected suite must be advertised. Other advertised suites remain
		// inactive here and are not treated as selected by strict_schema.
		if !containsStringV1(binding.CompatibilityBlock.SupportedSecuritySuites, ir.SecuritySuiteString()) {
			return ErrProfileIncompatible
		}
	}
	return nil
}

func verifyDowngradeSupportV1(client, relay ImplementationSupportV1, policy ir.EffectiveSecurityPolicy, clientFloor, relayFloor []string) error {
	suite := security.SelectedSuiteV1{KDFSuite: policy.KDFSuite, AEADSuite: policy.AEADSuite, MACSuite: policy.MACSuite}
	if policy.DowngradePolicy == "strict_suite_and_capabilities" && len(clientFloor) != 0 && !equalStringsV1(clientFloor, relayFloor) {
		return ErrDowngradeRejected
	}
	if policy.DowngradePolicy == "suite_bound_transcript" &&
		(!containsTupleV1(client.suiteTranscriptPairs, suite, policy.TranscriptMode) ||
			!containsTupleV1(relay.suiteTranscriptPairs, suite, policy.TranscriptMode)) {
		return ErrDowngradeRejected
	}
	return nil
}

func verifyCapabilitySelectionV1(policy ir.EffectiveSecurityPolicy, input supportAuthorizationInputV1) error {
	if !canonicalNonemptyStringsV1(input.clientOffered) || !canonicalNonemptyStringsV1(input.relayOffered) ||
		!canonicalNonemptyStringsV1(input.clientRequired) || !canonicalNonemptyStringsV1(input.relayRequired) {
		return ErrCapabilityRejected
	}
	floor := unionStringsV1(input.clientRequired, input.relayRequired)
	if !containsAllV1(input.clientOffered, floor) || !containsAllV1(input.relayOffered, floor) {
		return ErrDowngradeRejected
	}
	var want []string
	switch policy.CapabilityNegotiationPolicy {
	case "strict_required":
		want = floor
	case "intersection_with_required", "profile_declared_required":
		want = intersectionStringsV1(input.clientOffered, input.relayOffered)
	default:
		return ErrCapabilityRejected
	}
	if !equalStringsV1(want, input.selectedCapabilities) {
		return ErrCapabilityRejected
	}
	return nil
}

func verifyCapabilityTranscriptV1(s ImplementationSupportV1, bindings ...security.HandshakeModeBinding) bool {
	for _, binding := range bindings {
		for _, values := range [][]string{binding.ClientOptional, binding.ServerOptional} {
			if !canonicalStringsV1(values) || !allSupportedStringsV1(s.capabilities, values) {
				return false
			}
		}
		if !canonicalNonemptyStringsV1(binding.FeatureVectors) ||
			!supportedFeaturePrefixV1(s, s.proxyFeatures, "proxy:", binding.FeatureVectors) ||
			!supportedFeaturePrefixV1(s, s.streamFeatures, "stream:", binding.FeatureVectors) ||
			!knownCapabilityFeaturePrefixesV1(binding.FeatureVectors) ||
			!canonicalStringsV1(binding.CompatibilityBlock.SupportedProxyFeatures) ||
			!allSupportedStringsV1(s.proxyFeatures, binding.CompatibilityBlock.SupportedProxyFeatures) ||
			!canonicalStringsV1(binding.CompatibilityBlock.SupportedStreamFeatures) ||
			!allSupportedStringsV1(s.streamFeatures, binding.CompatibilityBlock.SupportedStreamFeatures) {
			return false
		}
	}
	return true
}

func verifyCarrierBindingV1(s ImplementationSupportV1, bindings ...security.HandshakeModeBinding) bool {
	for _, binding := range bindings {
		if !containsStringV1(s.carrierFamilies, binding.CarrierFamily) ||
			!containsStringV1(s.adapterClasses, binding.LocalAdapterClass) ||
			!containsHashV1(s.carrierPolicyHashes, binding.CarrierPolicyHash) ||
			!canonicalNonemptyStringsV1(binding.FeatureVectors) ||
			!supportedFeaturePrefixV1(s, s.carrierFamilies, "carrier:", binding.FeatureVectors) ||
			!canonicalNonemptyStringsV1(binding.CompatibilityBlock.SupportedCarrierFamilies) ||
			!allSupportedStringsV1(s.carrierFamilies, binding.CompatibilityBlock.SupportedCarrierFamilies) ||
			binding.EnvelopeLimit == 0 || binding.EnvelopeLimit > s.maxEnvelopeBytes ||
			binding.MaxFrameBytes == 0 || binding.MaxFrameBytes > s.maxFrameBytes || binding.EnvelopeLimit > binding.MaxFrameBytes ||
			binding.CompatibilityBlock.MaxEnvelopeBytes == 0 || binding.CompatibilityBlock.MaxEnvelopeBytes > s.maxEnvelopeBytes ||
			binding.CompatibilityBlock.MaxStreamCount == 0 || binding.CompatibilityBlock.MaxStreamCount > s.maxStreams ||
			binding.CompatibilityBlock.MaxReplayWindow < 2 || binding.CompatibilityBlock.MaxReplayWindow > s.maxReplayWindow ||
			binding.LimitBlock.CarrierMaxEnvelopeBytes != binding.EnvelopeLimit ||
			binding.LimitBlock.MaxFrameBytes != binding.MaxFrameBytes ||
			binding.LimitBlock.CarrierMaxQueueDepth == 0 || binding.LimitBlock.CarrierMaxQueueDepth > s.maxQueueDepth ||
			binding.LimitBlock.SessionMaxConcurrentStreams == 0 || binding.LimitBlock.SessionMaxConcurrentStreams > s.maxStreams {
			return false
		}
	}
	return true
}

// FeatureVectors retains all three namespaces. Each transcript mode consumes
// only its own namespace so inactive carrier metadata cannot bleed into the
// capabilities mode, and inactive proxy/stream metadata cannot bleed into the
// carrier mode.
func supportedFeaturePrefixV1(s ImplementationSupportV1, supported []string, prefix string, values []string) bool {
	for _, value := range values {
		if !strings.HasPrefix(value, prefix) {
			continue
		}
		if !containsStringV1(s.featureVectors, value) || !containsStringV1(supported, strings.TrimPrefix(value, prefix)) {
			return false
		}
	}
	return true
}

func knownCapabilityFeaturePrefixesV1(values []string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, "proxy:") || strings.HasPrefix(value, "stream:") || strings.HasPrefix(value, "carrier:") {
			continue
		}
		return false
	}
	return true
}

func containsHashV1(values [][32]byte, value [32]byte) bool {
	for _, candidate := range values {
		if equal32V1(candidate, value) {
			return true
		}
	}
	return false
}

func matchesFullAuthorizationV1(entry profileAuthorizationEntryV1, binding security.HandshakeModeBinding) bool {
	return equal32V1(entry.framingPolicyHash, binding.FramingPolicyHash) &&
		equal32V1(entry.stateMachinePolicyHash, binding.StateMachinePolicyHash) &&
		equal32V1(entry.schedulerPolicyHash, binding.SchedulerPolicyHash) &&
		equal32V1(entry.paddingPolicyHash, binding.PaddingPolicyHash) &&
		equal32V1(entry.streamPolicyHash, binding.StreamPolicyHash) &&
		equal32V1(entry.proxyPolicyHash, binding.ProxyPolicyHash) &&
		equal32V1(entry.carrierContextPolicyHash, binding.CarrierContextHash)
}

func matchesFullPolicyAuthorizationV1(entry profileAuthorizationEntryV1, binding security.HandshakeModeBinding) bool {
	return entry.replayWindowSize == binding.CompatibilityBlock.MaxReplayWindow &&
		entry.maxConcurrentStreams == binding.LimitBlock.SessionMaxConcurrentStreams &&
		entry.maxFrameBytes == binding.MaxFrameBytes && entry.maxEnvelopeBytes == binding.EnvelopeLimit &&
		matchesFullAuthorizationV1(entry, binding)
}

func equal32V1(left, right [32]byte) bool {
	return hmac.Equal(left[:], right[:])
}

func allSupportedStringsV1(supported, values []string) bool {
	for _, value := range values {
		if !containsStringV1(supported, value) {
			return false
		}
	}
	return true
}

func canonicalStringsV1(values []string) bool {
	if len(values) > implementationSupportListCapacityV1 {
		return false
	}
	for i, value := range values {
		if value == "" || !printableASCIIV1(value) || (i > 0 && values[i-1] >= value) {
			return false
		}
	}
	return true
}

func equalStringsV1(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func containsAllV1(values, required []string) bool {
	for _, value := range required {
		if !containsStringV1(values, value) {
			return false
		}
	}
	return true
}

func unionStringsV1(left, right []string) []string {
	out := append(append([]string(nil), left...), right...)
	sort.Strings(out)
	compact := out[:0]
	for _, value := range out {
		if len(compact) == 0 || compact[len(compact)-1] != value {
			compact = append(compact, value)
		}
	}
	return compact
}

func intersectionStringsV1(left, right []string) []string {
	out := make([]string, 0)
	for _, value := range left {
		if containsStringV1(right, value) {
			out = append(out, value)
		}
	}
	return out
}

func zero32V1(value [32]byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
