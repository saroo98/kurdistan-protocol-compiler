// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

type runtimeLabIdentityV1 struct {
	id  string
	key ed25519.PrivateKey
}

func (p runtimeLabIdentityV1) Local(id string) (ed25519.PrivateKey, error) {
	if id != p.id {
		return nil, errors.New("unknown identity")
	}
	return append(ed25519.PrivateKey(nil), p.key...), nil
}

type runtimeLabTrustV1 struct {
	id  string
	key ed25519.PublicKey
}

func (p runtimeLabTrustV1) Peer(id string) (ed25519.PublicKey, error) {
	if id != p.id {
		return nil, errors.New("unknown peer")
	}
	return append(ed25519.PublicKey(nil), p.key...), nil
}

func NewRuntimeLabEndpointPairV1(seed int64) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error) {
	if seed == 0 {
		return nil, nil, ErrConfigInvalid
	}
	profile, err := compiler.Generate(seed)
	if err != nil {
		return nil, nil, err
	}
	profile.Security.TranscriptMode = security.TranscriptCanonicalV1
	profile.Security.NonceMode = "counter_xor_base"
	profile.Security.ReplayPolicy = "ordered_only"
	profile.Security.DowngradePolicy = "strict_suite_and_capabilities"
	profile.Security.CapabilityNegotiationPolicy = "strict_required"
	profile.Security.ProfileCompatibilityPolicy = "strict_schema"
	profile.Security.KeyRotationPolicy = "message_lifetime_bound"
	profile.Security.ConfigValidationPolicy = "strict_required"
	profile.Security.SecureEnvelopeMode = "metadata_authenticated"
	profile.GenerationHash = ""
	profile.GenerationHash, err = ir.CanonicalHash(profile)
	if err != nil {
		return nil, nil, err
	}
	capabilities := append([]string(nil), ir.SecurityCapabilities()...)
	sort.Strings(capabilities)
	floor := append([]string(nil), capabilities[:2]...)
	policy, err := ir.BuildEffectiveSecurityPolicy(profile, floor, floor, floor)
	if err != nil {
		return nil, nil, err
	}
	clientPeer, err := auth.NewPeerParameters("lab-client", profile, policy, policy, capabilities, floor)
	if err != nil {
		return nil, nil, err
	}
	relayPeer, err := auth.NewPeerParameters("lab-relay", profile, policy, policy, capabilities, floor)
	if err != nil {
		return nil, nil, err
	}
	clientPrivate := runtimeLabPrivateKeyV1(seed, 1)
	relayPrivate := runtimeLabPrivateKeyV1(seed, 2)
	defer clear(clientPrivate)
	defer clear(relayPrivate)
	clientDeps := auth.Dependencies{Identity: runtimeLabIdentityV1{"lab-client", clientPrivate}, Trust: runtimeLabTrustV1{"lab-relay", relayPrivate.Public().(ed25519.PublicKey)}}
	relayDeps := auth.Dependencies{Identity: runtimeLabIdentityV1{"lab-relay", relayPrivate}, Trust: runtimeLabTrustV1{"lab-client", clientPrivate.Public().(ed25519.PublicKey)}}
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		return nil, nil, err
	}
	contact := auth.FirstContactInput{Client: clientPeer, Server: relayPeer, SelectedPolicy: policy, SelectedCapabilities: append([]string(nil), floor...), ClientDependencies: clientDeps, ServerDependencies: relayDeps, Replay: replay}
	snapshot, view, err := auth.SnapshotFirstContactInputV1(contact)
	if err != nil {
		return nil, nil, err
	}
	policyHash, err := security.EffectivePolicyHashV1(policy)
	if err != nil {
		return nil, nil, err
	}
	clientEntry := ClientProfileAuthorizationEntryV1{ProfileHash: snapshot.Client.ProfileHash, EffectivePolicyHash: policyHash, ReplayWindowSize: uint32(policy.ReplayWindowSize), MaxConcurrentStreams: view.ClientModeBinding.LimitBlock.SessionMaxConcurrentStreams, MaxFrameBytes: view.ClientModeBinding.MaxFrameBytes, MaxEnvelopeBytes: view.ClientModeBinding.EnvelopeLimit, FramingPolicyHash: view.ClientModeBinding.FramingPolicyHash, StateMachinePolicyHash: view.ClientModeBinding.StateMachinePolicyHash, SchedulerPolicyHash: view.ClientModeBinding.SchedulerPolicyHash, PaddingPolicyHash: view.ClientModeBinding.PaddingPolicyHash, StreamPolicyHash: view.ClientModeBinding.StreamPolicyHash, ProxyPolicyHash: view.ClientModeBinding.ProxyPolicyHash, CarrierContextPolicyHash: view.ClientModeBinding.CarrierContextHash}
	relayEntry := RelayProfileAuthorizationEntryV1{ProfileHash: snapshot.Server.ProfileHash, EffectivePolicyHash: policyHash, ReplayWindowSize: uint32(policy.ReplayWindowSize), MaxConcurrentStreams: view.ServerModeBinding.LimitBlock.SessionMaxConcurrentStreams, MaxFrameBytes: view.ServerModeBinding.MaxFrameBytes, MaxEnvelopeBytes: view.ServerModeBinding.EnvelopeLimit, FramingPolicyHash: view.ServerModeBinding.FramingPolicyHash, StateMachinePolicyHash: view.ServerModeBinding.StateMachinePolicyHash, SchedulerPolicyHash: view.ServerModeBinding.SchedulerPolicyHash, PaddingPolicyHash: view.ServerModeBinding.PaddingPolicyHash, StreamPolicyHash: view.ServerModeBinding.StreamPolicyHash, ProxyPolicyHash: view.ServerModeBinding.ProxyPolicyHash, CarrierContextPolicyHash: view.ServerModeBinding.CarrierContextHash}
	clientRegistry, err := NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{clientEntry})
	if err != nil {
		return nil, nil, err
	}
	relayRegistry, err := NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{relayEntry})
	if err != nil {
		return nil, nil, err
	}
	input := PairInputV1{FirstContactInput: contact, ClientControls: ClientLocalRuntimeControlsV1{RuntimeID: "lab-client", EventCapacity: 32, QueueCeiling: 2}, RelayControls: RelayLocalRuntimeControlsV1{RuntimeID: "lab-relay", EventCapacity: 32, QueueCeiling: 2}}
	probe, err := NewStrictHandshakeRuntimeV1(clientDeps, relayDeps, clientRegistry, relayRegistry)
	if err != nil {
		return nil, nil, err
	}
	_, context, err := probe.strictFirstContactWithContextV1(input.FirstContactInput)
	if err != nil {
		return nil, nil, err
	}
	clientValue, err := strictConfigFromContextV1(context, true)
	if err != nil {
		return nil, nil, err
	}
	relayValue, err := strictConfigFromContextV1(context, false)
	if err != nil {
		return nil, nil, err
	}
	input.ClientConfig, err = NewClientStrictSessionConfigV1(clientValue)
	if err != nil {
		return nil, nil, err
	}
	input.RelayConfig, err = NewRelayStrictSessionConfigV1(relayValue)
	if err != nil {
		return nil, nil, err
	}
	input.FirstContactInput.Replay, err = auth.NewHandshakeReplayCache(64)
	if err != nil {
		return nil, nil, err
	}
	owner, err := NewStrictHandshakeRuntimeV1(clientDeps, relayDeps, clientRegistry, relayRegistry)
	if err != nil {
		return nil, nil, err
	}
	client, relay, err := owner.NewAuthenticatedChannelPair(input)
	if err != nil {
		return nil, nil, err
	}
	return client, relay, nil
}

func runtimeLabPrivateKeyV1(seed int64, role byte) ed25519.PrivateKey {
	var raw [9]byte
	binary.BigEndian.PutUint64(raw[:8], uint64(seed))
	raw[8] = role
	sum := sha256.Sum256(raw[:])
	return ed25519.NewKeyFromSeed(sum[:])
}
