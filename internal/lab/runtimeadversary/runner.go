// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimeadversary

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/runtime/labfault"
	"kurdistan/internal/testkit/mutant"
)

type RealMutantCorpusRowV1 struct {
	Mode, Family, Owner, Category, Detector string
	PairShaped                              bool
	ExpectedCount                           uint32
}

type RealMutantCorpusResultV1 struct {
	Mode, Category, Detector                  string
	UnsafeObserved, DetectorRed, ControlGreen bool
	Count                                     uint32
}

var realMutantCorpusRowsV1 = []RealMutantCorpusRowV1{
	{mutant.ModeNoTranscriptBinding, "security", "auth", "transcript", "transcript_changed", false, 1},
	{mutant.ModeReusedNonce, "security", "runtime", "nonce", "collision", true, 1},
	{mutant.ModeAcceptsReplay, "security", "runtime", "security_replay", "duplicate_accepted", true, 1},
	{mutant.ModeAcceptsDowngrade, "security", "auth", "downgrade", "invalid_offer_accepted", false, 1},
	{mutant.ModeCapabilityMismatchAccepted, "security", "auth", "capability", "mismatch_accepted", false, 1},
	{mutant.ModeProfileMismatchAccepted, "security", "auth", "profile", "mismatch_accepted", false, 1},
	{mutant.ModeUnsafeConfigAllowed, "security", "auth", "config", "unsafe_allowed", false, 1},
	{mutant.ModeSecretTraceLeak, "security", "runtime", "trace", "canary_detected", false, 1},
	{mutant.ModeRuntimeAcceptsCapabilityDowngrade, "runtime", "auth", "runtime_capability", "mismatch_repaired", false, 1},
	{mutant.ModeRuntimeAcceptsProfileMismatch, "runtime", "auth", "runtime_profile", "mismatch_repaired", false, 1},
	{mutant.ModeRuntimeAcceptsReplay, "runtime", "runtime", "runtime_replay", "retry_accepted", true, 1},
	{mutant.ModeRuntimeIgnoresBackpressure, "runtime", "runtime", "backpressure", "overflow_accepted", false, 2},
	{mutant.ModeRuntimeLeaksSecretTrace, "runtime", "runtime", "trace", "canary_detected", false, 1},
	{mutant.ModeRuntimeLeaksPayloadTrace, "runtime", "runtime", "trace", "canary_detected", false, 1},
	{mutant.ModeRuntimeNoStateValidation, "runtime", "runtime", "state", "invalid_state_accepted", true, 1},
	{mutant.ModeRuntimePaddingOnlyDiversity, "runtime", "runtime", "padding", "padding_only_accepted", true, 2},
}

func RealMutantCorpusTableV1() []RealMutantCorpusRowV1 {
	return append([]RealMutantCorpusRowV1(nil), realMutantCorpusRowsV1...)
}

func RunRealMutantCorpusV1(seed int64) ([]RealMutantCorpusResultV1, error) {
	if seed == 0 {
		return nil, mutant.ErrInvalidLabFault
	}
	results := make([]RealMutantCorpusResultV1, 0, len(realMutantCorpusRowsV1))
	for i, row := range realMutantCorpusRowsV1 {
		var result RealMutantCorpusResultV1
		var err error
		if row.Owner == "runtime" {
			result, err = runRealRuntimeMutantV1(seed+int64(i)*2, row)
		} else {
			result, err = runRealAuthMutantV1(seed+int64(i)*2, row)
		}
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func runRealRuntimeMutantV1(seed int64, row RealMutantCorpusRowV1) (RealMutantCorpusResultV1, error) {
	token, err := mutant.AcquireRuntimeLabFaultV1(row.Mode)
	if err != nil {
		return RealMutantCorpusResultV1{}, err
	}
	var client *kruntime.ClientAuthenticatedEndpointV1
	var relay *kruntime.RelayAuthenticatedEndpointV1
	if row.PairShaped {
		client, relay, err = kruntime.NewRuntimeLabEndpointPairV1(seed)
		if err != nil {
			return RealMutantCorpusResultV1{}, err
		}
	}
	observation, err := kruntime.ExecuteRuntimeLabFaultV1(token, client, relay)
	if err != nil {
		return RealMutantCorpusResultV1{}, err
	}
	var controlClient *kruntime.ClientAuthenticatedEndpointV1
	var controlRelay *kruntime.RelayAuthenticatedEndpointV1
	if row.PairShaped {
		controlClient, controlRelay, err = kruntime.NewRuntimeLabEndpointPairV1(seed)
		if err != nil {
			return RealMutantCorpusResultV1{}, err
		}
		defer controlClient.Close()
		defer controlRelay.Close()
	}
	control, controlErr := kruntime.ExecuteRuntimeLabFaultV1(labfault.Token{}, controlClient, controlRelay)
	// Green means the zero token is rejected before any owner fault executes;
	// the zero observation proves no unsafe effect was produced.
	green := controlErr != nil && control == (kruntime.RuntimeLabFaultObservationV1{})
	return RealMutantCorpusResultV1{Mode: row.Mode, Category: observation.Category, Detector: row.Detector, UnsafeObserved: observation.UnsafeObserved, DetectorRed: observation.UnsafeObserved && observation.Count > 0, ControlGreen: green, Count: observation.Count}, nil
}

func runRealAuthMutantV1(seed int64, row RealMutantCorpusRowV1) (RealMutantCorpusResultV1, error) {
	token, err := mutant.AcquireAuthFaultV1(row.Mode)
	if err != nil {
		return RealMutantCorpusResultV1{}, err
	}
	unsafe := false
	green := false
	switch row.Mode {
	case mutant.ModeNoTranscriptBinding:
		controlInput, err := realCorpusFirstContactInputV1(seed, "")
		if err != nil {
			return RealMutantCorpusResultV1{}, err
		}
		control, controlErr := auth.FirstContact(controlInput)
		faultInput, err := realCorpusFirstContactInputV1(seed, "")
		if err != nil {
			return RealMutantCorpusResultV1{}, err
		}
		faulted, faultErr := auth.FirstContactWithAuthLabFaultV1(faultInput, token)
		green = controlErr == nil
		unsafe = faultErr == nil && faulted.TranscriptHash != control.TranscriptHash
	case mutant.ModeAcceptsDowngrade, mutant.ModeCapabilityMismatchAccepted, mutant.ModeProfileMismatchAccepted:
		controlInput, err := realCorpusFirstContactInputV1(seed, row.Mode)
		if err != nil {
			return RealMutantCorpusResultV1{}, err
		}
		_, controlErr := auth.FirstContact(controlInput)
		faultInput, err := realCorpusFirstContactInputV1(seed, row.Mode)
		if err != nil {
			return RealMutantCorpusResultV1{}, err
		}
		faulted, faultErr := auth.FirstContactWithAuthLabFaultV1(faultInput, token)
		green = controlErr != nil
		unsafe = faultErr == nil && faulted.ClientState == auth.StateEstablished
	case mutant.ModeRuntimeAcceptsCapabilityDowngrade:
		faultInput, err := realCorpusFirstContactInputV1(seed, mutant.ModeCapabilityMismatchAccepted)
		if err != nil {
			return RealMutantCorpusResultV1{}, err
		}
		controlInput := faultInput
		green = !auth.RuntimeAcceptsCapabilityDowngradeAuthLabFaultV1(auth.AuthLabFaultToken{}, &controlInput)
		unsafe = auth.RuntimeAcceptsCapabilityDowngradeAuthLabFaultV1(token, &faultInput)
	case mutant.ModeRuntimeAcceptsProfileMismatch:
		faultInput, err := realCorpusFirstContactInputV1(seed, mutant.ModeProfileMismatchAccepted)
		if err != nil {
			return RealMutantCorpusResultV1{}, err
		}
		controlInput := faultInput
		green = !auth.RuntimeAcceptsProfileMismatchAuthLabFaultV1(auth.AuthLabFaultToken{}, &controlInput)
		unsafe = auth.RuntimeAcceptsProfileMismatchAuthLabFaultV1(token, &faultInput)
	case mutant.ModeUnsafeConfigAllowed:
		green = !auth.UnsafeConfigAllowedAuthLabFaultV1(auth.AuthLabFaultToken{})
		unsafe = auth.UnsafeConfigAllowedAuthLabFaultV1(token)
	}
	count := uint32(0)
	if unsafe {
		count = 1
	}
	return RealMutantCorpusResultV1{Mode: row.Mode, Category: row.Category, Detector: row.Detector, UnsafeObserved: unsafe, DetectorRed: unsafe, ControlGreen: green, Count: count}, nil
}

type realCorpusIdentityV1 struct {
	id   string
	seed int64
	role byte
}

func (p realCorpusIdentityV1) Local(id string) (ed25519.PrivateKey, error) {
	if id != p.id {
		return nil, errors.New("unknown identity")
	}
	return realCorpusPrivateKeyV1(p.seed, p.role), nil
}

type realCorpusTrustV1 struct {
	id  string
	key ed25519.PublicKey
}

func (p realCorpusTrustV1) Peer(id string) (ed25519.PublicKey, error) {
	if id != p.id {
		return nil, errors.New("unknown peer")
	}
	return append(ed25519.PublicKey(nil), p.key...), nil
}

func realCorpusFirstContactInputV1(seed int64, mutation string) (auth.FirstContactInput, error) {
	p, err := compiler.Generate(seed)
	if err != nil {
		return auth.FirstContactInput{}, err
	}
	p.Security.TranscriptMode = security.TranscriptCanonicalV1
	p.Security.NonceMode, p.Security.ReplayPolicy, p.Security.DowngradePolicy = "counter_xor_base", "ordered_only", "strict_suite_and_capabilities"
	p.Security.CapabilityNegotiationPolicy, p.Security.ProfileCompatibilityPolicy = "strict_required", "strict_schema"
	p.Security.KeyRotationPolicy, p.Security.ConfigValidationPolicy, p.Security.SecureEnvelopeMode = "message_lifetime_bound", "strict_required", "metadata_authenticated"
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		return auth.FirstContactInput{}, err
	}
	capabilities := append([]string(nil), ir.SecurityCapabilities()...)
	sort.Strings(capabilities)
	floor := append([]string(nil), capabilities[:2]...)
	policy, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, floor)
	if err != nil {
		return auth.FirstContactInput{}, err
	}
	client, err := auth.NewPeerParameters("corpus-client", p, policy, policy, capabilities, floor)
	if err != nil {
		return auth.FirstContactInput{}, err
	}
	relay, err := auth.NewPeerParameters("corpus-relay", p, policy, policy, capabilities, floor)
	if err != nil {
		return auth.FirstContactInput{}, err
	}
	clientKey, relayKey := realCorpusPrivateKeyV1(seed, 1), realCorpusPrivateKeyV1(seed, 2)
	clientPublic, relayPublic := append(ed25519.PublicKey(nil), clientKey.Public().(ed25519.PublicKey)...), append(ed25519.PublicKey(nil), relayKey.Public().(ed25519.PublicKey)...)
	clear(clientKey)
	clear(relayKey)
	clientDeps := auth.Dependencies{Identity: realCorpusIdentityV1{"corpus-client", seed, 1}, Trust: realCorpusTrustV1{"corpus-relay", relayPublic}}
	relayDeps := auth.Dependencies{Identity: realCorpusIdentityV1{"corpus-relay", seed, 2}, Trust: realCorpusTrustV1{"corpus-client", clientPublic}}
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		return auth.FirstContactInput{}, err
	}
	input := auth.FirstContactInput{Client: client, Server: relay, SelectedPolicy: policy, SelectedCapabilities: append([]string(nil), floor...), ClientDependencies: clientDeps, ServerDependencies: relayDeps, Replay: replay}
	switch mutation {
	case mutant.ModeAcceptsDowngrade:
		input.Client.OfferPolicy.NonceMode = "directional_counter"
	case mutant.ModeCapabilityMismatchAccepted:
		input.SelectedCapabilities = append(input.SelectedCapabilities, "transcript_binding")
	case mutant.ModeProfileMismatchAccepted:
		input.Server.ProfileHash[0] ^= 1
	}
	return input, nil
}

func realCorpusPrivateKeyV1(seed int64, role byte) ed25519.PrivateKey {
	var raw [9]byte
	binary.BigEndian.PutUint64(raw[:8], uint64(seed))
	raw[8] = role
	sum := sha256.Sum256(raw[:])
	return ed25519.NewKeyFromSeed(sum[:])
}

func RunScenario(ctx context.Context, p *ir.Profile, scenario Scenario) ScenarioRun {
	opts := kruntime.HarnessOptions{
		Scenario:       ProxyScenarioFor(scenario.Type),
		CarrierFamily:  scenario.CarrierFamily,
		StreamCount:    scenario.StreamCount,
		ReplayInject:   scenario.Type == ScenarioReplayInjection,
		LinkQueueDepth: scenario.QueueDepth,
	}
	if scenario.Type == ScenarioCapabilityDowngrade {
		opts.ServerFeatures = []string{"multi_stream"}
	}
	if scenario.Type == ScenarioProfileMismatchSession {
		other := *p
		other.ID = p.ID + "_mismatch"
		other.GenerationHash = ""
		opts.ProfileMismatch = &other
	}
	if scenario.Type == ScenarioMalformedLinkFrame {
		opts.ReplayInject = true
	}
	summary, events, err := kruntime.RunLocalHarness(ctx, p, opts)
	run := ScenarioRun{ProfileID: p.ID, Scenario: scenario.Type, Summary: summary, Events: events, Correct: err == nil}
	if err != nil {
		run.Failure = err.Error()
	}
	switch scenario.Type {
	case ScenarioCapabilityDowngrade, ScenarioProfileMismatchSession:
		run.Correct = err != nil
	case ScenarioReplayInjection, ScenarioMalformedLinkFrame:
		run.Correct = err == nil && summary.ReplayRejected > 0
	case ScenarioTargetErrorIsolation:
		run.Correct = err == nil && summary.TargetErrors > 0 && summary.ClientState == "closed"
	case ScenarioTargetResetIsolation:
		run.Correct = err == nil && summary.TargetResets > 0 && summary.ClientState == "closed"
	case ScenarioCarrierQueuePressure, ScenarioLargeObjectRuntime:
		run.Correct = err == nil && summary.BackpressureEvents > 0
	case ScenarioCloseRace:
		run.Correct = err == nil && summary.ClientState == "closed" && summary.ServerState == "closed"
	}
	return run
}

func RunScenarioCorpus(ctx context.Context, profiles []*ir.Profile, scenarios []Scenario) []ScenarioRun {
	runs := make([]ScenarioRun, 0, len(profiles)*len(scenarios))
	for _, p := range profiles {
		for _, scenario := range scenarios {
			runs = append(runs, RunScenario(ctx, p, scenario))
		}
	}
	return runs
}
