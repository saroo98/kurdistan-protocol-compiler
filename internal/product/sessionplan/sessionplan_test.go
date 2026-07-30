// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package sessionplan

import (
	"errors"
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/livecarrier"
	"kurdistan/internal/product/relaydescriptor"
	"kurdistan/internal/product/strategy"
)

func validRequest(t *testing.T) Request {
	t.Helper()
	state := lifecycle.State{
		Status: lifecycle.Admitted, ProfileID: "profile", Scope: "scope",
		EvidenceReference: "evidence", Generation: 7,
	}
	strategyRequest := strategy.Request{
		Lifecycle: state,
		Policy: strategy.Policy{
			Version: strategy.Version, ProfileID: state.ProfileID, Scope: state.Scope,
			EvidenceReference: state.EvidenceReference, Generation: state.Generation,
			MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2,
			Permitted: []strategy.Candidate{{
				Family: carrierreview.FamilyHTTPSLikeTCP, RequiredCapabilities: []string{"cap-a"},
				MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2,
			}},
		},
		Client: strategy.Client{
			SupportedVersion:  strategy.Version,
			SupportedFamilies: []string{carrierreview.FamilyHTTPSLikeTCP},
			Capabilities:      []string{"cap-a"}, SafetyFloor: 2, PrivacyFloor: 2,
		},
	}
	selected, err := strategy.Select(strategyRequest)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := relaydescriptor.Descriptor{
		Version: relaydescriptor.Version, DescriptorID: "relay-1",
		ProfileID: state.ProfileID, Scope: state.Scope, EvidenceReference: state.EvidenceReference,
		Generation: state.Generation, Family: selected.SelectedFamily, ClientID: "client",
		ClientCapabilities: []string{"cap-a"}, EndpointReference: "relayref:owned-relay-1",
		NotBefore: 100, ExpiresAt: 300,
	}
	relayRequest := relaydescriptor.Request{
		Version: relaydescriptor.Version, StrategyRequest: strategyRequest, ClaimedResult: selected,
		EvaluationTime: 200, Client: relaydescriptor.ClientBinding{ID: "client"},
		Policy: relaydescriptor.Policy{
			Version: relaydescriptor.Version, ProfileID: state.ProfileID, Scope: state.Scope,
			EvidenceReference: state.EvidenceReference, Generation: state.Generation,
			FallbackPolicy: strategyRequest.Policy, SelectedFamily: selected.SelectedFamily,
			ClientCapabilities: []string{"cap-a"}, AuthorizedClientIDs: []string{"client"},
			AuthorizedDescriptors: []relaydescriptor.Descriptor{descriptor},
		},
		Revocation: relaydescriptor.RevocationState{
			Version: relaydescriptor.Version, Complete: true, ProfileID: state.ProfileID,
			Scope: state.Scope, EvidenceReference: state.EvidenceReference,
			Generation: state.Generation, EvaluatedAt: 200,
		},
		Descriptors: []relaydescriptor.Descriptor{descriptor},
	}
	admitted, err := relaydescriptor.Admit(relayRequest)
	if err != nil {
		t.Fatal(err)
	}
	return Request{
		StrategyRequest: strategyRequest, ClaimedStrategy: selected,
		RelayRequest: relayRequest, ClaimedAdmission: admitted,
		DescriptorID: "relay-1", DialTimeoutMs: 5_000, MaxFrameBytes: 64 << 10,
	}
}

func TestBuildRecomputesAuthorityAndProducesStableDigest(t *testing.T) {
	req := validRequest(t)
	first, err := Build(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(req)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.Digest == ([32]byte{}) {
		t.Fatalf("unstable or empty plan digest: first=%+v second=%+v", first, second)
	}
	if first.EndpointReference != "relayref:owned-relay-1" ||
		first.StrategyFamily != carrierreview.FamilyHTTPSLikeTCP ||
		first.CarrierFamily != livecarrier.FamilyKurdTLS13TCP || !first.LoopbackOnly {
		t.Fatalf("unexpected plan: %+v", first)
	}
}

func TestBuildRejectsForgedOrMixedAuthority(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Request)
		want error
	}{
		{"forged strategy", func(req *Request) { req.ClaimedStrategy.SelectedFamily = carrierreview.FamilyRelayBridgeRotation }, ErrStrategy},
		{"mixed strategy request", func(req *Request) { req.RelayRequest.StrategyRequest.Lifecycle.Generation++ }, ErrInconsistent},
		{"forged admission", func(req *Request) { req.ClaimedAdmission.Generation++ }, ErrRelay},
		{"unadmitted descriptor", func(req *Request) { req.DescriptorID = "relay-2" }, ErrDescriptor},
		{"unbounded timeout", func(req *Request) { req.DialTimeoutMs = maxDialMillis + 1 }, ErrInvalid},
		{"unbounded frame", func(req *Request) { req.MaxFrameBytes = maxFrameBytes + 1 }, ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := validRequest(t)
			test.edit(&req)
			if _, err := Build(req); !errors.Is(err, test.want) {
				t.Fatalf("Build error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestDigestBindsEveryExecutionField(t *testing.T) {
	baseline, err := Build(validRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Request){
		func(req *Request) { req.DialTimeoutMs++ },
		func(req *Request) { req.MaxFrameBytes++ },
		func(req *Request) {
			req.RelayRequest.Descriptors[0].EndpointReference = "relayref:owned-relay-2"
			req.RelayRequest.Policy.AuthorizedDescriptors[0] = req.RelayRequest.Descriptors[0]
			req.ClaimedAdmission, _ = relaydescriptor.Admit(req.RelayRequest)
		},
	}
	for index, mutate := range mutations {
		req := validRequest(t)
		mutate(&req)
		changed, err := Build(req)
		if err != nil {
			t.Fatalf("mutation %d: %v", index, err)
		}
		if changed.Digest == baseline.Digest {
			t.Fatalf("mutation %d did not change digest", index)
		}
	}
}

func TestValidateRejectsEveryMutatedExecutionField(t *testing.T) {
	plan, err := Build(validRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(plan); err != nil {
		t.Fatalf("built plan was rejected: %v", err)
	}
	mutations := map[string]func(*Plan){
		"profile":      func(value *Plan) { value.ProfileID += "-changed" },
		"generation":   func(value *Plan) { value.Generation++ },
		"strategy":     func(value *Plan) { value.StrategyFamily += "-changed" },
		"carrier":      func(value *Plan) { value.CarrierFamily += "-changed" },
		"loopback":     func(value *Plan) { value.LoopbackOnly = !value.LoopbackOnly },
		"descriptor":   func(value *Plan) { value.DescriptorID += "-changed" },
		"endpoint":     func(value *Plan) { value.EndpointReference += "-changed" },
		"dial timeout": func(value *Plan) { value.DialTimeoutMs++ },
		"frame bound":  func(value *Plan) { value.MaxFrameBytes++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := plan
			mutate(&changed)
			if err := Validate(changed); err == nil {
				t.Fatal("mutated plan was accepted")
			}
		})
	}
}
