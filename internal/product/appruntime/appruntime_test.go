// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package appruntime

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/relaydescriptor"
	"kurdistan/internal/product/strategy"
)

func validRequest(t *testing.T) Request {
	t.Helper()
	state := lifecycle.State{
		Status: lifecycle.Admitted, ProfileID: "profile", Scope: "device",
		EvidenceReference: "evidence", Generation: 7,
	}
	strategyRequest := strategy.Request{
		Lifecycle: state,
		Policy: strategy.Policy{
			Version: strategy.Version, ProfileID: state.ProfileID, Scope: state.Scope,
			EvidenceReference: state.EvidenceReference, Generation: state.Generation,
			Permitted: []strategy.Candidate{{
				Family: carrierreview.FamilyHTTPSLikeTCP, RequiredCapabilities: []string{"capability"},
				MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2,
			}},
			MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2,
		},
		Client: strategy.Client{
			SupportedVersion: strategy.Version, SupportedFamilies: []string{carrierreview.FamilyHTTPSLikeTCP},
			Capabilities: []string{"capability"}, SafetyFloor: 2, PrivacyFloor: 2,
		},
	}
	selected, err := strategy.Select(strategyRequest)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := relaydescriptor.Descriptor{
		Version: relaydescriptor.Version, DescriptorID: "relay", ProfileID: state.ProfileID,
		Scope: state.Scope, EvidenceReference: state.EvidenceReference, Generation: state.Generation,
		Family: selected.SelectedFamily, ClientID: "client", ClientCapabilities: []string{"capability"},
		EndpointReference: "relayref:node_A7", NotBefore: 10, ExpiresAt: 20,
	}
	relayRequest := relaydescriptor.Request{
		Version: relaydescriptor.Version, StrategyRequest: strategyRequest, ClaimedResult: selected,
		EvaluationTime: 15, Client: relaydescriptor.ClientBinding{ID: "client"},
		Policy: relaydescriptor.Policy{
			Version: relaydescriptor.Version, ProfileID: state.ProfileID, Scope: state.Scope,
			EvidenceReference: state.EvidenceReference, Generation: state.Generation,
			FallbackPolicy: strategyRequest.Policy, SelectedFamily: selected.SelectedFamily,
			ClientCapabilities: []string{"capability"}, AuthorizedClientIDs: []string{"client"},
			AuthorizedDescriptors: []relaydescriptor.Descriptor{descriptor},
		},
		Revocation: relaydescriptor.RevocationState{
			Version: relaydescriptor.Version, Complete: true, ProfileID: state.ProfileID, Scope: state.Scope,
			EvidenceReference: state.EvidenceReference, Generation: state.Generation, EvaluatedAt: 15,
		},
		Descriptors: []relaydescriptor.Descriptor{descriptor},
	}
	admission, err := relaydescriptor.Admit(relayRequest)
	if err != nil {
		t.Fatal(err)
	}
	return Request{
		Version: Version, Intent: IntentConnect,
		Current: State{Version: Version, Kind: StateInactive}, RequestedGeneration: 1,
		Platform: PlatformSnapshot{
			Version: Version, PermissionStateKnown: true, VPNConsentGranted: true,
			ProtectedStorageAvailable: true, RoutingPolicySafe: true, DNSPolicySafe: true,
			KillSwitchAvailable: true,
		},
		Lifecycle: state, StrategyRequest: strategyRequest, ClaimedStrategyResult: selected,
		RelayRequest: relayRequest, ClaimedRelayAdmission: admission,
	}
}

func TestEvaluatorIntentsAndRecognizedCurrentStates(t *testing.T) {
	intents := map[Intent]Disposition{
		IntentEvaluate: DispositionRemainInactive,
		IntentConnect:  DispositionReadyToStart,
		IntentRecover:  DispositionReadyToStart,
	}
	states := []State{
		{Version: Version, Kind: StateInactive},
		{Version: Version, Kind: StateEligible, Generation: 4},
		{Version: Version, Kind: StateBlocked, Generation: 4},
	}
	for intent, disposition := range intents {
		for _, current := range states {
			t.Run(string(intent)+"/"+string(current.Kind), func(t *testing.T) {
				req := validRequest(t)
				req.Intent, req.Current, req.RequestedGeneration = intent, current, 5
				if current.Kind == StateInactive {
					req.RequestedGeneration = 1
				}
				got, err := Evaluate(req)
				if err != nil || got.Disposition != disposition || got.Reason != ReasonEligible ||
					got.Next.Kind != StateEligible || got.Next.Generation != req.RequestedGeneration {
					t.Fatalf("decision=%+v err=%v", got, err)
				}
			})
		}
	}
}

func TestMalformedTopLevelStateAndGenerationReject(t *testing.T) {
	tests := map[string]func(*Request){
		"empty request version": func(r *Request) { r.Version = "" },
		"newer request version": func(r *Request) { r.Version = Version + "-next" },
		"empty state version":   func(r *Request) { r.Current.Version = "" },
		"unknown state":         func(r *Request) { r.Current.Kind = "connected" },
		"empty intent":          func(r *Request) { r.Intent = "" },
		"unknown intent":        func(r *Request) { r.Intent = "disconnect" },
		"inactive generation":   func(r *Request) { r.Current.Generation = 1; r.RequestedGeneration = 2 },
		"eligible zero": func(r *Request) {
			r.Current.Kind, r.Current.Generation, r.RequestedGeneration = StateEligible, 0, 1
		},
		"blocked zero": func(r *Request) {
			r.Current.Kind, r.Current.Generation, r.RequestedGeneration = StateBlocked, 0, 1
		},
		"zero generation": func(r *Request) { r.RequestedGeneration = 0 },
		"equal generation": func(r *Request) {
			r.Current = State{Version: Version, Kind: StateEligible, Generation: 2}
			r.RequestedGeneration = 2
		},
		"lower generation": func(r *Request) {
			r.Current = State{Version: Version, Kind: StateEligible, Generation: 2}
			r.RequestedGeneration = 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			mutate(&req)
			got, err := Evaluate(req)
			if err == nil || got != (Decision{}) || strings.Contains(err.Error(), req.Lifecycle.ProfileID) {
				t.Fatalf("decision=%+v err=%v", got, err)
			}
		})
	}
}

func TestUnknownCurrentStateRejectsEveryEvaluatorIntent(t *testing.T) {
	for _, intent := range []Intent{IntentEvaluate, IntentConnect, IntentRecover} {
		t.Run(string(intent), func(t *testing.T) {
			req := validRequest(t)
			req.Intent = intent
			req.Current.Kind = "service_running"
			got, err := Evaluate(req)
			if !errors.Is(err, ErrInvalidState) || got != (Decision{}) {
				t.Fatalf("decision=%+v err=%v", got, err)
			}
		})
	}
}

func TestKnownPlatformFailuresBlockCategorically(t *testing.T) {
	tests := map[string]struct {
		mutate func(*PlatformSnapshot)
		reason Reason
	}{
		"unknown permission": {func(p *PlatformSnapshot) { p.PermissionStateKnown = false }, ReasonPermissionRequired},
		"consent denied":     {func(p *PlatformSnapshot) { p.VPNConsentGranted = false }, ReasonPermissionRequired},
		"storage":            {func(p *PlatformSnapshot) { p.ProtectedStorageAvailable = false }, ReasonProtectedStorageUnavailable},
		"routing":            {func(p *PlatformSnapshot) { p.RoutingPolicySafe = false }, ReasonRoutingUnsafe},
		"dns":                {func(p *PlatformSnapshot) { p.DNSPolicySafe = false }, ReasonDNSUnsafe},
		"kill switch":        {func(p *PlatformSnapshot) { p.KillSwitchAvailable = false }, ReasonKillSwitchUnavailable},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			test.mutate(&req.Platform)
			assertBlocked(t, req, test.reason)
		})
	}
}

func TestContractVersionFailuresBlockBeforeNestedEvaluation(t *testing.T) {
	tests := map[string]func(*Request){
		"platform":        func(r *Request) { r.Platform.Version = "old" },
		"strategy policy": func(r *Request) { r.StrategyRequest.Policy.Version = "old" },
		"strategy client": func(r *Request) { r.StrategyRequest.Client.SupportedVersion = "old" },
		"relay request":   func(r *Request) { r.RelayRequest.Version = "old" },
		"relay embedded strategy policy": func(r *Request) {
			r.RelayRequest.StrategyRequest.Policy.Version = "old"
		},
		"relay embedded strategy client": func(r *Request) {
			r.RelayRequest.StrategyRequest.Client.SupportedVersion = "old"
		},
		"relay policy":          func(r *Request) { r.RelayRequest.Policy.Version = "old" },
		"relay fallback policy": func(r *Request) { r.RelayRequest.Policy.FallbackPolicy.Version = "old" },
		"relay revocation":      func(r *Request) { r.RelayRequest.Revocation.Version = "old" },
		"claimed admission":     func(r *Request) { r.ClaimedRelayAdmission.Version = "old" },
		"zero admission":        func(r *Request) { r.ClaimedRelayAdmission = relaydescriptor.Admission{} },
		"requested descriptor":  func(r *Request) { r.RelayRequest.Descriptors[0].Version = "old" },
		"authorized descriptor": func(r *Request) { r.RelayRequest.Policy.AuthorizedDescriptors[0].Version = "old" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			mutate(&req)
			assertBlocked(t, req, ReasonIncompatibleContract)
		})
	}
}

func TestLifecycleFailuresAndCrossContextBlock(t *testing.T) {
	statuses := []lifecycle.Status{lifecycle.Absent, lifecycle.Superseded, lifecycle.Revoked, lifecycle.Disabled, "unknown"}
	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			req := validRequest(t)
			req.Lifecycle.Status = status
			assertBlocked(t, req, ReasonProfileNotAdmitted)
		})
	}
	for name, mutate := range map[string]func(*Request){
		"zero generation":  func(r *Request) { r.Lifecycle.Generation = 0 },
		"cross profile":    func(r *Request) { r.Lifecycle.ProfileID = "other" },
		"cross generation": func(r *Request) { r.Lifecycle.Generation++ },
	} {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			mutate(&req)
			assertBlocked(t, req, ReasonProfileNotAdmitted)
		})
	}
}

func TestMalformedAdmittedLifecycleBindingsBlockBeforeRecomputation(t *testing.T) {
	tests := map[string]func(*lifecycle.State){
		"empty profile":       func(s *lifecycle.State) { s.ProfileID = "" },
		"oversized profile":   func(s *lifecycle.State) { s.ProfileID = strings.Repeat("p", 257) },
		"whitespace profile":  func(s *lifecycle.State) { s.ProfileID = " profile" },
		"empty scope":         func(s *lifecycle.State) { s.Scope = "" },
		"oversized scope":     func(s *lifecycle.State) { s.Scope = strings.Repeat("s", 65) },
		"whitespace scope":    func(s *lifecycle.State) { s.Scope = "scope " },
		"empty evidence":      func(s *lifecycle.State) { s.EvidenceReference = "" },
		"oversized evidence":  func(s *lifecycle.State) { s.EvidenceReference = strings.Repeat("e", 257) },
		"whitespace evidence": func(s *lifecycle.State) { s.EvidenceReference = " evidence" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			mutate(&req.Lifecycle)
			req.StrategyRequest.Lifecycle = req.Lifecycle
			req.RelayRequest.StrategyRequest.Lifecycle = req.Lifecycle
			assertBlocked(t, req, ReasonProfileNotAdmitted)
		})
	}

	req := validRequest(t)
	req.StrategyRequest.Lifecycle.EvidenceReference = "detached"
	assertBlocked(t, req, ReasonProfileNotAdmitted)
}

func TestStrategyRecomputationRejectsSubstitution(t *testing.T) {
	tests := map[string]func(*Request){
		"detached result": func(r *Request) { r.ClaimedStrategyResult.SelectedFamily = carrierreview.FamilyRelayBridgeRotation },
		"blocked result": func(r *Request) {
			r.ClaimedStrategyResult = strategy.Result{Outcome: strategy.OutcomeBlocked, Reason: strategy.ReasonNoSafe}
		},
		"zero result":             func(r *Request) { r.ClaimedStrategyResult = strategy.Result{} },
		"unknown result":          func(r *Request) { r.ClaimedStrategyResult.Outcome = "unknown" },
		"preference substitution": func(r *Request) { r.StrategyRequest.ManualPreference = carrierreview.FamilyRelayBridgeRotation },
		"family substitution": func(r *Request) {
			r.StrategyRequest.Policy.Permitted[0].Family = carrierreview.FamilyRelayBridgeRotation
		},
		"selector error": func(r *Request) { r.StrategyRequest.Policy.MinimumSafetyFloor = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			mutate(&req)
			assertBlocked(t, req, ReasonFallbackNotSelected)
		})
	}
}

func TestRelayRecomputationRejectsSubstitution(t *testing.T) {
	tests := map[string]func(*Request){
		"embedded strategy":       func(r *Request) { r.RelayRequest.StrategyRequest.ManualPreference = "other" },
		"embedded result":         func(r *Request) { r.RelayRequest.ClaimedResult.Reason = "other" },
		"admission family":        func(r *Request) { r.ClaimedRelayAdmission.SelectedFamily = "other" },
		"admission profile":       func(r *Request) { r.ClaimedRelayAdmission.ProfileID = "other" },
		"admission generation":    func(r *Request) { r.ClaimedRelayAdmission.Generation++ },
		"client substitution":     func(r *Request) { r.RelayRequest.Client.ID = "other" },
		"descriptor substitution": func(r *Request) { r.RelayRequest.Descriptors[0].DescriptorID = "other" },
		"revocation":              func(r *Request) { r.RelayRequest.Revocation.RevokedDescriptorIDs = []string{"relay"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			mutate(&req)
			assertBlocked(t, req, ReasonRelayNotAdmitted)
		})
	}
}

func TestDisconnectPendingShortCircuitsEverything(t *testing.T) {
	for _, intent := range []Intent{IntentEvaluate, IntentConnect, IntentRecover, "unknown"} {
		t.Run(string(intent), func(t *testing.T) {
			req := Request{
				Intent: intent, Current: State{Kind: StateDisconnectPending, Generation: 9},
				RequestedGeneration: 7,
				StrategyRequest:     strategy.Request{Policy: strategy.Policy{Permitted: make([]strategy.Candidate, 65)}},
				RelayRequest:        relaydescriptor.Request{Descriptors: make([]relaydescriptor.Descriptor, 33)},
			}
			got, err := Evaluate(req)
			want := shutdownDecision(9)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("decision=%+v want=%+v err=%v", got, want, err)
			}
		})
	}
	got, err := Evaluate(Request{Current: State{Kind: StateDisconnectPending, Generation: 2}, RequestedGeneration: 3})
	if err != nil || got.Next.Generation != 3 {
		t.Fatalf("decision=%+v err=%v", got, err)
	}
}

func TestRequestDisconnectIsAlwaysAvailableIdempotentAndOverflowSafe(t *testing.T) {
	tests := map[string]struct {
		request DisconnectRequest
		want    uint64
	}{
		"both zero": {DisconnectRequest{}, 1},
		"lower":     {DisconnectRequest{CurrentGeneration: 7, RequestedGeneration: 3}, 7},
		"equal":     {DisconnectRequest{CurrentGeneration: 7, RequestedGeneration: 7}, 7},
		"higher":    {DisconnectRequest{CurrentGeneration: 7, RequestedGeneration: 9}, 9},
		"max":       {DisconnectRequest{CurrentGeneration: math.MaxUint64, RequestedGeneration: math.MaxUint64}, math.MaxUint64},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			first := RequestDisconnect(test.request)
			second := RequestDisconnect(test.request)
			if !reflect.DeepEqual(first, second) || first.Next.Generation != test.want ||
				first.Disposition != DispositionShutdownRequired || first.Next.Kind != StateDisconnectPending {
				t.Fatalf("first=%+v second=%+v", first, second)
			}
		})
	}
}

func TestRecoveryRevalidatesEveryPrerequisite(t *testing.T) {
	mutations := map[string]struct {
		mutate func(*Request)
		reason Reason
	}{
		"permission loss":  {func(r *Request) { r.Platform.VPNConsentGranted = false }, ReasonPermissionRequired},
		"storage loss":     {func(r *Request) { r.Platform.ProtectedStorageAvailable = false }, ReasonProtectedStorageUnavailable},
		"routing loss":     {func(r *Request) { r.Platform.RoutingPolicySafe = false }, ReasonRoutingUnsafe},
		"dns loss":         {func(r *Request) { r.Platform.DNSPolicySafe = false }, ReasonDNSUnsafe},
		"kill switch loss": {func(r *Request) { r.Platform.KillSwitchAvailable = false }, ReasonKillSwitchUnavailable},
		"profile revoked":  {func(r *Request) { r.Lifecycle.Status = lifecycle.Revoked }, ReasonProfileNotAdmitted},
		"fallback changed": {func(r *Request) { r.ClaimedStrategyResult.Reason = "changed" }, ReasonFallbackNotSelected},
		"relay revoked":    {func(r *Request) { r.RelayRequest.Revocation.RevokedDescriptorIDs = []string{"relay"} }, ReasonRelayNotAdmitted},
	}
	for name, test := range mutations {
		t.Run(name, func(t *testing.T) {
			req := validRequest(t)
			req.Intent = IntentRecover
			test.mutate(&req)
			assertBlocked(t, req, test.reason)
		})
	}
}

func TestMaxGenerationAndPredecessorBounds(t *testing.T) {
	req := validRequest(t)
	req.Current = State{Version: Version, Kind: StateEligible, Generation: math.MaxUint64 - 1}
	req.RequestedGeneration = math.MaxUint64
	got, err := Evaluate(req)
	if err != nil || got.Next.Generation != math.MaxUint64 {
		t.Fatalf("decision=%+v err=%v", got, err)
	}

	req = validRequest(t)
	req.StrategyRequest.Policy.Permitted = make([]strategy.Candidate, 65)
	assertBlocked(t, req, ReasonFallbackNotSelected)

	req = validRequest(t)
	descriptor := req.RelayRequest.Descriptors[0]
	req.RelayRequest.Descriptors = make([]relaydescriptor.Descriptor, 33)
	for i := range req.RelayRequest.Descriptors {
		req.RelayRequest.Descriptors[i] = descriptor
	}
	assertBlocked(t, req, ReasonRelayNotAdmitted)

	req = validRequest(t)
	req.ClaimedRelayAdmission.Descriptors = make([]relaydescriptor.AdmittedDescriptor, 33)
	assertBlocked(t, req, ReasonRelayNotAdmitted)
}

func TestEvaluateDoesNotMutateOrAliasInput(t *testing.T) {
	req := validRequest(t)
	before := validRequest(t)
	got, err := Evaluate(req)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(req, before) {
		t.Fatal("request mutated")
	}
	got.Next.Kind = StateBlocked
	if req.Current.Kind != StateInactive {
		t.Fatal("decision aliases caller state")
	}
}

func TestNestedPredecessorCollectionBoundaries(t *testing.T) {
	type boundary struct {
		exact       func(*testing.T, *Request)
		exactReason Reason
		over        func(*Request)
		overReason  Reason
	}
	tests := map[string]boundary{
		"strategy supported families": {
			exact: func(_ *testing.T, r *Request) {
				r.StrategyRequest.Client.SupportedFamilies = repeatStrings(carrierreview.FamilyHTTPSLikeTCP, 64)
			},
			exactReason: ReasonFallbackNotSelected,
			over: func(r *Request) {
				r.StrategyRequest.Client.SupportedFamilies = repeatStrings(carrierreview.FamilyHTTPSLikeTCP, 65)
			},
			overReason: ReasonFallbackNotSelected,
		},
		"client capabilities": {
			exact:      func(t *testing.T, r *Request) { configureCapabilities(t, r, 64, false) },
			over:       func(r *Request) { r.StrategyRequest.Client.Capabilities = identifiers("capability", 65, true) },
			overReason: ReasonFallbackNotSelected,
		},
		"candidate required capabilities": {
			exact: func(t *testing.T, r *Request) { configureCapabilities(t, r, 64, true) },
			over: func(r *Request) {
				r.StrategyRequest.Policy.Permitted[0].RequiredCapabilities = identifiers("capability", 65, true)
			},
			overReason: ReasonFallbackNotSelected,
		},
		"relay requested descriptors": {
			exact: func(t *testing.T, r *Request) {
				r.RelayRequest.Descriptors = descriptorSet(r.RelayRequest.Descriptors[0], 32)
				r.RelayRequest.Policy.AuthorizedDescriptors = descriptorSet(r.RelayRequest.Descriptors[0], 32)
				refreshClaims(t, r)
			},
			over:       func(r *Request) { r.RelayRequest.Descriptors = descriptorSet(r.RelayRequest.Descriptors[0], 33) },
			overReason: ReasonRelayNotAdmitted,
		},
		"relay authorized descriptors": {
			exact: func(t *testing.T, r *Request) {
				r.RelayRequest.Policy.AuthorizedDescriptors = descriptorSet(r.RelayRequest.Descriptors[0], 32)
				refreshClaims(t, r)
			},
			over: func(r *Request) {
				r.RelayRequest.Policy.AuthorizedDescriptors = descriptorSet(r.RelayRequest.Descriptors[0], 33)
			},
			overReason: ReasonRelayNotAdmitted,
		},
		"relay policy capabilities": {
			exact:      func(t *testing.T, r *Request) { configureCapabilities(t, r, 64, false) },
			over:       func(r *Request) { r.RelayRequest.Policy.ClientCapabilities = identifiers("capability", 65, true) },
			overReason: ReasonRelayNotAdmitted,
		},
		"relay authorized client IDs": {
			exact: func(t *testing.T, r *Request) {
				r.RelayRequest.Policy.AuthorizedClientIDs = identifiers("client", 64, true)
				refreshClaims(t, r)
			},
			over:       func(r *Request) { r.RelayRequest.Policy.AuthorizedClientIDs = identifiers("client", 65, true) },
			overReason: ReasonRelayNotAdmitted,
		},
		"relay revocation IDs": {
			exact: func(t *testing.T, r *Request) {
				r.RelayRequest.Revocation.RevokedDescriptorIDs = identifiers("revoked", 64, false)
				refreshClaims(t, r)
			},
			over:       func(r *Request) { r.RelayRequest.Revocation.RevokedDescriptorIDs = identifiers("revoked", 65, false) },
			overReason: ReasonRelayNotAdmitted,
		},
		"descriptor capabilities": {
			exact: func(t *testing.T, r *Request) { configureCapabilities(t, r, 64, false) },
			over: func(r *Request) {
				caps := identifiers("capability", 65, true)
				r.RelayRequest.Descriptors[0].ClientCapabilities = caps
				r.RelayRequest.Policy.AuthorizedDescriptors[0].ClientCapabilities = append([]string(nil), caps...)
			},
			overReason: ReasonRelayNotAdmitted,
		},
		"descriptor metadata": {
			exact: func(t *testing.T, r *Request) {
				metadata := metadataSet(16)
				r.RelayRequest.Descriptors[0].Metadata = metadata
				r.RelayRequest.Policy.AuthorizedDescriptors[0].Metadata = append([]relaydescriptor.Metadata(nil), metadata...)
				refreshClaims(t, r)
			},
			over:       func(r *Request) { r.RelayRequest.Descriptors[0].Metadata = metadataSet(17) },
			overReason: ReasonRelayNotAdmitted,
		},
		"embedded fallback candidates": {
			exact: func(_ *testing.T, r *Request) {
				r.RelayRequest.Policy.FallbackPolicy.Permitted = repeatCandidates(r.StrategyRequest.Policy.Permitted[0], 64)
			},
			exactReason: ReasonRelayNotAdmitted,
			over: func(r *Request) {
				r.RelayRequest.Policy.FallbackPolicy.Permitted = repeatCandidates(r.StrategyRequest.Policy.Permitted[0], 65)
			},
			overReason: ReasonRelayNotAdmitted,
		},
		"claimed admission descriptors": {
			exact: func(t *testing.T, r *Request) {
				r.RelayRequest.Descriptors = descriptorSet(r.RelayRequest.Descriptors[0], 32)
				r.RelayRequest.Policy.AuthorizedDescriptors = descriptorSet(r.RelayRequest.Descriptors[0], 32)
				refreshClaims(t, r)
			},
			over: func(r *Request) {
				r.ClaimedRelayAdmission.Descriptors = make([]relaydescriptor.AdmittedDescriptor, 33)
			},
			overReason: ReasonRelayNotAdmitted,
		},
	}

	for name, test := range tests {
		t.Run(name+"/max", func(t *testing.T) {
			req := validRequest(t)
			test.exact(t, &req)
			if test.exactReason != "" {
				assertBlocked(t, req, test.exactReason)
				return
			}
			assertReady(t, req)
		})
		t.Run(name+"/max-plus-one", func(t *testing.T) {
			req := validRequest(t)
			test.over(&req)
			assertBlocked(t, req, test.overReason)
		})
	}
}

func configureCapabilities(t *testing.T, req *Request, count int, requireAll bool) {
	t.Helper()
	caps := identifiers("capability", count, true)
	req.StrategyRequest.Client.Capabilities = caps
	if requireAll {
		req.StrategyRequest.Policy.Permitted[0].RequiredCapabilities = append([]string(nil), caps...)
	}
	refreshClaims(t, req)
}

func refreshClaims(t *testing.T, req *Request) {
	t.Helper()
	selected, err := strategy.Select(req.StrategyRequest)
	if err != nil {
		t.Fatalf("refresh strategy: %v", err)
	}
	req.ClaimedStrategyResult = selected
	req.RelayRequest.StrategyRequest = req.StrategyRequest
	req.RelayRequest.ClaimedResult = selected
	req.RelayRequest.Policy.FallbackPolicy = req.StrategyRequest.Policy
	req.RelayRequest.Policy.SelectedFamily = selected.SelectedFamily
	req.RelayRequest.Policy.ClientCapabilities = append([]string(nil), req.StrategyRequest.Client.Capabilities...)
	for i := range req.RelayRequest.Descriptors {
		req.RelayRequest.Descriptors[i].Family = selected.SelectedFamily
		req.RelayRequest.Descriptors[i].ClientCapabilities = append([]string(nil), req.StrategyRequest.Client.Capabilities...)
	}
	for i := range req.RelayRequest.Policy.AuthorizedDescriptors {
		req.RelayRequest.Policy.AuthorizedDescriptors[i].Family = selected.SelectedFamily
		req.RelayRequest.Policy.AuthorizedDescriptors[i].ClientCapabilities = append([]string(nil), req.StrategyRequest.Client.Capabilities...)
	}
	if recomputed, err := strategy.Select(req.RelayRequest.StrategyRequest); err != nil || !reflect.DeepEqual(recomputed, req.RelayRequest.ClaimedResult) {
		t.Fatalf("refresh embedded strategy: result=%+v claimed=%+v err=%v", recomputed, req.RelayRequest.ClaimedResult, err)
	}
	admission, err := relaydescriptor.Admit(req.RelayRequest)
	if err != nil {
		recomputed, selectErr := strategy.Select(req.RelayRequest.StrategyRequest)
		t.Fatalf("refresh relay admission: %v; recomputed=%+v claimed=%+v equal=%v selectErr=%v", err, recomputed, req.RelayRequest.ClaimedResult, reflect.DeepEqual(recomputed, req.RelayRequest.ClaimedResult), selectErr)
	}
	req.ClaimedRelayAdmission = admission
}

func identifiers(prefix string, count int, includeBase bool) []string {
	values := make([]string, count)
	for i := range values {
		values[i] = fmt.Sprintf("%s-%02d", prefix, i)
	}
	if includeBase && count > 0 {
		values[0] = prefix
	}
	return values
}

func repeatStrings(value string, count int) []string {
	values := make([]string, count)
	for i := range values {
		values[i] = value
	}
	return values
}

func repeatCandidates(value strategy.Candidate, count int) []strategy.Candidate {
	values := make([]strategy.Candidate, count)
	for i := range values {
		values[i] = value
	}
	return values
}

func descriptorSet(base relaydescriptor.Descriptor, count int) []relaydescriptor.Descriptor {
	values := make([]relaydescriptor.Descriptor, count)
	for i := range values {
		values[i] = base
		if i > 0 {
			values[i].DescriptorID = fmt.Sprintf("relay-%02d", i)
			values[i].EndpointReference = fmt.Sprintf("relayref:node_%02d", i)
		}
	}
	return values
}

func metadataSet(count int) []relaydescriptor.Metadata {
	values := make([]relaydescriptor.Metadata, count)
	for i := range values {
		values[i] = relaydescriptor.Metadata{Name: fmt.Sprintf("meta-%02d", i), Value: fmt.Sprintf("value-%02d", i)}
	}
	return values
}

func assertReady(t *testing.T, req Request) {
	t.Helper()
	got, err := Evaluate(req)
	if err != nil || got.Disposition != DispositionReadyToStart || got.Next.Kind != StateEligible || got.Reason != ReasonEligible {
		t.Fatalf("decision=%+v err=%v", got, err)
	}
}

func assertBlocked(t *testing.T, req Request, reason Reason) {
	t.Helper()
	got, err := Evaluate(req)
	if err != nil || got.Version != Version || got.Next.Kind != StateBlocked ||
		got.Next.Generation != req.RequestedGeneration || got.Disposition != DispositionBlocked || got.Reason != reason {
		t.Fatalf("decision=%+v reason=%q err=%v", got, reason, err)
	}
}
