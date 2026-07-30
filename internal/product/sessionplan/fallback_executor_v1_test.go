// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package sessionplan

import (
	"context"
	"errors"
	"testing"
	"time"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/relaydescriptor"
	"kurdistan/internal/product/strategy"
)

func TestPermittedFallbackV1PreservesOrderAndStopsAfterSuccess(t *testing.T) {
	plans := processFallbackPlansV1(t, 3)
	var attempted [][32]byte
	result, err := ExecutePermittedFallbackV1(context.Background(), plans, func(_ context.Context, plan Plan) error {
		attempted = append(attempted, plan.Digest)
		if len(attempted) < 2 {
			return errors.New("categorical attempt failure")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(attempted) != 2 || attempted[0] != plans[0].Digest || attempted[1] != plans[1].Digest {
		t.Fatal("executor changed the admitted order")
	}
	if result.SelectedIndex != 1 || result.AttemptCount != 2 || result.PlanDigest != plans[1].Digest {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestPermittedFallbackV1RejectsForgedDuplicateAndMixedAuthority(t *testing.T) {
	plans := processFallbackPlansV1(t, 2)
	cases := map[string][]Plan{
		"duplicate":       {plans[0], plans[0]},
		"forged":          {plans[0], func() Plan { value := plans[1]; value.Generation++; return value }()},
		"mixed authority": {plans[0], func() Plan { value := plans[1]; value.ClientID += "-other"; return value }()},
	}
	for name, candidatePlans := range cases {
		t.Run(name, func(t *testing.T) {
			called := false
			if _, err := ExecutePermittedFallbackV1(context.Background(), candidatePlans, func(context.Context, Plan) error {
				called = true
				return nil
			}); !errors.Is(err, ErrFallbackExecutionV1) || called {
				t.Fatal("invalid candidate set reached the attempt boundary")
			}
		})
	}
}

func TestPermittedFallbackV1BoundsAttemptsAndCancellation(t *testing.T) {
	if _, err := ExecutePermittedFallbackV1(context.Background(), make([]Plan, maxFallbackAttemptsV1+1), func(context.Context, Plan) error { return nil }); !errors.Is(err, ErrFallbackExecutionV1) {
		t.Fatal("overlong attempt set was accepted")
	}
	plans := processFallbackPlansV1(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	if _, err := ExecutePermittedFallbackV1(ctx, plans, func(context.Context, Plan) error {
		calls++
		cancel()
		return errors.New("failed")
	}); !errors.Is(err, ErrFallbackExecutionV1) || calls != 1 {
		t.Fatal("cancellation did not stop before the next candidate")
	}
}

func TestPermittedFallbackV1AppliesPerAttemptDeadline(t *testing.T) {
	plans := processFallbackPlansV1(t, 1)
	plans = processFallbackPlansWithTimeoutV1(t, 1, 1)
	if _, err := ExecutePermittedFallbackV1(context.Background(), plans, func(ctx context.Context, _ Plan) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
			return nil
		}
	}); !errors.Is(err, ErrFallbackExecutionV1) {
		t.Fatal("timed-out attempt was accepted")
	}
}

func processFallbackPlansV1(t *testing.T, count int) []Plan {
	return processFallbackPlansWithTimeoutV1(t, count, 50)
}

func processFallbackPlansWithTimeoutV1(t *testing.T, count int, timeout uint32) []Plan {
	t.Helper()
	plans := make([]Plan, count)
	for index := range plans {
		state := lifecycle.State{
			Status: lifecycle.Admitted, ProfileID: "phase11-profile", Scope: "device",
			EvidenceReference: "phase11-evidence", Generation: 11,
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
				SupportedVersion: strategy.Version, SupportedFamilies: []string{carrierreview.FamilyHTTPSLikeTCP},
				Capabilities: []string{"cap-a"}, SafetyFloor: 2, PrivacyFloor: 2,
			},
		}
		selected, err := strategy.Select(strategyRequest)
		if err != nil {
			t.Fatal(err)
		}
		descriptorID := "relay-" + string(rune('a'+index))
		endpointReference := "relayref:owned-" + string(rune('a'+index))
		descriptor := relaydescriptor.Descriptor{
			Version: relaydescriptor.Version, DescriptorID: descriptorID,
			ProfileID: state.ProfileID, Scope: state.Scope, EvidenceReference: state.EvidenceReference,
			Generation: state.Generation, Family: selected.SelectedFamily, ClientID: "client",
			ClientCapabilities: []string{"cap-a"}, EndpointReference: endpointReference,
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
		plan, err := Build(Request{
			StrategyRequest: strategyRequest, ClaimedStrategy: selected,
			RelayRequest: relayRequest, ClaimedAdmission: admitted,
			DescriptorID: descriptorID, DialTimeoutMs: timeout, MaxFrameBytes: 64 << 10,
		})
		if err != nil {
			t.Fatal(err)
		}
		plans[index] = plan
	}
	return plans
}
