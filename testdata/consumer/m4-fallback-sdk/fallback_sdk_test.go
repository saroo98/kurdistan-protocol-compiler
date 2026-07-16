package fallback_sdk_test

import (
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/strategy"
)

func request() strategy.Request {
	s := lifecycle.State{Status: lifecycle.Admitted, ProfileID: "p", Scope: "device", EvidenceReference: "e", Generation: 1}
	return strategy.Request{
		Lifecycle: s,
		Policy: strategy.Policy{Version: strategy.Version, ProfileID: s.ProfileID, Scope: s.Scope, EvidenceReference: s.EvidenceReference, Generation: s.Generation, MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2, Permitted: []strategy.Candidate{
			{Family: carrierreview.FamilyHTTPSLikeTCP, MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2},
			{Family: carrierreview.FamilyRelayBridgeRotation, MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2},
		}},
		Client: strategy.Client{SupportedVersion: strategy.Version, SupportedFamilies: []string{carrierreview.FamilyRelayBridgeRotation, carrierreview.FamilyHTTPSLikeTCP}, SafetyFloor: 2, PrivacyFloor: 2},
	}
}

func TestExternalConsumerSelectedBlockedAndRollback(t *testing.T) {
	req := request()
	lastSafe, err := strategy.Select(req)
	if err != nil || lastSafe.SelectedFamily != carrierreview.FamilyHTTPSLikeTCP {
		t.Fatalf("selected=%+v err=%v", lastSafe, err)
	}
	req.ManualPreference = carrierreview.FamilyRelayBridgeRotation
	manual, err := strategy.Select(req)
	if err != nil || manual.SelectedFamily != req.ManualPreference {
		t.Fatalf("manual=%+v err=%v", manual, err)
	}
	req = request()
	req.Client.SafetyFloor = 1
	blocked, err := strategy.Select(req)
	if err != nil || blocked.Outcome != strategy.OutcomeBlocked || blocked.SelectedFamily != "" {
		t.Fatalf("blocked=%+v err=%v", blocked, err)
	}
	req = request()
	req.Policy.Version = "permitted-fallback-v2"
	if got, err := strategy.Select(req); err == nil || got != (strategy.Result{}) {
		t.Fatalf("future=%+v err=%v", got, err)
	}
	if lastSafe.Outcome != strategy.OutcomeSelected {
		t.Fatalf("last safe changed: %+v", lastSafe)
	}
}
