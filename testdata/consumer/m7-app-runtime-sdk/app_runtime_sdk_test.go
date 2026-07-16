package app_runtime_sdk_test

import (
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/product/appruntime"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/relaydescriptor"
	"kurdistan/internal/product/strategy"
)

func request(t *testing.T) appruntime.Request {
	t.Helper()
	state := lifecycle.State{Status: lifecycle.Admitted, ProfileID: "profile", Scope: "device", EvidenceReference: "evidence", Generation: 1}
	strategyRequest := strategy.Request{
		Lifecycle: state,
		Policy: strategy.Policy{
			Version: strategy.Version, ProfileID: state.ProfileID, Scope: state.Scope, EvidenceReference: state.EvidenceReference,
			Generation: state.Generation, MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2,
			Permitted: []strategy.Candidate{{Family: carrierreview.FamilyHTTPSLikeTCP, RequiredCapabilities: []string{"capability"}, MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2}},
		},
		Client: strategy.Client{SupportedVersion: strategy.Version, SupportedFamilies: []string{carrierreview.FamilyHTTPSLikeTCP}, Capabilities: []string{"capability"}, SafetyFloor: 2, PrivacyFloor: 2},
	}
	selected, err := strategy.Select(strategyRequest)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := relaydescriptor.Descriptor{
		Version: relaydescriptor.Version, DescriptorID: "relay", ProfileID: state.ProfileID, Scope: state.Scope,
		EvidenceReference: state.EvidenceReference, Generation: state.Generation, Family: selected.SelectedFamily,
		ClientID: "client", ClientCapabilities: []string{"capability"}, EndpointReference: "relayref:node_A7",
		NotBefore: 10, ExpiresAt: 20,
	}
	relayRequest := relaydescriptor.Request{
		Version: relaydescriptor.Version, StrategyRequest: strategyRequest, ClaimedResult: selected, EvaluationTime: 15,
		Client: relaydescriptor.ClientBinding{ID: "client"},
		Policy: relaydescriptor.Policy{
			Version: relaydescriptor.Version, ProfileID: state.ProfileID, Scope: state.Scope, EvidenceReference: state.EvidenceReference,
			Generation: state.Generation, FallbackPolicy: strategyRequest.Policy, SelectedFamily: selected.SelectedFamily,
			ClientCapabilities: []string{"capability"}, AuthorizedClientIDs: []string{"client"}, AuthorizedDescriptors: []relaydescriptor.Descriptor{descriptor},
		},
		Revocation:  relaydescriptor.RevocationState{Version: relaydescriptor.Version, Complete: true, ProfileID: state.ProfileID, Scope: state.Scope, EvidenceReference: state.EvidenceReference, Generation: state.Generation, EvaluatedAt: 15},
		Descriptors: []relaydescriptor.Descriptor{descriptor},
	}
	admission, err := relaydescriptor.Admit(relayRequest)
	if err != nil {
		t.Fatal(err)
	}
	return appruntime.Request{
		Version: appruntime.Version, Intent: appruntime.IntentConnect,
		Current: appruntime.State{Version: appruntime.Version, Kind: appruntime.StateInactive}, RequestedGeneration: 1,
		Platform:  appruntime.PlatformSnapshot{Version: appruntime.Version, PermissionStateKnown: true, VPNConsentGranted: true, ProtectedStorageAvailable: true, RoutingPolicySafe: true, DNSPolicySafe: true, KillSwitchAvailable: true},
		Lifecycle: state, StrategyRequest: strategyRequest, ClaimedStrategyResult: selected,
		RelayRequest: relayRequest, ClaimedRelayAdmission: admission,
	}
}

func TestExternalConsumerEligibilityFailClosedAndDisconnect(t *testing.T) {
	req := request(t)
	decision, err := appruntime.Evaluate(req)
	if err != nil || decision.Disposition != appruntime.DispositionReadyToStart || decision.Next.Kind != appruntime.StateEligible {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}

	req.Platform.DNSPolicySafe = false
	decision, err = appruntime.Evaluate(req)
	if err != nil || decision.Disposition != appruntime.DispositionBlocked || decision.Reason != appruntime.ReasonDNSUnsafe {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}

	disconnect := appruntime.RequestDisconnect(appruntime.DisconnectRequest{})
	if disconnect.Disposition != appruntime.DispositionShutdownRequired || disconnect.Next.Generation != 1 {
		t.Fatalf("disconnect=%+v", disconnect)
	}
}
