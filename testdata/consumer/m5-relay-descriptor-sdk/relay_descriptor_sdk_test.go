package relay_descriptor_sdk_test

import (
	"reflect"
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/relaydescriptor"
	"kurdistan/internal/product/strategy"
)

func request(t *testing.T) relaydescriptor.Request {
	t.Helper()
	s := lifecycle.State{Status: lifecycle.Admitted, ProfileID: "profile", Scope: "device", EvidenceReference: "evidence", Generation: 1}
	sr := strategy.Request{
		Lifecycle: s,
		Policy: strategy.Policy{
			Version: strategy.Version, ProfileID: s.ProfileID, Scope: s.Scope, EvidenceReference: s.EvidenceReference, Generation: s.Generation,
			Permitted:          []strategy.Candidate{{Family: carrierreview.FamilyHTTPSLikeTCP, RequiredCapabilities: []string{"capability"}, MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2}},
			MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2,
		},
		Client: strategy.Client{
			SupportedVersion: strategy.Version, SupportedFamilies: []string{carrierreview.FamilyHTTPSLikeTCP},
			Capabilities: []string{"capability"}, SafetyFloor: 2, PrivacyFloor: 2,
		},
	}
	selected, err := strategy.Select(sr)
	if err != nil {
		t.Fatal(err)
	}
	d := relaydescriptor.Descriptor{
		Version: relaydescriptor.Version, DescriptorID: "relay", ProfileID: s.ProfileID, Scope: s.Scope,
		EvidenceReference: s.EvidenceReference, Generation: s.Generation, Family: selected.SelectedFamily,
		ClientID: "client", ClientCapabilities: []string{"capability"}, EndpointReference: "relayref:node_A7",
		NotBefore: 10, ExpiresAt: 20,
	}
	return relaydescriptor.Request{
		Version: relaydescriptor.Version, StrategyRequest: sr, ClaimedResult: selected, EvaluationTime: 15,
		Client: relaydescriptor.ClientBinding{ID: "client"},
		Policy: relaydescriptor.Policy{
			Version: relaydescriptor.Version, ProfileID: s.ProfileID, Scope: s.Scope, EvidenceReference: s.EvidenceReference, Generation: s.Generation,
			FallbackPolicy: sr.Policy, SelectedFamily: selected.SelectedFamily, ClientCapabilities: []string{"capability"},
			AuthorizedClientIDs: []string{"client"}, AuthorizedDescriptors: []relaydescriptor.Descriptor{d},
		},
		Revocation: relaydescriptor.RevocationState{
			Version: relaydescriptor.Version, Complete: true, ProfileID: s.ProfileID, Scope: s.Scope,
			EvidenceReference: s.EvidenceReference, Generation: s.Generation, EvaluatedAt: 15,
		},
		Descriptors: []relaydescriptor.Descriptor{d},
	}
}

func TestExternalConsumerAdmissionAndFailClosedRollback(t *testing.T) {
	req := request(t)
	lastSafe, err := relaydescriptor.Admit(req)
	if err != nil || len(lastSafe.Descriptors) != 1 {
		t.Fatalf("admission=%+v err=%v", lastSafe, err)
	}

	tests := map[string]func(*relaydescriptor.Request){
		"result substitution": func(r *relaydescriptor.Request) {
			r.ClaimedResult.SelectedFamily = carrierreview.FamilyRelayBridgeRotation
		},
		"client substitution": func(r *relaydescriptor.Request) { r.Client.ID = "another-client" },
		"descriptor mismatch": func(r *relaydescriptor.Request) { r.Descriptors[0].EndpointReference = "relayref:node_B8" },
		"revocation":          func(r *relaydescriptor.Request) { r.Revocation.RevokedDescriptorIDs = []string{"relay"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			rejected := request(t)
			mutate(&rejected)
			got, err := relaydescriptor.Admit(rejected)
			if err == nil || !reflect.DeepEqual(got, relaydescriptor.Admission{}) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
			if len(lastSafe.Descriptors) != 1 || lastSafe.Descriptors[0].DescriptorID != "relay" {
				t.Fatalf("prior safe state changed: %+v", lastSafe)
			}
		})
	}
}
