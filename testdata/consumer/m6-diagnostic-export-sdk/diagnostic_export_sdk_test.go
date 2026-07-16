package diagnostic_export_sdk_test

import (
	"bytes"
	"reflect"
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/product/diagnosticexport"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/relaydescriptor"
	"kurdistan/internal/product/strategy"
)

func predecessorOutcomes(t *testing.T) (lifecycle.State, strategy.Request, strategy.Result, relaydescriptor.Request, relaydescriptor.Admission) {
	t.Helper()
	state, err := lifecycle.Apply(lifecycle.State{}, lifecycle.Decision{
		Action: lifecycle.Admit, ProfileID: "profile", Scope: "device", EvidenceReference: "evidence", Generation: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	selectionRequest := strategy.Request{
		Lifecycle: state,
		Policy: strategy.Policy{
			Version: strategy.Version, ProfileID: state.ProfileID, Scope: state.Scope, EvidenceReference: state.EvidenceReference, Generation: state.Generation,
			Permitted:          []strategy.Candidate{{Family: carrierreview.FamilyHTTPSLikeTCP, RequiredCapabilities: []string{"capability"}, MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2}},
			MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2,
		},
		Client: strategy.Client{SupportedVersion: strategy.Version, SupportedFamilies: []string{carrierreview.FamilyHTTPSLikeTCP}, Capabilities: []string{"capability"}, SafetyFloor: 2, PrivacyFloor: 2},
	}
	selection, err := strategy.Select(selectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := relaydescriptor.Descriptor{
		Version: relaydescriptor.Version, DescriptorID: "relay", ProfileID: state.ProfileID, Scope: state.Scope,
		EvidenceReference: state.EvidenceReference, Generation: state.Generation, Family: selection.SelectedFamily,
		ClientID: "client", ClientCapabilities: []string{"capability"}, EndpointReference: "relayref:node_A7", NotBefore: 10, ExpiresAt: 20,
	}
	admissionRequest := relaydescriptor.Request{
		Version: relaydescriptor.Version, StrategyRequest: selectionRequest, ClaimedResult: selection, EvaluationTime: 15,
		Client: relaydescriptor.ClientBinding{ID: "client"},
		Policy: relaydescriptor.Policy{
			Version: relaydescriptor.Version, ProfileID: state.ProfileID, Scope: state.Scope, EvidenceReference: state.EvidenceReference, Generation: state.Generation,
			FallbackPolicy: selectionRequest.Policy, SelectedFamily: selection.SelectedFamily, ClientCapabilities: []string{"capability"},
			AuthorizedClientIDs: []string{"client"}, AuthorizedDescriptors: []relaydescriptor.Descriptor{descriptor},
		},
		Revocation: relaydescriptor.RevocationState{
			Version: relaydescriptor.Version, Complete: true, ProfileID: state.ProfileID, Scope: state.Scope,
			EvidenceReference: state.EvidenceReference, Generation: state.Generation, EvaluatedAt: 15,
		},
		Descriptors: []relaydescriptor.Descriptor{descriptor},
	}
	admission, err := relaydescriptor.Admit(admissionRequest)
	if err != nil {
		t.Fatal(err)
	}
	return state, selectionRequest, selection, admissionRequest, admission
}

func diagnosticEntries(state lifecycle.State, selection strategy.Result, admission relaydescriptor.Admission) []diagnosticexport.Entry {
	entries := []diagnosticexport.Entry{{Category: diagnosticexport.CategoryContractVersions, Value: diagnosticexport.ValueSupported}}
	if state.Status == lifecycle.Admitted {
		entries = append(entries, diagnosticexport.Entry{Category: diagnosticexport.CategoryProfileLifecycle, Value: diagnosticexport.ValueAdmitted})
	}
	if selection.Outcome == strategy.OutcomeSelected {
		entries = append(entries, diagnosticexport.Entry{Category: diagnosticexport.CategoryFallbackSelection, Value: diagnosticexport.ValueSelected})
	}
	if len(admission.Descriptors) > 0 {
		entries = append(entries, diagnosticexport.Entry{Category: diagnosticexport.CategoryRelayAdmission, Value: diagnosticexport.ValueAdmitted})
	}
	if len(entries) == 4 {
		entries = append(entries, diagnosticexport.Entry{Category: diagnosticexport.CategoryRuntimeDisposition, Value: diagnosticexport.ValueEligible})
	}
	return entries
}

func TestExternalConsumerRequiresPreviewAndConfirmation(t *testing.T) {
	state, _, selection, _, admission := predecessorOutcomes(t)
	req := diagnosticexport.Request{
		Version: diagnosticexport.Version, Revision: 1, UserInitiated: true,
		Entries: diagnosticEntries(state, selection, admission),
	}
	prepared, err := diagnosticexport.Prepare(req)
	if err != nil {
		t.Fatal(err)
	}
	previewed, preview, err := diagnosticexport.PreviewPrepared(prepared)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := diagnosticexport.Confirm(previewed, diagnosticexport.Confirmation{Approved: true, Version: diagnosticexport.Version, Revision: 1, Preview: preview})
	if err != nil {
		t.Fatal(err)
	}
	first, err := diagnosticexport.Build(confirmed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := diagnosticexport.Build(confirmed)
	if err != nil || !bytes.Equal(first.Bytes, second.Bytes) {
		t.Fatal("bundle is not deterministic")
	}
	_ = diagnosticexport.CancelPrepared(prepared)
	_ = diagnosticexport.CancelPreviewed(previewed)
	_ = diagnosticexport.CancelConfirmed(confirmed)
}

func TestDiagnosticFailureAndCancellationDoNotChangePredecessorDecisions(t *testing.T) {
	state, selectionRequest, selection, admissionRequest, admission := predecessorOutcomes(t)
	wantState, wantSelection, wantAdmission := state, selection, admission

	failed := diagnosticexport.Request{
		Version: diagnosticexport.Version, Revision: 2, UserInitiated: false,
		Entries: diagnosticEntries(state, selection, admission),
	}
	if _, err := diagnosticexport.Prepare(failed); err == nil {
		t.Fatal("diagnostic prepare unexpectedly succeeded")
	}

	prepared, err := diagnosticexport.Prepare(diagnosticexport.Request{
		Version: diagnosticexport.Version, Revision: 3, UserInitiated: true,
		Entries: diagnosticEntries(state, selection, admission),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = diagnosticexport.CancelPrepared(prepared)

	recomputedSelection, err := strategy.Select(selectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	recomputedAdmission, err := relaydescriptor.Admit(admissionRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state, wantState) || !reflect.DeepEqual(recomputedSelection, wantSelection) || !reflect.DeepEqual(recomputedAdmission, wantAdmission) {
		t.Fatalf("diagnostic flow changed predecessor decisions: state=%+v selection=%+v admission=%+v", state, recomputedSelection, recomputedAdmission)
	}
}
