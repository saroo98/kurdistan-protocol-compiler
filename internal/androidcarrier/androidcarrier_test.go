// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidcarrier

import "testing"

func TestGenerateFixtureSet(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet() error = %v", err)
	}
	if set.BackendVersion != BackendVersion {
		t.Fatalf("backend version = %q, want %q", set.BackendVersion, BackendVersion)
	}
	if set.Decision != DecisionReady {
		t.Fatalf("decision = %q, want %q", set.Decision, DecisionReady)
	}
	if !containsAll(set.UIStates.States, RequiredUIStates()) {
		t.Fatalf("UI states = %v, want all %v", set.UIStates.States, RequiredUIStates())
	}
	if !set.FlowIntegration.ConnectedThroughCarrier {
		t.Fatal("M59 must represent Android flow connected through reviewed carrier path")
	}
	if set.PayloadLogged || set.SecretLogged {
		t.Fatal("fixture leaked payload or secret flags")
	}
}

func TestValidateRejectsProfileBypass(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.RuntimePath.BypassesProfileValidation = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("ValidateFixtureSet accepted profile validation bypass")
	}
}

func TestValidateRejectsCarrierReviewBypass(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.CarrierSelection.CarrierReviewEnforced = false
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("ValidateFixtureSet accepted missing carrier review enforcement")
	}
}

func TestValidateRejectsRelayIncompatibleBypass(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.RelayCompatibility.RelayBypassAllowed = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("ValidateFixtureSet accepted relay compatibility bypass")
	}
}

func TestValidateRejectsUnboundedFallback(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.ReconnectFallback.UnboundedRetry = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("ValidateFixtureSet accepted unbounded reconnect/fallback")
	}
}

func TestValidateRejectsUnsafeDiagnostics(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.FailureDiagnostics.PayloadLogged = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("ValidateFixtureSet accepted payload logging diagnostics")
	}
}

func TestCompareDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.FixtureHash = "sha256:changed"
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != "failed" {
		t.Fatalf("drift conclusion = %q, want failed", report.Conclusion)
	}
	if len(report.UnexpectedDrift) == 0 {
		t.Fatal("expected unexpected drift entry")
	}
}

func TestScanForLeakRejectsForbiddenMarkers(t *testing.T) {
	unsafe := map[string]string{"raw_payload": "redacted-test-value"}
	if err := ScanForLeak(unsafe); err == nil {
		t.Fatal("ScanForLeak accepted raw payload marker")
	}
}

func TestRequiredMisuseNames(t *testing.T) {
	names := RequiredMisuseNames()
	if len(names) < 14 {
		t.Fatalf("misuse names = %d, want at least 14", len(names))
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			t.Fatalf("duplicate misuse name %q", name)
		}
		seen[name] = true
	}
}
