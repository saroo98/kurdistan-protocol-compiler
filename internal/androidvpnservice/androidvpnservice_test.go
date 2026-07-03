// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidvpnservice

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
	if !containsAll(set.Lifecycle.States, RequiredVPNStates()) {
		t.Fatalf("lifecycle states = %v, want all %v", set.Lifecycle.States, RequiredVPNStates())
	}
	if set.PacketFlow.CarrierConnectedTraffic {
		t.Fatal("M58 must not enable carrier-connected Android traffic")
	}
	if set.PayloadLogged || set.SecretLogged {
		t.Fatal("fixture leaked payload or secret flags")
	}
}

func TestValidateRejectsPermissionBypass(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.Permission.StartWithoutPermission = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("ValidateFixtureSet accepted start without permission")
	}
}

func TestValidateRejectsUnsafeLifecycle(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.Lifecycle.PostStopPacketAccepted = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("ValidateFixtureSet accepted packet flow after stop")
	}
}

func TestValidateRejectsCarrierConnectedTraffic(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.PacketFlow.CarrierConnectedTraffic = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("ValidateFixtureSet accepted carrier-connected Android traffic in M58")
	}
}

func TestValidateRejectsFailOpenKillSwitch(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.KillSwitch.CarrierRuntimeFailureFailsOpen = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("ValidateFixtureSet accepted fail-open carrier runtime failure")
	}
}

func TestValidateRejectsUnsafeDiagnostics(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.Diagnostics.PayloadLogged = true
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
	if len(names) < 12 {
		t.Fatalf("misuse names = %d, want at least 12", len(names))
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			t.Fatalf("duplicate misuse name %q", name)
		}
		seen[name] = true
	}
}
