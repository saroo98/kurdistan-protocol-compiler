// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidreview

import "testing"

func TestFixtureSetCoversAndroidArchitectureContract(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Decision != "ready_for_android_local_runtime_port" {
		t.Fatalf("unexpected decision: %s", set.Decision)
	}
	if set.BlockerCount != 0 || set.RiskCount < 5 {
		t.Fatalf("unexpected blocker/risk counts: blockers=%d risks=%d", set.BlockerCount, set.RiskCount)
	}
	if len(set.UserFlows.Flows) < 10 {
		t.Fatalf("user flow coverage incomplete: %+v", set.UserFlows)
	}
	if len(set.Permissions.RequiredPermissions) < 4 || set.Permissions.BypassesVPNPermission {
		t.Fatalf("unsafe permission model: %+v", set.Permissions)
	}
	if len(set.UIStates.States) < 14 {
		t.Fatalf("UI state model incomplete: %+v", set.UIStates)
	}
	if set.Diagnostics.PayloadLogged || set.Diagnostics.SecretLogged || set.Diagnostics.AutoUploadAllowed {
		t.Fatalf("unsafe diagnostics contract: %+v", set.Diagnostics)
	}
	if set.KillSwitch.FailClosedRequired == false || set.KillSwitch.BypassAllowed {
		t.Fatalf("unsafe kill-switch contract: %+v", set.KillSwitch)
	}
}

func TestUnsafeAndroidReviewControlsRejected(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.Permissions.BypassesVPNPermission = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("VPN permission bypass was not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.Diagnostics.PayloadLogged = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("payload diagnostics were not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.Privacy.PreciseLocationCollected = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("precise location collection was not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.Contracts.M57Requirements = set.Contracts.M57Requirements[:len(set.Contracts.M57Requirements)-1]
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("incomplete M57 contract was not rejected")
	}
}

func TestAndroidArchitectureFixtureDriftDetected(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.UIStates.States = append(newSet.UIStates.States, "unexpected_state")
	newSet.FixtureHash = HashValue(fixtureHashInput(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != "failed" || len(report.UnexpectedDrift) == 0 {
		t.Fatalf("expected fixture drift, got %+v", report)
	}
}

func TestAndroidReviewLeakScannerRejectsUnsafeFields(t *testing.T) {
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"visited_domain": "synthetic"},
		map[string]string{"dns_query": "synthetic"},
		map[string]string{"phone_identifier": "synthetic"},
		map[string]string{"telemetry_upload_endpoint": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe Android review fixture accepted: %v", tc)
		}
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add(`{"summary":"safe"}`)
	f.Add(`{"raw_payload":"x"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		_ = ScanForLeak(map[string]string{"input": raw})
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompareFixtureSets(b *testing.B) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	newSet, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CompareFixtureSets(oldSet, newSet)
	}
}

func BenchmarkScanForLeak(b *testing.B) {
	set, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ScanForLeak(set); err != nil {
			b.Fatal(err)
		}
	}
}
