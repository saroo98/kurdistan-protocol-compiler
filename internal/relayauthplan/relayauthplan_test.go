// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayauthplan

import "testing"

func TestFixtureSetCoversRelayAuthDesign(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.AuthInventory) < 15 {
		t.Fatalf("auth inventory incomplete: %d", len(set.AuthInventory))
	}
	if len(set.IdentityBinding.BoundComponents) < 6 || !set.IdentityBinding.RelayIdentityRequired || !set.IdentityBinding.ClientProfileIdentityRequired {
		t.Fatalf("identity binding incomplete: %+v", set.IdentityBinding)
	}
	if set.IdentityBinding.UnauthenticatedRelayAllowed || set.CompatibilityMatrix.UnknownVersionFailOpen || set.DowngradeRejection.RejectsSilentDowngrade == false {
		t.Fatalf("unsafe relay auth contract: %+v", set)
	}
	if !set.OperationalPrereqs.M55Ready || len(set.OperationalPrereqs.RequiredArtifacts) < 7 {
		t.Fatalf("M55 prerequisites unsafe: %+v", set.OperationalPrereqs)
	}
}

func TestUnsafeRelayAuthRejected(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.IdentityBinding.UnauthenticatedRelayAllowed = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("unauthenticated relay acceptance was not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.RotationPolicy.RotationWithoutWindow = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("rotation without window was not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.ExpiryRevocation.RevocationMissing = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("missing revocation policy was not rejected")
	}
}

func TestMisuseControlsDetected(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) {
		t.Fatalf("misuse count mismatch: %+v", set.Misuse)
	}
	seen := map[string]bool{}
	for _, control := range set.Misuse.DetectedControls {
		seen[control] = true
	}
	for _, control := range RequiredMisuseNames() {
		if !seen[control] {
			t.Fatalf("missing misuse control %s", control)
		}
	}
}

func TestFixtureDriftDetected(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.IdentityBinding.BoundComponents = append(newSet.IdentityBinding.BoundComponents, "unexpected_component")
	newSet.FixtureHash = HashValue(fixtureHashInput(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != "failed" || len(report.UnexpectedDrift) == 0 {
		t.Fatalf("expected fixture drift, got %+v", report)
	}
}

func TestLeakScannerRejectsUnsafeFields(t *testing.T) {
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"secret_value": "synthetic"},
		map[string]string{"key_material_value": "synthetic"},
		map[string]string{"account_identifier": "synthetic"},
		map[string]string{"cloud_provider_metadata": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe relay auth fixture accepted: %v", tc)
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
