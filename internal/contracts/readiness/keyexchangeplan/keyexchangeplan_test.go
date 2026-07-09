// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package keyexchangeplan

import "testing"

func TestFixtureSetCoversKeyExchangeDesign(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.DesignInventory) < 10 {
		t.Fatalf("design inventory incomplete: %d", len(set.DesignInventory))
	}
	if len(set.TranscriptBinding.BoundComponents) < 6 || !set.TranscriptBinding.RejectsConfusion {
		t.Fatalf("transcript binding incomplete: %+v", set.TranscriptBinding)
	}
	if set.IdentityBinding.UnauthenticatedRelayID || set.NonceReplay.ReplayAccepted || set.DowngradeResistance.RejectsSilentDowngrade == false {
		t.Fatalf("unsafe key exchange contract: %+v", set)
	}
	if set.ExternalReviewReadiness.ReviewBypassAllowed || !set.ExternalReviewReadiness.IndependentReview {
		t.Fatalf("external review readiness unsafe: %+v", set.ExternalReviewReadiness)
	}
}

func TestUnsafeKeyExchangeRejected(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.NonceReplay.ReplayAccepted = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("unsafe replay acceptance was not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.ExternalReviewReadiness.ReviewBypassAllowed = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("review bypass was not rejected")
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
	newSet.TranscriptBinding.BoundComponents = append(newSet.TranscriptBinding.BoundComponents, "unexpected_component")
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
		map[string]string{"nonce_value": "synthetic"},
		map[string]string{"auth_tag": "synthetic"},
		map[string]string{"private_key": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe key exchange fixture accepted: %v", tc)
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
