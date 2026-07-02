// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package multicarrierselect

import "testing"

func TestGenerateFixtureSetCoversSelection(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(set.Report.CarrierFamilies) < len(RequiredFamilyClasses()) {
		t.Fatalf("missing carrier family classes")
	}
	if set.Report.SelectionPolicy.Conclusion != ConclusionPassed || !set.Report.SelectionPolicy.PathRaceEnforced {
		t.Fatalf("selection policy enforcement incomplete: %+v", set.Report.SelectionPolicy)
	}
	if set.Report.ProfileSensitivity.DiversityScore < 0.75 {
		t.Fatalf("insufficient profile diversity: %+v", set.Report.ProfileSensitivity)
	}
}

func TestSelectCarrierIsProfileSensitive(t *testing.T) {
	a := SelectCarrier(12345, "default")
	b := SelectCarrier(12346, "default")
	if a.Family == b.Family {
		t.Fatalf("expected profile-sensitive carrier choice, got %q", a.Family)
	}
	c := SelectCarrier(12346, "survival_preferred")
	if c.Family != FamilyDNSSurvivalLab {
		t.Fatalf("expected DNS survival selection, got %q", c.Family)
	}
}

func TestValidateConfigRejectsUnsafeFallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowUnsafeFallback = true
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected unsafe fallback config rejection")
	}
	cfg = DefaultConfig()
	cfg.MaxCandidates = 1
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected unsafe candidate limit rejection")
	}
}

func TestScanForLeakRejectsUnsafeMaterial(t *testing.T) {
	if err := ScanForLeak(map[string]bool{"payload_logged": false, "secret_logged": false}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"resolver_ip": "synthetic"},
		map[string]string{"host_header": "synthetic"},
		map[string]bool{"allow_public_network": true},
	} {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe metadata accepted: %+v", tc)
		}
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	a, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	b := a
	b.Report.Candidates[0].DecisionClass = "changed"
	b.FixtureHash = HashValue(reportWithoutHash(b))
	report := CompareFixtureSets(a, b)
	if report.Conclusion != ConclusionFailed || len(report.UnexpectedDrift) == 0 {
		t.Fatalf("expected drift failure: %+v", report)
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add(`{"decision_class":"selected_primary"}`)
	f.Add(`{"raw_payload":"x"}`)
	f.Fuzz(func(t *testing.T, s string) {
		_ = ScanForLeak(map[string]string{"input_class": s})
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSelectCarrier(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = SelectCarrier(12345+i, "default")
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
