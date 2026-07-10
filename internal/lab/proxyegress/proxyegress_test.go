// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyegress

import "testing"

func TestGenerateFixtureSetValidates(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet() error = %v", err)
	}
	if set.Conclusion != "passed" {
		t.Fatalf("conclusion = %s", set.Conclusion)
	}
	if len(set.Scenarios) < 12 {
		t.Fatalf("scenario count = %d", len(set.Scenarios))
	}
	if set.PayloadLogged || set.SecretLogged {
		t.Fatalf("fixture leaked payload or secret")
	}
}

func TestRequestTargetAndMappingValidationRejectUnsafeInput(t *testing.T) {
	scenario := DefaultScenarios()[0]
	req := RequestDescriptorFor(scenario)
	if err := ValidateRequestDescriptor(req); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	req.TargetClass = "real_endpoint"
	if err := ValidateRequestDescriptor(req); err == nil {
		t.Fatalf("invalid target class accepted")
	}
	target := TargetDescriptorFor(scenario)
	target.TargetID = "target_with_dns_query"
	if err := ValidateTargetDescriptor(target); err == nil {
		t.Fatalf("unsafe target descriptor accepted")
	}
}

func TestLifecycleBackpressureAndResetIsolation(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet() error = %v", err)
	}
	if set.Backpressure.Conclusion != "passed" || set.Backpressure.PressureEvents == 0 {
		t.Fatalf("backpressure not preserved: %+v", set.Backpressure)
	}
	if set.ResetError.Conclusion != "passed" || set.ResetError.ResetEvents == 0 || set.ResetError.ErrorEvents == 0 {
		t.Fatalf("reset/error isolation not represented: %+v", set.ResetError)
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet() error = %v", err)
	}
	changed := set
	changed.FixtureHash = "sha256:changed"
	report := CompareFixtureSets(set, changed)
	if report.Conclusion != "failed" {
		t.Fatalf("drift not detected: %+v", report)
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add(`{"version":"proxyegress-v1","payload_logged":false}`)
	f.Add(`{"endpoint":"example"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		_ = ScanForLeak(map[string]string{"input_class": raw})
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMisuseScanner(b *testing.B) {
	set, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if report := ScanMisuse(set); report.Conclusion != "passed" {
			b.Fatal(report)
		}
	}
}
