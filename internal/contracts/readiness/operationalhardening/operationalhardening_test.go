// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package operationalhardening

import "testing"

func TestFixtureSetCoversOperationalHardeningContract(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Decision != "ready_for_android_architecture_review" {
		t.Fatalf("unexpected decision: %s", set.Decision)
	}
	if set.BlockerCount != 0 || set.RiskCount < 4 {
		t.Fatalf("unexpected blocker/risk counts: blockers=%d risks=%d", set.BlockerCount, set.RiskCount)
	}
	if len(set.ResourceLimits.Bounds) < 8 {
		t.Fatalf("resource limits incomplete: %+v", set.ResourceLimits)
	}
	if len(set.ConfigValidation.RejectedConfigClasses) < 7 {
		t.Fatalf("config rejection coverage incomplete: %+v", set.ConfigValidation)
	}
	if !set.Lifecycle.DeterministicShutdown || !set.Lifecycle.IdempotentRestart || set.Lifecycle.UnboundedRestartLoopAllowed {
		t.Fatalf("unsafe lifecycle contract: %+v", set.Lifecycle)
	}
	if set.Logging.PayloadLogged || set.Logging.SecretLogged || set.Logging.DestinationLogged {
		t.Fatalf("unsafe logging contract: %+v", set.Logging)
	}
	if set.Compatibility.BypassesCarrierReview || set.Compatibility.BypassesMeasurementReview || set.Compatibility.BypassesPathHealth {
		t.Fatalf("compatibility bypass accepted: %+v", set.Compatibility)
	}
}

func TestUnsafeOperationalControlsRejected(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.ResourceLimits.MissingBounds = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("missing resource bounds were not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.ConfigValidation.AllowAmbiguousConfig = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("ambiguous config was not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.Logging.PayloadLogged = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("payload logging was not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.Misuse.DetectedControls = set.Misuse.DetectedControls[:len(set.Misuse.DetectedControls)-1]
	set.Misuse.DetectedCount--
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("missing misuse control was not rejected")
	}
}

func TestRollbackAndHealthDiagnosticsAreSafe(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Rollback.FailClosedRequired == false || len(set.Rollback.ProfileRotationRequired) < 3 {
		t.Fatalf("rollback policy incomplete: %+v", set.Rollback)
	}
	if set.Health.PayloadLogged || set.Health.SecretLogged || set.Health.ExactUserIdentifierLogged || len(set.Health.SafeFields) < 8 {
		t.Fatalf("unsafe health summary: %+v", set.Health)
	}
	if err := ScanForLeak(set); err != nil {
		t.Fatalf("safe fixture flagged as leaking: %v", err)
	}
}

func TestFixtureDriftDetected(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Logging.AllowedFields = append(newSet.Logging.AllowedFields, "unexpected_field")
	newSet.FixtureHash = HashValue(fixtureHashInput(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != "failed" || len(report.UnexpectedDrift) == 0 {
		t.Fatalf("expected fixture drift, got %+v", report)
	}
}

func TestLeakScannerRejectsUnsafeFields(t *testing.T) {
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"destination_url": "synthetic"},
		map[string]string{"profile_secret": "synthetic"},
		map[string]string{"key_material": "synthetic"},
		map[string]string{"exact_user_identifier": "synthetic"},
		map[string]string{"telemetry_upload_endpoint": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe operational fixture accepted: %v", tc)
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
