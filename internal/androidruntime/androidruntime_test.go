// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidruntime

import "testing"

func TestFixtureSetCoversAndroidLocalRuntimePort(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Decision != "ready_for_android_vpnservice_prototype" {
		t.Fatalf("unexpected decision: %s", set.Decision)
	}
	if set.BlockerCount != 0 || set.RiskCount < 6 {
		t.Fatalf("unexpected blocker/risk counts: blockers=%d risks=%d", set.BlockerCount, set.RiskCount)
	}
	if len(set.Initialization.Steps) < 7 || !set.Initialization.ProfileValidated || set.Initialization.VpnTrafficCaptured {
		t.Fatalf("unsafe initialization report: %+v", set.Initialization)
	}
	if len(set.Lifecycle.Events) < 10 || len(set.Lifecycle.InvalidTransitionsRejected) < 5 || set.Lifecycle.StaleSessionReused {
		t.Fatalf("unsafe lifecycle report: %+v", set.Lifecycle)
	}
	if set.Diagnostics.PayloadLogged || set.Diagnostics.SecretLogged || set.Diagnostics.AutoUploadAllowed {
		t.Fatalf("unsafe diagnostics report: %+v", set.Diagnostics)
	}
	if set.Concurrency.UnboundedWorkers || set.Concurrency.UnboundedQueues || set.Concurrency.StaleSessionAllowed {
		t.Fatalf("unsafe concurrency report: %+v", set.Concurrency)
	}
	if set.Shutdown.CloseIdempotent == false || set.Shutdown.LeakedWorkers != 0 {
		t.Fatalf("unsafe shutdown report: %+v", set.Shutdown)
	}
}

func TestUnsafeAndroidRuntimeControlsRejected(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	set.Initialization.ProfileValidated = false
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("unvalidated profile startup was not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.Initialization.VpnTrafficCaptured = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("VPN traffic capture in M57 was not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.Concurrency.UnboundedWorkers = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("unbounded Android runtime workers were not rejected")
	}
	set, _ = GenerateFixtureSet()
	set.Diagnostics.PayloadLogged = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("payload diagnostics were not rejected")
	}
}

func TestAndroidRuntimeFixtureDriftDetected(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Lifecycle.Events = append(newSet.Lifecycle.Events, "unexpected_event")
	newSet.FixtureHash = HashValue(fixtureHashInput(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != "failed" || len(report.UnexpectedDrift) == 0 {
		t.Fatalf("expected fixture drift, got %+v", report)
	}
}

func TestAndroidRuntimeLeakScannerRejectsUnsafeFields(t *testing.T) {
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"packet_capture": "synthetic"},
		map[string]string{"visited_domain": "synthetic"},
		map[string]string{"device_identifier": "synthetic"},
		map[string]string{"telemetry_upload_endpoint": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe Android runtime fixture accepted: %v", tc)
		}
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add(`{"summary":"safe"}`)
	f.Add(`{"packet_capture":"x"}`)
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
