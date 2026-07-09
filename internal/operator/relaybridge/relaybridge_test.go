// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

import "testing"

func TestGenerateFixtureSetValidates(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet() error = %v", err)
	}
	if set.Conclusion != "passed" {
		t.Fatalf("conclusion = %s", set.Conclusion)
	}
	if BackpressureEvents(set.Reports) == 0 {
		t.Fatalf("backpressure not represented")
	}
	if ResetEvents(set.Reports) == 0 {
		t.Fatalf("reset not represented")
	}
}

func TestBridgeValidationRejectsUnsafeFields(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet() error = %v", err)
	}
	session := set.Sessions[0]
	session.RelayID = "real_relay_endpoint"
	if err := ValidateSession(session); err == nil {
		t.Fatalf("unsafe relay field accepted")
	}
	stream := set.Streams[0]
	stream.StreamID = ""
	if err := ValidateStream(stream); err == nil {
		t.Fatalf("invalid stream accepted")
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
	f.Add(`{"version":"relaybridge-v1","payload_logged":false}`)
	f.Add(`{"real_relay_endpoint":"x"}`)
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
