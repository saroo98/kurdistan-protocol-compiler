// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package vpnsemantics

import "testing"

func TestGenerateFixtureSetCoversM51Contract(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if set.M51Contract.Decision != DecisionReady || len(set.Scope.BlockedBehaviors) < 10 || set.PayloadLogged || set.SecretLogged {
		t.Fatalf("M51 contract or hygiene incomplete: %+v", set)
	}
}

func TestMisuseControlsDetected(t *testing.T) {
	report := BuildMisuseReport()
	if report.DetectedCount != len(RequiredMisuseNames()) || report.ExpectedCount != len(RequiredMisuseNames()) || report.Conclusion != ConclusionPassed {
		t.Fatalf("misuse report incomplete: %+v", report)
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Taxonomy.PacketFlowClasses = append(newSet.Taxonomy.PacketFlowClasses, "extra_class")
	newSet.FixtureHash = HashValue(fixtureHashInput(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion == ConclusionPassed || len(report.UnexpectedDrift) == 0 {
		t.Fatalf("drift was not detected: %+v", report)
	}
}

func TestScanForLeakRejectsUnsafeFields(t *testing.T) {
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_packet_bytes": "synthetic"},
		map[string]string{"app_identity_value": "synthetic"},
		map[string]string{"exact_endpoint_value": "synthetic"},
		map[string]bool{"payload_logged": true},
		map[string]bool{"android_vpnservice": true},
	}
	for _, tc := range unsafeCases {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe metadata accepted: %#v", tc)
		}
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add(`{"packet_flow_class":"tcp_like_flow"}`)
	f.Add(`{"raw_packet_bytes":"synthetic"}`)
	f.Fuzz(func(t *testing.T, input string) {
		_ = ScanForLeak(map[string]string{"value": input})
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
