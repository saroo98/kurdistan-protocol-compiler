// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyadapterreview

import (
	"encoding/json"
	"testing"
)

func TestGenerateFixtureSetCoversM49Contract(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet: %v", err)
	}
	if set.M49Contract.CommandName != "localproxyadapter" {
		t.Fatalf("unexpected M49 command: %s", set.M49Contract.CommandName)
	}
	if len(set.Protocols.AcceptedProtocols) != 2 {
		t.Fatalf("expected SOCKS-like and CONNECT-like local protocols")
	}
	if set.Payload.PayloadLogged || set.SecretLogged || set.Payload.RawPayloadCommitted {
		t.Fatalf("unsafe logging flags set")
	}
}

func TestMisuseControlsDetected(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet: %v", err)
	}
	have := map[string]bool{}
	for _, name := range set.Misuse.DetectedControls {
		have[name] = true
	}
	for _, name := range RequiredMisuseNames() {
		if !have[name] {
			t.Fatalf("missing misuse control %s", name)
		}
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	a, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet: %v", err)
	}
	b := a
	b.Scope.Decision = "changed"
	b.FixtureHash = HashValue(hashInput(b))
	report := CompareFixtureSets(a, b)
	if report.Conclusion != "failed" || len(report.UnexpectedDrift) == 0 {
		t.Fatalf("expected drift failure: %+v", report)
	}
}

func TestScanForLeakRejectsUnsafeFields(t *testing.T) {
	if err := ScanForLeak(map[string]string{"class": "safe_bucket"}); err != nil {
		t.Fatalf("safe scan failed: %v", err)
	}
	if err := ScanForLeak(map[string]string{"raw_payload": "blocked"}); err == nil {
		t.Fatalf("raw payload marker accepted")
	}
	if err := ScanForLeak(map[string]bool{"secret_logged": true}); err == nil {
		t.Fatalf("secret logging flag accepted")
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add(`{"class":"safe_bucket"}`)
	f.Add(`{"raw_payload":"blocked"}`)
	f.Fuzz(func(t *testing.T, input string) {
		var value any
		if err := json.Unmarshal([]byte(input), &value); err != nil {
			value = map[string]string{"input_class": "malformed_json"}
		}
		_ = ScanForLeak(value)
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
	set, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CompareFixtureSets(set, set)
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
