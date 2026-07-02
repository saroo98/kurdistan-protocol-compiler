// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package httpslikecarrier

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateFixtureSet(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || set.BackendVersion != BackendVersion {
		t.Fatalf("unexpected fixture: %+v", set)
	}
	if len(set.Scenarios) < 8 || len(set.Report.ShapeEvents) < 8 {
		t.Fatalf("fixture did not exercise required scenarios: %+v", set.Report)
	}
	if set.Report.BackpressureEvents == 0 || set.Report.StreamResets == 0 || set.Report.TargetErrors == 0 {
		t.Fatalf("missing pressure/reset/error evidence: %+v", set.Report)
	}
	if err := ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
}

func TestValidateConfigRejectsUnsafeBehavior(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowRealTLS = true
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("real TLS flag accepted")
	}
	cfg = DefaultConfig()
	cfg.AllowPublicNetwork = true
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("public network flag accepted")
	}
	cfg = DefaultConfig()
	cfg.AllowPayloadLogging = true
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("payload logging accepted")
	}
}

func TestShapeSelectionIsProfileSensitiveAndBounded(t *testing.T) {
	a := SelectRequestShape("profile-a", 1, 1, 24)
	b := SelectRequestShape("profile-b", 1, 1, 24)
	if a.ShapeClass == b.ShapeClass && a.MarkerClass == b.MarkerClass {
		t.Fatalf("shape selection collapsed: %+v %+v", a, b)
	}
	if a.MarkerBytes > DefaultConfig().MaxMarkerBytes || b.MarkerBytes > DefaultConfig().MaxMarkerBytes {
		t.Fatalf("shape marker exceeded bound")
	}
}

func TestFixtureComparisonDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Report.Completed = false
	newSet.Report.ReportHash = HashValue(reportWithoutHash(newSet.Report))
	newSet.FixtureHash = HashValue(setWithoutHash(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != "failed" {
		t.Fatalf("drift not detected: %+v", report)
	}
}

func TestScanForLeakRejectsUnsafeMarkers(t *testing.T) {
	cases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"claim": "real HTTPS carrier support"},
		map[string]bool{"contains_sni": true},
		map[string]bool{"contains_host_header": true},
		map[string]bool{"allow_public_network": true},
	}
	for _, tc := range cases {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe marker accepted: %+v", tc)
		}
	}
}

func FuzzFixtureJSON(f *testing.F) {
	set, err := GenerateFixtureSet()
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := json.Marshal(set)
	f.Add(string(raw))
	f.Add(`{"claim":"real HTTPS carrier support"}`)
	f.Add(`{"contains_host_header":true}`)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<15 {
			input = input[:1<<15]
		}
		var value any
		if json.Unmarshal([]byte(input), &value) == nil {
			err := ScanForLeak(value)
			lower := strings.ToLower(input)
			if (strings.Contains(lower, "real https carrier") || strings.Contains(lower, "contains_host_header\":true")) && err == nil {
				t.Fatalf("unsafe fixture accepted")
			}
		}
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(); err != nil {
			b.Fatal(err)
		}
	}
}
