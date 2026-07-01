// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package httpscarrierreview

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
	if set.Conclusion != "passed" || set.Contract.Decision != DecisionReady {
		t.Fatalf("unexpected HTTPS carrier fixture: %+v", set.Contract)
	}
	if len(set.RequestShapes) < 4 || len(set.ResponseShapes) < 4 || len(set.M42Contract) < 10 {
		t.Fatalf("fixture missing required sections: %+v", set)
	}
	if err := ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
}

func TestBlockedBehaviorIsEnforced(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{
		"real_tls_behavior":          false,
		"real_https_client_behavior": false,
		"real_sni_routing":           false,
		"real_host_header_routing":   false,
		"public_network_egress":      false,
		"payload_logging":            false,
	}
	for _, blocker := range set.Blockers {
		if _, ok := required[blocker.Name]; ok && blocker.Blocked {
			required[blocker.Name] = true
		}
	}
	for name, seen := range required {
		if !seen {
			t.Fatalf("required blocker not enforced: %s", name)
		}
	}
}

func TestFixtureComparisonDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Contract.Decision = StatusReview
	newSet.Contract.ContractHash = HashValue(contractWithoutHash(newSet.Contract))
	newSet.FixtureHash = HashValue(setWithoutHash(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != "failed" {
		t.Fatalf("drift not detected: %+v", report)
	}
}

func TestScanForLeakRejectsUnsafeClaimsAndLeakyFields(t *testing.T) {
	for _, marker := range []string{"raw_payload", "raw_secret", "guaranteed bypass", "undetectable", "production VPN", "working VPN app"} {
		if err := ScanForLeak(map[string]string{"claim": marker}); err == nil {
			t.Fatalf("%s accepted", marker)
		}
	}
	for _, value := range []any{
		map[string]bool{"contains_sni": true},
		map[string]bool{"contains_host_header": true},
		map[string]bool{"payload_logged": true},
	} {
		if err := ScanForLeak(value); err == nil {
			t.Fatalf("unsafe marker accepted: %+v", value)
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
	f.Add(`{"claim":"guaranteed bypass"}`)
	f.Add(`{"contains_sni":true}`)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<15 {
			input = input[:1<<15]
		}
		var v any
		if json.Unmarshal([]byte(input), &v) == nil {
			err := ScanForLeak(v)
			lower := strings.ToLower(input)
			if (strings.Contains(lower, "guaranteed bypass") || strings.Contains(lower, "contains_sni\":true")) && err == nil {
				t.Fatalf("unsafe HTTPS carrier review fixture accepted")
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
