// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrierreadiness

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
	if set.Conclusion != "passed" || set.Review.Decision != DecisionReady {
		t.Fatalf("unexpected readiness fixture: %+v", set.Review)
	}
	if len(set.Review.FutureContracts) != 3 || len(set.Review.Blockers) == 0 || len(set.Review.Boundaries) == 0 {
		t.Fatalf("review missing required sections: %+v", set.Review)
	}
	if err := ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureComparisonDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Review.Decision = StatusNeedsWork
	newSet.Review.ReviewHash = HashValue(reviewWithoutHash(newSet.Review))
	newSet.FixtureHash = HashValue(setWithoutHash(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != "failed" {
		t.Fatalf("drift not detected: %+v", report)
	}
}

func TestScanForLeakRejectsUnsafePublicClaims(t *testing.T) {
	for _, marker := range []string{"raw_payload", "raw_secret", "guaranteed bypass", "undetectable", "production VPN"} {
		if err := ScanForLeak(map[string]string{"claim": marker}); err == nil {
			t.Fatalf("%s accepted", marker)
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
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<15 {
			input = input[:1<<15]
		}
		var v any
		if json.Unmarshal([]byte(input), &v) == nil {
			err := ScanForLeak(v)
			if strings.Contains(strings.ToLower(input), "guaranteed bypass") && err == nil {
				t.Fatalf("unsafe claim accepted")
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
