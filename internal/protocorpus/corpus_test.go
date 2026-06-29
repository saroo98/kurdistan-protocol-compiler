// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

import (
	"encoding/json"
	"testing"
)

func TestDefaultCorpusValidates(t *testing.T) {
	corpus := DefaultCorpus()
	if err := ValidateManifest(corpus); err != nil {
		t.Fatalf("default corpus invalid: %v", err)
	}
	if len(corpus.Entries) < 12 {
		t.Fatalf("expected at least 12 corpus entries, got %d", len(corpus.Entries))
	}
	if report := ValidateRedaction(corpus); !report.Passed {
		t.Fatalf("default corpus redaction failed: %v", report.Findings)
	}
}

func TestCorpusRejectsInvalidTaxonomy(t *testing.T) {
	corpus := DefaultCorpus()
	corpus.Entries[0].Family = "bad"
	if err := ValidateManifest(corpus); err == nil {
		t.Fatalf("invalid family accepted")
	}
	corpus = DefaultCorpus()
	corpus.Entries[0].Phases[0].Phase = "bad"
	if err := ValidateManifest(corpus); err == nil {
		t.Fatalf("invalid phase accepted")
	}
	corpus = DefaultCorpus()
	corpus.Entries[0].Phases[0].Fields[0].Kind = "bad"
	if err := ValidateManifest(corpus); err == nil {
		t.Fatalf("invalid field kind accepted")
	}
	corpus = DefaultCorpus()
	corpus.Entries[0].Phases[0].Fields[0].Visibility = "bad"
	if err := ValidateManifest(corpus); err == nil {
		t.Fatalf("invalid visibility accepted")
	}
}

func TestCorpusRejectsUnsafeFeatureText(t *testing.T) {
	corpus := DefaultCorpus()
	corpus.Entries[0].Notes = append(corpus.Entries[0].Notes, "raw_payload")
	if err := ValidateManifest(corpus); err == nil {
		t.Fatalf("unsafe corpus text accepted")
	}
}

func TestCorpusHashStable(t *testing.T) {
	corpus := DefaultCorpus()
	a, err := HashValue(corpus)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashValue(corpus)
	if err != nil {
		t.Fatal(err)
	}
	if a == "" || a != b {
		t.Fatalf("unstable corpus hash: %q %q", a, b)
	}
}

func TestCorpusCompareDetectsChange(t *testing.T) {
	oldCorpus := DefaultCorpus()
	newCorpus := DefaultCorpus()
	newCorpus.Entries[0].ControlRichness = "changed"
	report := CompareManifests(oldCorpus, newCorpus)
	if report.Passed || len(report.Changed) == 0 {
		t.Fatalf("expected changed corpus report, got %#v", report)
	}
}

func FuzzCorpusManifestParser(f *testing.F) {
	raw, _ := StableJSON(DefaultCorpus())
	f.Add(string(raw))
	f.Add(`{"version":"bad"}`)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64*1024 {
			t.Skip()
		}
		var manifest CorpusManifest
		if err := json.Unmarshal([]byte(input), &manifest); err == nil {
			_ = ValidateManifest(manifest)
		}
	})
}

func BenchmarkCorpusManifestValidation(b *testing.B) {
	corpus := DefaultCorpus()
	for i := 0; i < b.N; i++ {
		if err := ValidateManifest(corpus); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCorpusHashCalculation(b *testing.B) {
	corpus := DefaultCorpus()
	for i := 0; i < b.N; i++ {
		if _, err := HashValue(corpus); err != nil {
			b.Fatal(err)
		}
	}
}
