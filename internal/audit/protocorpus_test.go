// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"encoding/json"
	"testing"
)

func TestProtocolCorpusAuditShape(t *testing.T) {
	report, err := RunProtocolCorpusAudit(context.Background(), AuditConfig{Mode: "quick", ProfileCount: 3, Thresholds: DefaultThresholds()})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() {
		t.Fatalf("protocol corpus audit failed: %+v", report.Gates)
	}
	for _, name := range []string{
		"protocorpus_schema_valid",
		"protocorpus_feature_taxonomy",
		"protocorpus_entry_coverage",
		"protocorpus_trace_hygiene",
	} {
		if _, ok := gateByName(report.Gates, name); !ok {
			t.Fatalf("missing gate %s", name)
		}
	}
	raw, err := json.Marshal(report)
	if err != nil || !json.Valid(raw) {
		t.Fatalf("invalid protocol corpus audit JSON: %v", err)
	}
}

func TestWireFeaturesAuditShape(t *testing.T) {
	report, err := RunWireFeaturesAudit(context.Background(), AuditConfig{Mode: "quick", ProfileCount: 3, Thresholds: DefaultThresholds()})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() {
		t.Fatalf("wirefeatures audit failed: %+v", report.Gates)
	}
	for _, name := range []string{
		"wirefeatures_extraction",
		"wirefeatures_firstn_model",
		"wirefeatures_corpus_comparison",
		"wirefeatures_collapse_resistance",
		"wirefeatures_generated_backend_parity",
		"wirefeatures_mutant_detection",
		"wirefeatures_baseline_fixtures",
	} {
		if _, ok := gateByName(report.Gates, name); !ok {
			t.Fatalf("missing gate %s", name)
		}
	}
	raw, err := json.Marshal(report)
	if err != nil || !json.Valid(raw) {
		t.Fatalf("invalid wirefeatures audit JSON: %v", err)
	}
}

func BenchmarkRunProtocolCorpusAuditQuick(b *testing.B) {
	cfg := AuditConfig{Mode: "quick", ProfileCount: 3, Thresholds: DefaultThresholds()}
	for i := 0; i < b.N; i++ {
		if _, err := RunProtocolCorpusAudit(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRunWireFeaturesAuditQuick(b *testing.B) {
	cfg := AuditConfig{Mode: "quick", ProfileCount: 3, Thresholds: DefaultThresholds()}
	for i := 0; i < b.N; i++ {
		if _, err := RunWireFeaturesAudit(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}
