// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"encoding/json"
	"testing"

	"kurdistan/internal/byteparity"
	"kurdistan/internal/fixtures"
)

func TestBytePathParityGateFailsOnUnexpectedDrift(t *testing.T) {
	report := byteparity.ByteParityReport{ComparedPairs: 1, SemanticMatches: 0, UnexpectedDifferences: []string{"frame_count"}}
	gate := BytePathGeneratedInterpretedParityGate(report)
	if gate.Passed {
		t.Fatalf("parity drift gate passed unexpectedly")
	}
}

func TestBytePathMalformedCorpusGatePasses(t *testing.T) {
	gate := BytePathMalformedCorpusGate("", fixtures.DefaultMalformedCorpus())
	if !gate.Passed {
		t.Fatalf("malformed corpus gate failed: %#v", gate)
	}
}

func TestRunBytePathAuditShape(t *testing.T) {
	report, err := RunBytePathAudit(context.Background(), AuditConfig{Mode: "quick", ProfileCount: 3, Thresholds: DefaultThresholds()})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatalf("invalid audit JSON")
	}
	required := []string{
		"fixture_bytepath_drift",
		"bytepath_fixture_stability",
		"bytepath_generated_interpreted_parity",
		"bytepath_malformed_corpus",
		"bytepath_regression_baselines",
		"bytepath_fixture_trace_hygiene",
	}
	for _, name := range required {
		if _, ok := gateByName(report.Gates, name); !ok {
			t.Fatalf("missing gate %s", name)
		}
	}
}

func BenchmarkRunBytePathAuditQuick(b *testing.B) {
	cfg := AuditConfig{Mode: "quick", ProfileCount: 3, Thresholds: DefaultThresholds()}
	for i := 0; i < b.N; i++ {
		if _, err := RunBytePathAudit(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}
