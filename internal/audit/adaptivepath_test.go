// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"

	"kurdistan/internal/adaptivepath"
)

func TestAdaptivePathGatesPass(t *testing.T) {
	set, err := adaptivepath.GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	comparison := adaptivepath.CompareFixtureSets(set, set)
	for _, gate := range AdaptivePathGates(set, comparison) {
		if !gate.Passed {
			t.Fatalf("%s failed: %s", gate.Name, gate.Summary)
		}
	}
}

func TestAdaptivePathMisuseGateDetectsCollapsedControl(t *testing.T) {
	set, err := adaptivepath.GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	set.CollapsedControl = adaptivepath.AdaptivePathMisuseReport{Conclusion: "passed"}
	gate := AdaptivePathMisuseDetectionGate(set)
	if gate.Passed {
		t.Fatalf("collapsed control was not required by misuse gate")
	}
}

func TestAdaptivePathTraceHygieneGateRejectsUnsafeFields(t *testing.T) {
	set, err := adaptivepath.GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gate := AdaptivePathTraceHygieneGate(set)
	if !gate.Passed {
		t.Fatalf("clean fixture rejected: %s", gate.Summary)
	}
	if err := adaptivepath.ScanForLeak(map[string]string{"endpoint": "synthetic"}); err == nil {
		t.Fatalf("endpoint field accepted")
	}
	if err := adaptivepath.ScanForLeak(map[string]string{"resolver_ip": "synthetic"}); err == nil {
		t.Fatalf("resolver field accepted")
	}
}

func TestAdaptivePathAuditQuickIncludesRequiredGates(t *testing.T) {
	report, err := RunAdaptivePathAudit(context.Background(), DefaultConfig("quick"))
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"adaptivepath_candidate_taxonomy",
		"adaptivepath_condition_model",
		"adaptivepath_freshness_uncertainty",
		"adaptivepath_viability_evaluation",
		"adaptivepath_decision_inputs",
		"adaptivepath_misuse_detection",
		"adaptivepath_generated_backend_parity",
		"adaptivepath_trace_hygiene",
		"adaptivepath_mutant_detection",
		"adaptivepath_roadmap_public_docs",
	}
	for _, name := range required {
		if _, ok := gateByName(report.Gates, name); !ok {
			t.Fatalf("missing adaptivepath gate %s", name)
		}
	}
}

func BenchmarkAdaptivePathQuickAudit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		report, err := RunAdaptivePathAudit(context.Background(), DefaultConfig("quick"))
		if err != nil {
			b.Fatal(err)
		}
		if len(report.Gates) == 0 {
			b.Fatal("no gates")
		}
	}
}
