// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"

	"kurdistan/internal/pathrace"
)

func TestPathRaceGatesPassAndDetectControls(t *testing.T) {
	set, err := pathrace.GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gates := PathRaceGates(set, pathrace.CompareFixtureSets(set, set))
	for _, gate := range gates {
		if !gate.Passed {
			t.Fatalf("gate %s failed: %+v", gate.Name, gate)
		}
	}
	if gate, ok := gateByName(gates, "pathrace_misuse_detection"); !ok || !gate.Passed {
		t.Fatalf("missing misuse gate: %+v", gates)
	}
}

func TestPathRaceAuditQuickIncludesRequiredGates(t *testing.T) {
	report, err := RunPathRaceAudit(context.Background(), DefaultConfig("quick"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"pathrace_scenario_validation",
		"pathrace_parallel_scheduler",
		"pathrace_candidate_verification",
		"pathrace_short_lived_scoring",
		"pathrace_ranking_tiebreak",
		"pathrace_misuse_detection",
		"pathrace_generated_backend_parity",
		"pathrace_trace_hygiene",
		"pathrace_mutant_detection",
	} {
		if _, ok := gateByName(report.Gates, name); !ok {
			t.Fatalf("missing pathrace gate %s", name)
		}
	}
}
