// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"

	"kurdistan/internal/relayfleet"
)

func TestRelayFleetAuditQuickPasses(t *testing.T) {
	report, err := RunRelayFleetAudit(context.Background(), DefaultConfig("quick"))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() {
		t.Fatalf("relayfleet quick audit failed: %+v", report.Gates)
	}
	for _, name := range []string{
		"relayfleet_lifecycle_integrity",
		"relayfleet_profile_assignment",
		"relayfleet_churn_schedule",
		"relayfleet_migration_model",
		"relayfleet_burn_risk",
		"relayfleet_collapse_detection",
		"relayfleet_control_detection",
		"relayfleet_generated_backend_parity",
		"relayfleet_trace_hygiene",
		"relayfleet_mutant_detection",
	} {
		if gate, ok := gateByName(report.Gates, name); !ok || !gate.Passed {
			t.Fatalf("missing or failed relayfleet gate %s", name)
		}
	}
}

func TestRelayFleetCollapseGateFailsSyntheticFixedFleet(t *testing.T) {
	summary, err := relayfleet.GenerateGoldenSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := range summary.Fleet.Relays {
		summary.Fleet.Relays[i].ProfileSeed = 7
		summary.Fleet.Relays[i].WirePolicyHash = "same"
		summary.Fleet.Relays[i].SelectedFamily = "same"
	}
	summary.Assignment = relayfleet.AnalyzeProfileAssignment(summary.Fleet)
	summary.BurnRisk = relayfleet.ScoreBurnRisk(summary.Fleet, nil)
	summary.Collapse = relayfleet.ScanCollapse(summary.Fleet, summary.Assignment, nil, nil, summary.BurnRisk)
	gate := RelayFleetCollapseDetectionGate(summary.Collapse)
	if gate.Passed {
		t.Fatalf("fixed fleet collapse gate passed: %+v", gate)
	}
}

func BenchmarkRelayFleetAuditQuick(b *testing.B) {
	for i := 0; i < b.N; i++ {
		report, err := RunRelayFleetAudit(context.Background(), DefaultConfig("quick"))
		if err != nil {
			b.Fatal(err)
		}
		if !report.Passed() {
			b.Fatal("relayfleet quick audit failed")
		}
	}
}
