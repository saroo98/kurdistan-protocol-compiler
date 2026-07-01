// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kurdistan/internal/carrierreadiness"
	"kurdistan/internal/mutant"
)

func RunCarrierReadinessAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	start := time.Now()
	set, err := carrierreadiness.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	comparison := carrierReadinessComparison(filepath.Join(root, "testdata", "carrierreadiness", "carrierreadiness-golden.json"), set)
	gates := CarrierReadinessGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "carrierreadiness-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     100,
		Gates:            gates,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

func CarrierReadinessGates(set carrierreadiness.FixtureSet, comparison carrierreadiness.FixtureComparisonReport) []GateResult {
	return []GateResult{
		CarrierReadinessInventoryGate(set),
		CarrierReadinessDependencyGate(set),
		CarrierReadinessBoundaryGate(set),
		CarrierReadinessFutureContractGate(set),
		CarrierReadinessBlockerGate(set),
		CarrierReadinessRiskGate(set),
		CarrierReadinessChecklistGate(set),
		CarrierReadinessClaimSafetyGate(set),
		CarrierReadinessGeneratedBackendParityGate(set),
		CarrierReadinessMutantDetectionGate(),
		CarrierReadinessFixtureDriftGate(comparison),
	}
}

func CarrierReadinessInventoryGate(set carrierreadiness.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Review.Inventory) < 6 {
		failures = append(failures, "carrier readiness inventory incomplete")
	}
	return gate("carrierreadiness_inventory", len(failures) == 0, "required", fmt.Sprintf("%d inventory items checked", len(set.Review.Inventory)), nil, failures)
}

func CarrierReadinessDependencyGate(set carrierreadiness.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Review.Dependencies) < 5 {
		failures = append(failures, "carrier readiness dependency graph incomplete")
	}
	return gate("carrierreadiness_dependency_graph", len(failures) == 0, "required", fmt.Sprintf("%d dependency edges checked", len(set.Review.Dependencies)), nil, failures)
}

func CarrierReadinessBoundaryGate(set carrierreadiness.FixtureSet) GateResult {
	failures := []string{}
	for _, boundary := range set.Review.Boundaries {
		if !boundary.Enforced {
			failures = append(failures, "boundary not enforced: "+boundary.Name)
		}
	}
	return gate("carrierreadiness_boundary_policy", len(failures) == 0, "required", fmt.Sprintf("%d boundaries enforced", len(set.Review.Boundaries)), nil, failures)
}

func CarrierReadinessFutureContractGate(set carrierreadiness.FixtureSet) GateResult {
	failures := []string{}
	required := map[string]bool{"M41": false, "M42": false, "M43": false}
	for _, contract := range set.Review.FutureContracts {
		if _, ok := required[contract.Milestone]; ok {
			required[contract.Milestone] = true
		}
	}
	for milestone, ok := range required {
		if !ok {
			failures = append(failures, "missing future contract "+milestone)
		}
	}
	return gate("carrierreadiness_future_contracts", len(failures) == 0, "required", fmt.Sprintf("%d future contracts scoped", len(set.Review.FutureContracts)), nil, failures)
}

func CarrierReadinessBlockerGate(set carrierreadiness.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Review.Blockers) < 5 {
		failures = append(failures, "blocker register incomplete")
	}
	return gate("carrierreadiness_blocker_register", len(failures) == 0, "required", fmt.Sprintf("%d blockers tracked", len(set.Review.Blockers)), nil, failures)
}

func CarrierReadinessRiskGate(set carrierreadiness.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Review.Risks) < 4 {
		failures = append(failures, "risk matrix incomplete")
	}
	return gate("carrierreadiness_risk_matrix", len(failures) == 0, "required", fmt.Sprintf("%d risk items checked", len(set.Review.Risks)), nil, failures)
}

func CarrierReadinessChecklistGate(set carrierreadiness.FixtureSet) GateResult {
	failures := []string{}
	for _, item := range set.Review.Checklist {
		if !item.Checked {
			failures = append(failures, "unchecked readiness item: "+item.Name)
		}
	}
	if set.Review.Decision != carrierreadiness.DecisionReady {
		failures = append(failures, "readiness decision is not ready for next design review")
	}
	return gate("carrierreadiness_checklist", len(failures) == 0, "required", fmt.Sprintf("%d checklist items checked", len(set.Review.Checklist)), nil, failures)
}

func CarrierReadinessClaimSafetyGate(set carrierreadiness.FixtureSet) GateResult {
	failures := []string{}
	if err := carrierreadiness.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	for _, claim := range []string{"guaranteed bypass", "undetectable", "production VPN"} {
		if err := carrierreadiness.ScanForLeak(map[string]string{"claim": claim}); err == nil {
			failures = append(failures, "unsafe public claim accepted: "+claim)
		}
	}
	return gate("carrierreadiness_public_claim_safety", len(failures) == 0, "required", "public claim safety markers checked", nil, failures)
}

func CarrierReadinessGeneratedBackendParityGate(set carrierreadiness.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.SemanticMatches != set.Parity.InventoryCompared+set.Parity.ContractsCompared {
		failures = append(failures, "generated/interpreted carrier readiness parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"carrierreadiness_generated.go", "carrierreadiness_test.go", "carrierreadiness_parity_test.go", "carrierreadiness_hygiene_test.go", "CarrierReadinessSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated carrier readiness marker "+marker)
				}
			}
		}
	}
	return gate("carrierreadiness_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d inventory items compared", set.Parity.InventoryCompared), nil, failures)
}

func CarrierReadinessMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeCarrierReadinessMissingInventory,
		mutant.ModeCarrierReadinessMissingFutureContract,
		mutant.ModeCarrierReadinessAllowsExternalCarrier,
		mutant.ModeCarrierReadinessAllowsDeployment,
		mutant.ModeCarrierReadinessUnsafePublicClaim,
		mutant.ModeCarrierReadinessIgnoresBlocker,
		mutant.ModeCarrierReadinessGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("carrierreadiness_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d carrier readiness mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func CarrierReadinessFixtureDriftGate(report carrierreadiness.FixtureComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("carrierreadiness_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func carrierReadinessComparison(path string, current carrierreadiness.FixtureSet) carrierreadiness.FixtureComparisonReport {
	oldSet, err := carrierreadiness.LoadFixtureSet(path)
	if err != nil {
		return carrierreadiness.FixtureComparisonReport{Version: carrierreadiness.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return carrierreadiness.CompareFixtureSets(oldSet, current)
}
