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

	"kurdistan/internal/mutant"
	"kurdistan/internal/productionreadiness"
)

type ProductionReadinessAuditSummary struct {
	Version       string                                        `json:"version"`
	ItemCount     int                                           `json:"item_count"`
	ContractCount int                                           `json:"contract_count"`
	BoundaryCount int                                           `json:"boundary_count"`
	Comparison    productionreadiness.ReadinessComparisonReport `json:"comparison"`
	Conclusion    string                                        `json:"conclusion"`
}

func RunProductionReadinessAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	review, err := productionreadiness.GenerateReview()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := productionReadinessComparison(filepath.Join(root, "testdata", "productionreadiness", "productionreadiness-golden.json"), review)
	gates := ProductionReadinessGates(review, comparison)
	summary := ProductionReadinessAuditSummary{
		Version:       productionreadiness.Version,
		ItemCount:     len(review.Items),
		ContractCount: len(review.Contracts),
		BoundaryCount: len(review.Boundaries),
		Comparison:    comparison,
		Conclusion:    "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "productionreadiness-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
		TraceCount:       0,
		Gates:            gates,
		TraceScanSummary: summary,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
		summary.Conclusion = "failed"
		report.TraceScanSummary = summary
	}
	return report, nil
}

func ProductionReadinessGates(review productionreadiness.ProductionReadinessReview, comparison productionreadiness.ReadinessComparisonReport) []GateResult {
	return []GateResult{
		ProductionReadinessInventoryGate(review),
		ProductionReadinessDependencyGraphGate(review),
		ProductionReadinessRealIOBoundaryGate(review),
		ProductionReadinessFutureContractsGate(review),
		ProductionReadinessBlockerRegisterGate(review),
		ProductionReadinessTraceHygieneGate(review),
		ProductionReadinessGeneratedBackendParityGate(review),
		ProductionReadinessMutantDetectionGate(),
		ProductionReadinessFixtureDriftGate(comparison),
	}
}

func ProductionReadinessInventoryGate(review productionreadiness.ProductionReadinessReview) GateResult {
	failures := []string{}
	if err := productionreadiness.ValidateReview(review); err != nil {
		failures = append(failures, err.Error())
	}
	if len(review.Items) < 18 {
		failures = append(failures, "readiness inventory too small")
	}
	return gate("productionreadiness_inventory", len(failures) == 0, "required", fmt.Sprintf("%d readiness items checked", len(review.Items)), nil, failures)
}

func ProductionReadinessDependencyGraphGate(review productionreadiness.ProductionReadinessReview) GateResult {
	failures := []string{}
	if len(review.Dependencies) < 10 {
		failures = append(failures, "dependency graph too small")
	}
	required := []string{"end-to-end local proxy pipeline", "M36"}
	seen := map[string]bool{}
	for _, edge := range review.Dependencies {
		seen[edge.From] = true
		seen[edge.To] = true
	}
	for _, name := range required {
		if !seen[name] {
			failures = append(failures, "missing dependency node "+name)
		}
	}
	return gate("productionreadiness_dependency_graph", len(failures) == 0, "required", fmt.Sprintf("%d dependency edges checked", len(review.Dependencies)), nil, failures)
}

func ProductionReadinessRealIOBoundaryGate(review productionreadiness.ProductionReadinessReview) GateResult {
	failures := []string{}
	for _, boundary := range review.Boundaries {
		if boundary.Allowed || boundary.Conclusion != "passed" {
			failures = append(failures, "unsafe boundary "+boundary.Name)
		}
	}
	return gate("productionreadiness_real_io_boundary", len(failures) == 0, "required", fmt.Sprintf("%d closed boundaries checked", len(review.Boundaries)), nil, failures)
}

func ProductionReadinessFutureContractsGate(review productionreadiness.ProductionReadinessReview) GateResult {
	failures := []string{}
	foundM36 := false
	for _, contract := range review.Contracts {
		if contract.Milestone == "M36" {
			foundM36 = true
		}
		if contract.Name == "" || len(contract.ForbiddenScopes) == 0 || len(contract.RequiredGates) == 0 {
			failures = append(failures, "incomplete contract "+contract.Milestone)
		}
	}
	if !foundM36 {
		failures = append(failures, "missing M36 contract")
	}
	return gate("productionreadiness_future_contracts", len(failures) == 0, "required", fmt.Sprintf("%d future contracts checked", len(review.Contracts)), nil, failures)
}

func ProductionReadinessBlockerRegisterGate(review productionreadiness.ProductionReadinessReview) GateResult {
	failures := []string{}
	required := 0
	for _, blocker := range review.Blockers {
		if blocker.Required {
			required++
		}
		if blocker.ID == "" || blocker.Severity == "" || blocker.Category == "" {
			failures = append(failures, "invalid blocker")
		}
	}
	if required < 4 {
		failures = append(failures, "missing required blockers")
	}
	return gate("productionreadiness_blocker_register", len(failures) == 0, "required", fmt.Sprintf("%d blockers tracked; %d required blockers unresolved", len(review.Blockers), required), nil, failures)
}

func ProductionReadinessTraceHygieneGate(review productionreadiness.ProductionReadinessReview) GateResult {
	failures := []string{}
	if err := productionreadiness.ScanForLeak(review); err != nil {
		failures = append(failures, err.Error())
	}
	for _, unsafe := range []map[string]string{{"raw_payload": "x"}, {"encoded_bytes": "x"}, {"dns_query": "x"}, {"deployment_token": "x"}, {"claim": "undetectable"}} {
		if err := productionreadiness.ScanForLeak(unsafe); err == nil {
			failures = append(failures, "unsafe production readiness metadata accepted")
		}
	}
	return gate("productionreadiness_trace_hygiene", len(failures) == 0, "required", "production readiness review contains safe metadata only", nil, failures)
}

func ProductionReadinessGeneratedBackendParityGate(review productionreadiness.ProductionReadinessReview) GateResult {
	failures := []string{}
	if review.Parity.Conclusion != "passed" {
		failures = append(failures, review.Parity.UnexpectedDifferences...)
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"productionreadiness_generated.go", "productionreadiness_test.go", "productionreadiness_parity_test.go", "productionreadiness_hygiene_test.go", "ProductionReadinessSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated productionreadiness marker "+marker)
				}
			}
		}
	}
	return gate("productionreadiness_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d items and %d contracts compared", review.Parity.ItemsCompared, review.Parity.ContractsCompared), nil, failures)
}

func ProductionReadinessMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeProductionReadinessMissingBoundary,
		mutant.ModeProductionReadinessAllowsRealIO,
		mutant.ModeProductionReadinessAllowsDeployment,
		mutant.ModeProductionReadinessPayloadTraceLeak,
		mutant.ModeProductionReadinessSecretTraceLeak,
		mutant.ModeProductionReadinessMissingM36Contract,
		mutant.ModeProductionReadinessIgnoresBlockers,
		mutant.ModeProductionReadinessGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("productionreadiness_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d productionreadiness mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func ProductionReadinessFixtureDriftGate(report productionreadiness.ReadinessComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("productionreadiness_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func productionReadinessComparison(path string, current productionreadiness.ProductionReadinessReview) productionreadiness.ReadinessComparisonReport {
	oldReview, err := productionreadiness.LoadReview(path)
	if err != nil {
		return productionreadiness.ReadinessComparisonReport{Version: productionreadiness.Version, NewHash: current.ReviewHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return productionreadiness.CompareReviews(oldReview, current)
}
