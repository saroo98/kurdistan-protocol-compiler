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

	"kurdistan/internal/localpipeline"
	"kurdistan/internal/mutant"
)

type LocalPipelineAuditSummary struct {
	Version       string                                 `json:"version"`
	ScenarioCount int                                    `json:"scenario_count"`
	RunCount      int                                    `json:"run_count"`
	Boundary      localpipeline.PipelineBoundaryReport   `json:"boundary"`
	Collapse      localpipeline.PipelineCollapseReport   `json:"collapse"`
	Parity        localpipeline.PipelineParityReport     `json:"parity"`
	Comparison    localpipeline.PipelineComparisonReport `json:"comparison"`
	Conclusion    string                                 `json:"conclusion"`
}

func RunLocalPipelineAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := localpipeline.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := localPipelineComparison(filepath.Join(root, "testdata", "localpipeline", "localpipeline-golden.json"), set)
	gates := LocalPipelineGates(set, comparison)
	summary := LocalPipelineAuditSummary{
		Version:       localpipeline.Version,
		ScenarioCount: len(set.Scenarios),
		RunCount:      len(set.Runs),
		Boundary:      set.Boundary,
		Collapse:      set.Collapse,
		Parity:        set.Parity,
		Comparison:    comparison,
		Conclusion:    "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "localpipeline-" + cfg.Mode,
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

func LocalPipelineGates(set localpipeline.PipelineFixtureSet, comparison localpipeline.PipelineComparisonReport) []GateResult {
	return []GateResult{
		LocalPipelineCorrectnessGate(set),
		LocalPipelineBoundaryIntegrationGate(set),
		LocalPipelineBackpressureGate(set),
		LocalPipelineErrorResetIsolationGate(set),
		LocalPipelineDescriptorRejectionGate(set),
		LocalPipelineTraceHygieneGate(set),
		LocalPipelineCollapseResistanceGate(set),
		LocalPipelineGeneratedBackendParityGate(set),
		LocalPipelineMutantDetectionGate(),
		LocalPipelineFixtureDriftGate(comparison),
	}
}

func LocalPipelineCorrectnessGate(set localpipeline.PipelineFixtureSet) GateResult {
	failures := []string{}
	if err := localpipeline.ValidateFixtureSet(set); err != nil {
		failures = append(failures, err.Error())
	}
	passedRuns := 0
	for _, run := range set.Runs {
		if run.Conclusion == "passed" {
			passedRuns++
		}
	}
	if passedRuns < 8 {
		failures = append(failures, "insufficient successful local pipeline scenarios")
	}
	return gate("localpipeline_correctness", len(failures) == 0, "required", fmt.Sprintf("%d runs checked", len(set.Runs)), nil, failures)
}

func LocalPipelineBoundaryIntegrationGate(set localpipeline.PipelineFixtureSet) GateResult {
	failures := []string{}
	b := set.Boundary
	if b.Conclusion != "passed" || !b.IngressBound || !b.EgressBound || !b.BridgeBound || !b.RuntimeBound || !b.CarrierBound || !b.ByteTransportBound || !b.AdaptiveBound {
		failures = append(failures, "pipeline boundary integration incomplete")
	}
	return gate("localpipeline_boundary_integration", len(failures) == 0, "required", fmt.Sprintf("%d scenarios bound", b.ScenariosChecked), nil, failures)
}

func LocalPipelineBackpressureGate(set localpipeline.PipelineFixtureSet) GateResult {
	failures := []string{}
	total := 0
	for _, run := range set.Runs {
		total += run.BackpressureEvents
	}
	if total == 0 {
		failures = append(failures, "pipeline backpressure not observed")
	}
	return gate("localpipeline_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d pressure events", total), nil, failures)
}

func LocalPipelineErrorResetIsolationGate(set localpipeline.PipelineFixtureSet) GateResult {
	failures := []string{}
	errors, resets := 0, 0
	for _, run := range set.Runs {
		errors += run.TargetErrors
		resets += run.TargetResets
	}
	if errors == 0 || resets == 0 {
		failures = append(failures, "pipeline target error/reset isolation not represented")
	}
	return gate("localpipeline_error_reset_isolation", len(failures) == 0, "required", fmt.Sprintf("%d errors, %d resets", errors, resets), nil, failures)
}

func LocalPipelineDescriptorRejectionGate(set localpipeline.PipelineFixtureSet) GateResult {
	failures := []string{}
	rejections := 0
	for _, run := range set.Runs {
		rejections += run.DescriptorRejections
	}
	if rejections == 0 {
		failures = append(failures, "unsafe descriptor rejection not represented")
	}
	return gate("localpipeline_descriptor_rejection", len(failures) == 0, "required", fmt.Sprintf("%d descriptor rejections", rejections), nil, failures)
}

func LocalPipelineTraceHygieneGate(set localpipeline.PipelineFixtureSet) GateResult {
	failures := []string{}
	if err := localpipeline.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	for _, unsafe := range []map[string]string{{"endpoint": "synthetic"}, {"raw_payload": "synthetic"}, {"secret": "synthetic"}, {"dns_query": "synthetic"}} {
		if err := localpipeline.ScanForLeak(unsafe); err == nil {
			failures = append(failures, "unsafe localpipeline metadata accepted")
		}
	}
	return gate("localpipeline_trace_hygiene", len(failures) == 0, "required", "local pipeline summaries contain safe metadata only", nil, failures)
}

func LocalPipelineCollapseResistanceGate(set localpipeline.PipelineFixtureSet) GateResult {
	failures := []string{}
	if set.Collapse.Conclusion != "passed" {
		failures = append(failures, set.Collapse.SuspiciousMetrics...)
	}
	return gate("localpipeline_collapse_resistance", len(failures) == 0, "required", fmt.Sprintf("diversity %.2f", set.Collapse.DiversityScore), nil, failures)
}

func LocalPipelineGeneratedBackendParityGate(set localpipeline.PipelineFixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" {
		failures = append(failures, set.Parity.UnexpectedDifferences...)
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"localpipeline_generated.go", "localpipeline_test.go", "localpipeline_parity_test.go", "localpipeline_hygiene_test.go", "LocalPipelineSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated localpipeline marker "+marker)
				}
			}
		}
	}
	return gate("localpipeline_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d scenarios compared", set.Parity.ComparedScenarios), nil, failures)
}

func LocalPipelineMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeLocalPipelineIngressMappingBroken,
		mutant.ModeLocalPipelineEgressMappingBroken,
		mutant.ModeLocalPipelineBridgeIntegrationBroken,
		mutant.ModeLocalPipelineIgnoresBackpressure,
		mutant.ModeLocalPipelineSwallowsReset,
		mutant.ModeLocalPipelineSwallowsTargetError,
		mutant.ModeLocalPipelineAcceptsUnsafeDescriptor,
		mutant.ModeLocalPipelinePayloadTraceLeak,
		mutant.ModeLocalPipelineSecretTraceLeak,
		mutant.ModeLocalPipelinePaddingOnlyDiversity,
		mutant.ModeLocalPipelineGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("localpipeline_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d localpipeline mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func LocalPipelineFixtureDriftGate(report localpipeline.PipelineComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("localpipeline_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func localPipelineComparison(path string, current localpipeline.PipelineFixtureSet) localpipeline.PipelineComparisonReport {
	oldSet, err := localpipeline.LoadFixtureSet(path)
	if err != nil {
		return localpipeline.PipelineComparisonReport{Version: localpipeline.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return localpipeline.CompareFixtureSets(oldSet, current)
}
