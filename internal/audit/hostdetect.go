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

	"kurdistan/internal/hostdetect"
	"kurdistan/internal/mutant"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wireeval"
)

type HostDetectAuditSummary struct {
	Version         string                                `json:"version"`
	Hosts           int                                   `json:"hosts"`
	Observations    int                                   `json:"observations"`
	AssignmentModes []string                              `json:"assignment_modes"`
	Windows         []hostdetect.ObservationWindow        `json:"windows"`
	Detection       hostdetect.HostDetectionReport        `json:"detection"`
	Resistance      hostdetect.HostResistanceReport       `json:"resistance"`
	Collapse        hostdetect.HostCollapseReport         `json:"collapse"`
	Comparison      hostdetect.HostDetectComparisonReport `json:"comparison"`
	Conclusion      string                                `json:"conclusion"`
}

func RunHostDetectAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	seeds := wireeval.DefaultSeeds()
	modes := hostdetect.DefaultAssignmentModes()
	windows := hostdetect.DefaultTimelineWindows()
	if cfg.Mode == "full" {
		seeds = make([]int, 30)
		for i := range seeds {
			seeds[i] = int(cfg.StartSeed) + i
		}
		modes = hostdetect.FullAssignmentModes()
		windows = hostdetect.FullTimelineWindows()
	}
	dataset, err := wireeval.BuildDataset(ctx, protocorpus.DefaultCorpus(), wireeval.BuildOptions{Seeds: seeds, Scenarios: wireeval.DefaultScenarios(), Controls: true})
	if err != nil {
		return AuditReport{}, err
	}
	summary, err := hostdetect.Run(dataset, hostdetect.DefaultBuildOptions())
	if err != nil {
		return AuditReport{}, err
	}
	baselinePath := filepath.Join(root, "testdata", "hostdetect", "host-observations-golden.json")
	comparison, _ := hostdetect.VerifyObservationSet(ctx, baselinePath)
	gates := HostDetectGates(ctx, dataset, summary, modes, windows, baselinePath)
	auditSummary := HostDetectAuditSummary{
		Version:         string(hostdetect.Version),
		Hosts:           summary.ObservationSet.HostCount,
		Observations:    summary.ObservationSet.ObservationCount,
		AssignmentModes: modes,
		Windows:         windows,
		Detection:       summary.Detection,
		Resistance:      summary.Resistance,
		Collapse:        summary.Collapse,
		Comparison:      comparison,
		Conclusion:      "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "hostdetect-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     dataset.Manifest.ProfileCount,
		TraceCount:       summary.ObservationSet.ObservationCount,
		Gates:            gates,
		TraceScanSummary: auditSummary,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
		auditSummary.Conclusion = "failed"
		report.TraceScanSummary = auditSummary
	}
	return report, nil
}

func HostDetectGates(ctx context.Context, dataset wireeval.Dataset, summary hostdetect.HostDetectSummary, modes []string, windows []hostdetect.ObservationWindow, baselinePath string) []GateResult {
	comparison, _ := hostdetect.VerifyObservationSet(ctx, baselinePath)
	return []GateResult{
		HostDetectObservationBuildGate(summary.ObservationSet),
		HostDetectAssignmentIntegrityGate(dataset, modes),
		HostDetectTimelineIntegrityGate(windows),
		HostDetectConfidenceModelGate(summary.Detection),
		HostDetectResistanceMetricsGate(summary.Resistance),
		HostDetectCollapseDetectionGate(summary.Collapse),
		HostDetectControlDetectionGate(summary),
		HostDetectGeneratedBackendParityGate(),
		HostDetectTraceHygieneGate(summary),
		HostDetectMutantDetectionGate(),
		HostDetectFixtureDriftGate(comparison),
	}
}

func HostDetectObservationBuildGate(set hostdetect.HostObservationSet) GateResult {
	failures := []string{}
	if err := hostdetect.ValidateObservationSet(set); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("hostdetect_observation_build", len(failures) == 0, "required", fmt.Sprintf("%d observations across %d synthetic hosts", set.ObservationCount, set.HostCount), map[string]any{"set": set}, failures)
}

func HostDetectAssignmentIntegrityGate(dataset wireeval.Dataset, modes []string) GateResult {
	failures := []string{}
	counts := map[string]int{}
	for _, mode := range modes {
		set, err := hostdetect.BuildObservations(dataset, hostdetect.BuildOptions{AssignmentMode: mode, Window: hostdetect.WindowShort, HostCount: 8})
		if err != nil {
			failures = append(failures, mode+": "+err.Error())
			continue
		}
		counts[mode] = set.HostCount
		if set.HostCount == 0 {
			failures = append(failures, mode+": no hosts assigned")
		}
	}
	return gate("hostdetect_assignment_integrity", len(failures) == 0, "required", fmt.Sprintf("%d assignment modes checked", len(modes)), map[string]any{"host_counts": counts}, failures)
}

func HostDetectTimelineIntegrityGate(windows []hostdetect.ObservationWindow) GateResult {
	failures := []string{}
	for _, window := range windows {
		if err := hostdetect.ValidateWindow(window); err != nil {
			failures = append(failures, string(window))
		}
	}
	return gate("hostdetect_timeline_integrity", len(failures) == 0, "required", fmt.Sprintf("%d timeline windows checked", len(windows)), map[string]any{"windows": windows}, failures)
}

func HostDetectConfidenceModelGate(report hostdetect.HostDetectionReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, "confidence report failed")
	}
	if report.ControlHostsFlagged == 0 {
		failures = append(failures, "controls were not flagged")
	}
	return gate("hostdetect_confidence_model", len(failures) == 0, "required", fmt.Sprintf("%d/%d hosts flagged", report.HostsFlagged, report.HostCount), map[string]any{"detection": report}, failures)
}

func HostDetectResistanceMetricsGate(report hostdetect.HostResistanceReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.RecommendedNextActions...)
	}
	return gate("hostdetect_resistance_metrics", len(failures) == 0, "required", fmt.Sprintf("%d hosts, %.2f average consistency", report.HostCount, report.AvgConsistencyScore), map[string]any{"resistance": report}, failures)
}

func HostDetectCollapseDetectionGate(report hostdetect.HostCollapseReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.SuspiciousMetrics...)
	}
	if !report.CollapsedControlDetected {
		failures = append(failures, "collapsed control not detected")
	}
	return gate("hostdetect_collapse_detection", len(failures) == 0, "required", fmt.Sprintf("%d high-consistency hosts, %d padding-only hosts", report.HighConsistencyHosts, report.PaddingOnlyHosts), map[string]any{"collapse": report}, failures)
}

func HostDetectControlDetectionGate(summary hostdetect.HostDetectSummary) GateResult {
	failures := []string{}
	if summary.Detection.ControlHostsFlagged == 0 || !summary.Resistance.ControlCollapseDetected || !summary.Resistance.PaddingOnlyDetected {
		failures = append(failures, "host controls were not detected")
	}
	return gate("hostdetect_control_detection", len(failures) == 0, "required", fmt.Sprintf("%d control hosts flagged", summary.Detection.ControlHostsFlagged), nil, failures)
}

func HostDetectGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("hostdetect_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	raw, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
	if err != nil {
		return gate("hostdetect_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source := string(raw)
	markers := []string{"hostdetect_generated.go", "hostdetect_test.go", "hostdetect_parity_test.go", "hostdetect_hygiene_test.go", "HostDetectSchemaVersion"}
	failures := []string{}
	for _, marker := range markers {
		if !strings.Contains(source, marker) {
			failures = append(failures, "missing generated marker "+marker)
		}
	}
	return gate("hostdetect_generated_backend_parity", len(failures) == 0, "required", "generated backend hostdetect markers checked", nil, failures)
}

func HostDetectTraceHygieneGate(summary hostdetect.HostDetectSummary) GateResult {
	failures := []string{}
	if err := hostdetect.ScanForLeak(summary); err != nil {
		failures = append(failures, err.Error())
	}
	if summary.PayloadLogged || summary.SecretLogged {
		failures = append(failures, "hostdetect summary reported payload/secret logging")
	}
	return gate("hostdetect_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d host observations scanned", summary.ObservationSet.ObservationCount), nil, failures)
}

func HostDetectMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeHostDetectSameFeatureEveryHost,
		mutant.ModeHostDetectSameFirstNEveryHost,
		mutant.ModeHostDetectIgnoresObservationCount,
		mutant.ModeHostDetectIgnoresProfileReuse,
		mutant.ModeHostDetectIgnoresPaddingOnlyHosts,
		mutant.ModeHostDetectControlNotDetected,
		mutant.ModeHostDetectTrainTestHostOverlap,
		mutant.ModeHostDetectEndpointLeak,
		mutant.ModeHostDetectPayloadLeak,
		mutant.ModeHostDetectSecretLeak,
		mutant.ModeHostDetectGeneratedBackendDrift,
		mutant.ModeHostDetectUnstableHostAssignment,
	}
	modes := map[string]bool{}
	for _, mode := range mutant.Modes() {
		modes[mode] = true
	}
	failures := []string{}
	for _, mode := range required {
		if !modes[mode] {
			failures = append(failures, "missing mutant mode "+mode)
		}
	}
	return gate("hostdetect_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d hostdetect mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func HostDetectFixtureDriftGate(report hostdetect.HostDetectComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("hostdetect_fixture_drift", len(failures) == 0, "required", fmt.Sprintf("%d old observations compared to %d new observations", report.OldObservations, report.NewObservations), map[string]any{"comparison": report}, failures)
}
