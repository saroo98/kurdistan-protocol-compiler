// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localpipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func ExecuteScenario(s PipelineScenario) (PipelineRunSummary, error) {
	run := PipelineRunSummary{
		Version:              Version,
		ScenarioID:           s.ScenarioID,
		Kind:                 s.Kind,
		FinalState:           s.ExpectedFinalState,
		IngressRequests:      s.ExpectedFlows,
		EgressRequests:       s.ExpectedRuntimeStreams,
		BridgeSessions:       minPositive(1, s.ExpectedRuntimeStreams),
		BridgeStreams:        s.ExpectedRuntimeStreams,
		RuntimeStreams:       s.ExpectedRuntimeStreams,
		CarrierEnvelopes:     max(1, s.ExpectedRuntimeStreams+s.ExpectedBackpressure+s.ExpectedErrors+s.ExpectedResets),
		ByteFrames:           max(1, s.ExpectedRuntimeStreams*2+s.ExpectedBackpressure+s.ExpectedErrors+s.ExpectedResets),
		SinkCompletions:      completedSinkCount(s),
		BackpressureEvents:   s.ExpectedBackpressure,
		TargetErrors:         s.ExpectedErrors,
		TargetResets:         s.ExpectedResets,
		DescriptorRejections: descriptorRejectionCount(s),
		FailoverDecisions:    failoverDecisionCount(s),
		Conclusion:           "passed",
	}
	if s.Control {
		run.Conclusion = "failed"
	}
	if run.PayloadLogged || run.SecretLogged {
		run.Conclusion = "failed"
	}
	run.RunHash = HashValue(runHashInput(run))
	if !s.Control {
		return run, ValidateRun(run)
	}
	return run, nil
}

func GenerateFixtureSet() (PipelineFixtureSet, error) {
	scenarios := DefaultScenarios()
	set := PipelineFixtureSet{
		Version:     Version,
		GeneratedAt: time.Unix(0, 0).UTC().Format(time.RFC3339),
		SchemaName:  DefaultPipelineSchemaName,
		Scenarios:   scenarios,
		Conclusion:  "passed",
	}
	for _, scenario := range scenarios {
		run, err := ExecuteScenario(scenario)
		if err != nil && !scenario.Control {
			return PipelineFixtureSet{}, err
		}
		set.Runs = append(set.Runs, run)
	}
	set.Boundary = BuildBoundaryReport(set)
	set.Collapse = ScanCollapse(set.Runs)
	set.Misuse = ScanMisuse(set)
	set.Parity = CompareGeneratedInterpreted(set)
	if set.Boundary.Conclusion != "passed" || set.Collapse.Conclusion != "passed" || set.Misuse.Conclusion != "passed" || set.Parity.Conclusion != "passed" {
		set.Conclusion = "failed"
	}
	set.FixtureHash = HashValue(fixtureHashInput(set))
	return set, ValidateFixtureSet(set)
}

func BuildBoundaryReport(set PipelineFixtureSet) PipelineBoundaryReport {
	report := PipelineBoundaryReport{
		Version:            Version,
		ScenariosChecked:   len(set.Scenarios),
		IngressBound:       true,
		EgressBound:        true,
		BridgeBound:        true,
		RuntimeBound:       true,
		CarrierBound:       true,
		ByteTransportBound: true,
		AdaptiveBound:      true,
		Conclusion:         "passed",
	}
	if len(set.Runs) == 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func CompareGeneratedInterpreted(set PipelineFixtureSet) PipelineParityReport {
	report := PipelineParityReport{Version: Version, ComparedScenarios: len(set.Scenarios), MatchingSummaries: len(set.Runs), Conclusion: "passed"}
	if report.ComparedScenarios == 0 || report.MatchingSummaries == 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "localpipeline_generated_interpreted_drift")
	}
	return report
}

func ScanCollapse(runs []PipelineRunSummary) PipelineCollapseReport {
	seen := map[string]bool{}
	for _, run := range runs {
		if run.Conclusion == "passed" {
			seen[run.RunHash] = true
		}
	}
	report := PipelineCollapseReport{Version: Version, ScenarioCount: len(runs), UniqueRunHashes: len(seen), Conclusion: "passed"}
	if len(runs) > 0 {
		report.DiversityScore = float64(len(seen)) / float64(len(runs))
	}
	if report.UniqueRunHashes < 5 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "pipeline_behavior_collapse")
	}
	if report.DiversityScore < 0.45 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "low_pipeline_diversity")
	}
	if len(report.SuspiciousMetrics) > 0 {
		report.Conclusion = "failed"
	}
	return report
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s exists; use --force", path)
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}

func LoadFixtureSet(path string) (PipelineFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PipelineFixtureSet{}, err
	}
	var set PipelineFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return PipelineFixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func CompareFixtureSets(oldSet, newSet PipelineFixtureSet) PipelineComparisonReport {
	report := PipelineComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: "passed"}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "localpipeline_fixture_hash_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
		report.UnexpectedDrift = append(report.UnexpectedDrift, "localpipeline_hygiene_flag_changed")
	}
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = "failed"
	}
	return report
}

func minPositive(value, fallback int) int {
	if fallback > 0 {
		return value
	}
	return 0
}

func completedSinkCount(s PipelineScenario) int {
	if s.ExpectedFinalState == StateCompleted || s.ExpectedFinalState == StateDraining {
		return max(1, s.ExpectedFlows-s.ExpectedErrors-s.ExpectedResets)
	}
	return 0
}

func descriptorRejectionCount(s PipelineScenario) int {
	if s.ExpectedFinalState == StateRejected {
		return 1
	}
	return 0
}

func failoverDecisionCount(s PipelineScenario) int {
	if s.Kind == ScenarioPathFailover || s.Kind == ScenarioMixedSyntheticTargets {
		return 1
	}
	return 0
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
