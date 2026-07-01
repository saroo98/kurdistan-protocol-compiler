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
	"kurdistan/internal/pathrace"
)

type PathRaceAuditSummary struct {
	Version            string                            `json:"version"`
	ScenarioCount      int                               `json:"scenario_count"`
	CandidateCount     int                               `json:"candidate_count"`
	RaceModes          map[string]int                    `json:"race_modes"`
	StartedCandidates  int                               `json:"started_candidates"`
	VerifiedCandidates int                               `json:"verified_candidates"`
	FailedCandidates   int                               `json:"failed_candidates"`
	StalledCandidates  int                               `json:"stalled_candidates"`
	RejectedCandidates int                               `json:"rejected_candidates"`
	GatedCandidates    int                               `json:"gated_candidates"`
	WinnersDeclared    int                               `json:"winners_declared"`
	MisuseFindings     []string                          `json:"misuse_findings,omitempty"`
	FixtureComparison  pathrace.PathRaceComparisonReport `json:"fixture_comparison"`
	GeneratedParity    string                            `json:"generated_parity"`
	Conclusion         string                            `json:"conclusion"`
}

func RunPathRaceAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := pathrace.GenerateFixtureSet(ctx)
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := pathRaceFixtureComparison(filepath.Join(root, "testdata", "pathrace", "pathrace-report-golden.json"), set)
	gates := PathRaceGates(set, comparison)
	summary := PathRaceAuditSummary{
		Version:           string(pathrace.Version),
		ScenarioCount:     len(set.Scenarios),
		CandidateCount:    set.MisuseReport.CandidateCount,
		RaceModes:         raceModeCounts(set.Scenarios),
		MisuseFindings:    set.Controls.MisuseFindings,
		FixtureComparison: comparison,
		GeneratedParity:   set.Parity.Conclusion,
		Conclusion:        "passed",
	}
	for _, report := range set.Reports {
		summary.StartedCandidates += report.StartedCandidates
		summary.VerifiedCandidates += report.VerifiedCandidates
		summary.FailedCandidates += report.FailedCandidates
		summary.StalledCandidates += report.StalledCandidates
		summary.RejectedCandidates += report.RejectedCandidates
		summary.GatedCandidates += report.GatedCandidates
		if report.WinnerDeclared {
			summary.WinnersDeclared++
		}
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "pathrace-" + cfg.Mode,
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

func PathRaceGates(set pathrace.PathRaceFixtureSet, comparison pathrace.PathRaceComparisonReport) []GateResult {
	return []GateResult{
		PathRaceScenarioValidationGate(set),
		PathRaceParallelSchedulerGate(set),
		PathRaceCandidateVerificationGate(set),
		PathRaceShortLivedScoringGate(set),
		PathRaceRankingTieBreakGate(set),
		PathRaceMisuseDetectionGate(set),
		PathRaceGeneratedBackendParityGate(set),
		PathRaceTraceHygieneGate(set),
		PathRaceMutantDetectionGate(set),
		PathRaceFixtureDriftGate(comparison),
	}
}

func PathRaceScenarioValidationGate(set pathrace.PathRaceFixtureSet) GateResult {
	failures := []string{}
	if err := pathrace.ValidateFixtureSet(set); err != nil {
		failures = append(failures, err.Error())
	}
	if len(set.Scenarios) < len(pathrace.DefaultScenarios()) {
		failures = append(failures, "missing pathrace scenarios")
	}
	return gate("pathrace_scenario_validation", len(failures) == 0, "required", fmt.Sprintf("%d scenarios checked", len(set.Scenarios)), nil, failures)
}

func PathRaceParallelSchedulerGate(set pathrace.PathRaceFixtureSet) GateResult {
	failures := []string{}
	for _, run := range set.Runs {
		if run.Policy.MaxParallelCandidates < 2 && !run.Scenario.Control {
			failures = append(failures, "non-parallel scheduler for "+run.Scenario.ScenarioID)
		}
		if run.Policy.DeterministicTieBreak == "" {
			failures = append(failures, "missing deterministic tie break")
		}
	}
	return gate("pathrace_parallel_scheduler", len(failures) == 0, "required", fmt.Sprintf("%d race runs scheduled", len(set.Runs)), nil, failures)
}

func PathRaceCandidateVerificationGate(set pathrace.PathRaceFixtureSet) GateResult {
	failures := []string{}
	verified := 0
	for _, outcome := range set.Outcomes {
		if outcome.VerifiedUsable {
			verified++
		}
		if outcome.FailureBucket != "none" && outcome.VerifiedUsable {
			failures = append(failures, "failed candidate verified: "+outcome.CandidateID)
		}
	}
	if verified == 0 {
		failures = append(failures, "no verified candidates")
	}
	return gate("pathrace_candidate_verification", len(failures) == 0, "required", fmt.Sprintf("%d verified candidate outcomes", verified), nil, failures)
}

func PathRaceShortLivedScoringGate(set pathrace.PathRaceFixtureSet) GateResult {
	failures := []string{}
	freshHigh := false
	staleLow := false
	for _, score := range set.Scores {
		if score.FreshnessClass == "fresh" && (score.ScoreBucket == "score_high" || score.ScoreBucket == "score_medium") {
			freshHigh = true
		}
		if score.FreshnessClass == "stale" && score.ScoreBucket != "score_high" {
			staleLow = true
		}
		if score.ScoreHash == "" {
			failures = append(failures, "missing score hash")
		}
	}
	if !freshHigh {
		failures = append(failures, "fresh success did not improve score")
	}
	if !staleLow {
		failures = append(failures, "stale success decay not represented")
	}
	return gate("pathrace_short_lived_scoring", len(failures) == 0, "required", fmt.Sprintf("%d score buckets checked", len(set.Scores)), nil, failures)
}

func PathRaceRankingTieBreakGate(set pathrace.PathRaceFixtureSet) GateResult {
	failures := []string{}
	if len(set.RankingReport.RankedCandidates) == 0 || set.RankingReport.WinnerCandidateID == "" {
		failures = append(failures, "missing healthy ranking winner")
	}
	if set.RankingReport.WinnerSyntheticOnly != true {
		failures = append(failures, "winner not marked synthetic-only")
	}
	return gate("pathrace_ranking_tiebreak", len(failures) == 0, "required", fmt.Sprintf("%d ranked candidates", len(set.RankingReport.RankedCandidates)), nil, failures)
}

func PathRaceMisuseDetectionGate(set pathrace.PathRaceFixtureSet) GateResult {
	failures := []string{}
	required := []string{"always_picks_first_candidate", "stale_success_beats_fresh_success", "high_risk_candidate_wins_by_default"}
	for _, finding := range required {
		if !containsPathRaceString(set.Controls.MisuseFindings, finding) {
			failures = append(failures, "missing misuse finding "+finding)
		}
	}
	return gate("pathrace_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d control findings", len(set.Controls.MisuseFindings)), map[string]any{"controls": set.Controls}, failures)
}

func PathRaceGeneratedBackendParityGate(set pathrace.PathRaceFixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" {
		failures = append(failures, set.Parity.UnexpectedDifferences...)
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"pathrace_generated.go", "pathrace_test.go", "pathrace_parity_test.go", "pathrace_hygiene_test.go", "PathRaceSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated pathrace marker "+marker)
				}
			}
		}
	}
	return gate("pathrace_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d scenarios compared", set.Parity.ComparedScenarios), nil, failures)
}

func PathRaceTraceHygieneGate(set pathrace.PathRaceFixtureSet) GateResult {
	failures := []string{}
	if err := pathrace.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	for _, tc := range []map[string]string{
		{"endpoint": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"dns_query": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
	} {
		if err := pathrace.ScanForLeak(tc); err == nil {
			failures = append(failures, "unsafe pathrace metadata accepted")
		}
	}
	return gate("pathrace_trace_hygiene", len(failures) == 0, "required", "pathrace fixtures contain safe metadata only", nil, failures)
}

func PathRaceMutantDetectionGate(set pathrace.PathRaceFixtureSet) GateResult {
	required := []string{
		mutant.ModePathRaceAlwaysFirstCandidate,
		mutant.ModePathRaceSerialOnly,
		mutant.ModePathRaceStaleSuccessWins,
		mutant.ModePathRaceIgnoresRecentFailure,
		mutant.ModePathRaceIgnoresStall,
		mutant.ModePathRaceIgnoresRelayBurn,
		mutant.ModePathRaceHighRiskWins,
		mutant.ModePathRaceExperimentalWins,
		mutant.ModePathRaceBurnedRelayWins,
		mutant.ModePathRaceBlockedCandidateVerified,
		mutant.ModePathRaceAllScoresIdentical,
		mutant.ModePathRaceUnstableTieBreak,
		mutant.ModePathRaceEndpointLeak,
		mutant.ModePathRacePayloadLeak,
		mutant.ModePathRaceSecretLeak,
		mutant.ModePathRaceGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	if set.Controls.Conclusion != "failed" {
		failures = append(failures, "pathrace controls not detected")
	}
	if err := pathrace.ScanForLeak(map[string]string{"endpoint": "synthetic"}); err == nil {
		failures = append(failures, "endpoint leak mutant not detected")
	}
	return gate("pathrace_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d mutants represented", len(required)-len(failures)), nil, failures)
}

func PathRaceFixtureDriftGate(report pathrace.PathRaceComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("pathrace_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func pathRaceFixtureComparison(path string, current pathrace.PathRaceFixtureSet) pathrace.PathRaceComparisonReport {
	oldSet, err := pathrace.LoadFixtureSet(path)
	if err != nil {
		return pathrace.PathRaceComparisonReport{Version: string(pathrace.Version), NewHash: current.FixtureSetHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return pathrace.CompareFixtureSets(oldSet, current)
}

func raceModeCounts(scenarios []pathrace.RaceScenario) map[string]int {
	out := map[string]int{}
	for _, scenario := range scenarios {
		out[string(scenario.RaceMode)]++
	}
	return out
}

func containsPathRaceString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
