// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import (
	"context"
)

type PathRaceFixtureSet struct {
	Version        string                  `json:"version"`
	Scenarios      []RaceScenario          `json:"scenarios"`
	Runs           []PathRaceRun           `json:"runs"`
	Events         []RaceEvent             `json:"events"`
	Outcomes       []RaceOutcome           `json:"outcomes"`
	ScoringPolicy  ShortLivedScoringPolicy `json:"scoring_policy"`
	Scores         []CandidateScore        `json:"scores"`
	RankingReport  CandidateRankingReport  `json:"ranking_report"`
	Reports        []PathRaceReport        `json:"reports"`
	MisuseReport   PathRaceMisuseReport    `json:"misuse_report"`
	Controls       PathRaceMisuseReport    `json:"controls"`
	Parity         PathRaceParityReport    `json:"parity"`
	PayloadLogged  bool                    `json:"payload_logged"`
	SecretLogged   bool                    `json:"secret_logged"`
	FixtureSetHash string                  `json:"fixture_set_hash"`
}

type PathRaceComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}

func GenerateFixtureSet(ctx context.Context) (PathRaceFixtureSet, error) {
	scenarios := DefaultScenarios()
	runs := make([]PathRaceRun, 0, len(scenarios))
	events := []RaceEvent{}
	outcomes := []RaceOutcome{}
	scores := []CandidateScore{}
	reports := []PathRaceReport{}
	for _, scenario := range scenarios {
		run, err := RunScenario(ctx, scenario)
		if err != nil {
			return PathRaceFixtureSet{}, err
		}
		runs = append(runs, run)
		events = append(events, run.Events...)
		outcomes = append(outcomes, run.Outcomes...)
		scores = append(scores, run.Scores...)
		reports = append(reports, run.Report)
	}
	set := PathRaceFixtureSet{
		Version:       string(Version),
		Scenarios:     scenarios,
		Runs:          runs,
		Events:        events,
		Outcomes:      outcomes,
		ScoringPolicy: DefaultScoringPolicy(),
		Scores:        scores,
		RankingReport: firstHealthyRanking(runs),
		Reports:       reports,
		MisuseReport:  ScanMisuse(runs),
		Controls:      ScanMisuse(controlRuns(runs)),
		Parity:        CompareGeneratedInterpreted(runs),
	}
	set.FixtureSetHash = HashValue(fixtureSetHashInput(set))
	return set, ValidateFixtureSet(set)
}

func BuildReport(scenario RaceScenario, bundleID string, candidates []RaceCandidate, outcomes []RaceOutcome, ranking CandidateRankingReport) PathRaceReport {
	report := PathRaceReport{
		Version:           string(Version),
		RaceID:            "race_" + scenario.ScenarioID + "_" + bundleID,
		RaceMode:          scenario.RaceMode,
		ScenarioID:        scenario.ScenarioID,
		BundleID:          bundleID,
		CandidateCount:    len(candidates),
		RankedCandidates:  append([]string(nil), ranking.RankedCandidates...),
		WinnerCandidateID: ranking.WinnerCandidateID,
		WinnerFamily:      ranking.WinnerFamily,
		WinnerDeclared:    ranking.WinnerCandidateID != "",
		SyntheticOnly:     true,
		Conclusion:        "passed",
	}
	if !report.WinnerDeclared {
		report.Conclusion = "no_winner"
	}
	if scenario.Control {
		report.Conclusion = "control_failed"
	}
	for _, outcome := range outcomes {
		if outcome.FinalState != RaceStatePending {
			report.StartedCandidates++
		}
		if outcome.VerifiedUsable {
			report.VerifiedCandidates++
		}
		switch outcome.FinalState {
		case RaceStateFailed:
			report.FailedCandidates++
		case RaceStateStalled:
			report.StalledCandidates++
		case RaceStateRejected:
			report.RejectedCandidates++
		case RaceStateGated:
			report.GatedCandidates++
		}
		report.PayloadLogged = report.PayloadLogged || outcome.PayloadLogged
		report.SecretLogged = report.SecretLogged || outcome.SecretLogged
	}
	report.ReportHash = HashValue(reportHashInput(report))
	return report
}

func reportHashInput(report PathRaceReport) PathRaceReport {
	report.ReportHash = ""
	return report
}

func fixtureSetHashInput(set PathRaceFixtureSet) PathRaceFixtureSet {
	set.FixtureSetHash = ""
	return set
}

func firstHealthyRanking(runs []PathRaceRun) CandidateRankingReport {
	for _, run := range runs {
		if !run.Scenario.Control && run.Report.WinnerDeclared {
			return run.Ranking
		}
	}
	return CandidateRankingReport{Conclusion: "no_winner"}
}

func controlRuns(runs []PathRaceRun) []PathRaceRun {
	out := []PathRaceRun{}
	for _, run := range runs {
		if run.Scenario.Control {
			out = append(out, run)
		}
	}
	return out
}

func CompareFixtureSets(oldSet, newSet PathRaceFixtureSet) PathRaceComparisonReport {
	report := PathRaceComparisonReport{Version: string(Version), OldHash: oldSet.FixtureSetHash, NewHash: newSet.FixtureSetHash, Conclusion: "passed"}
	if err := ValidateFixtureSet(oldSet); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if err := ValidateFixtureSet(newSet); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if oldSet.FixtureSetHash != newSet.FixtureSetHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_hash_changed")
	}
	if oldSet.PayloadLogged || newSet.PayloadLogged {
		report.PayloadLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "payload_logged")
	}
	if oldSet.SecretLogged || newSet.SecretLogged {
		report.SecretLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "secret_logged")
	}
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = "failed"
	}
	return report
}
