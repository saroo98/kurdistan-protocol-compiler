// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

import (
	"context"
)

type PathHealthFixtureSet struct {
	Version        string                  `json:"version"`
	Scenarios      []HealthScenario        `json:"scenarios"`
	Runs           []PathHealthRun         `json:"runs"`
	ActivePaths    []ActivePath            `json:"active_paths"`
	Events         []HealthEvent           `json:"events"`
	Transitions    []HealthTransitionEvent `json:"transitions"`
	Degradation    []DegradationReport     `json:"degradation_reports"`
	Scores         []ActivePathScoreReport `json:"active_score_reports"`
	Policy         FailoverPolicy          `json:"failover_policy"`
	Decisions      []FailoverDecision      `json:"failover_decisions"`
	Reports        []PathHealthReport      `json:"reports"`
	MisuseReport   PathHealthMisuseReport  `json:"misuse_report"`
	Controls       PathHealthMisuseReport  `json:"controls"`
	Parity         PathHealthParityReport  `json:"parity"`
	PayloadLogged  bool                    `json:"payload_logged"`
	SecretLogged   bool                    `json:"secret_logged"`
	FixtureSetHash string                  `json:"fixture_set_hash"`
}

type PathHealthComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}

func GenerateFixtureSet(ctx context.Context) (PathHealthFixtureSet, error) {
	scenarios := DefaultScenarios()
	runs := make([]PathHealthRun, 0, len(scenarios))
	activePaths := []ActivePath{}
	events := []HealthEvent{}
	transitions := []HealthTransitionEvent{}
	degradation := []DegradationReport{}
	scores := []ActivePathScoreReport{}
	decisions := []FailoverDecision{}
	reports := []PathHealthReport{}
	for _, scenario := range scenarios {
		run, err := RunScenario(ctx, scenario)
		if err != nil {
			return PathHealthFixtureSet{}, err
		}
		runs = append(runs, run)
		activePaths = append(activePaths, run.ActivePath)
		events = append(events, run.Events...)
		transitions = append(transitions, run.Transitions...)
		degradation = append(degradation, run.Degradation)
		scores = append(scores, run.Score)
		decisions = append(decisions, run.Failover)
		reports = append(reports, run.Report)
	}
	set := PathHealthFixtureSet{
		Version:      string(Version),
		Scenarios:    scenarios,
		Runs:         runs,
		ActivePaths:  activePaths,
		Events:       events,
		Transitions:  transitions,
		Degradation:  degradation,
		Scores:       scores,
		Policy:       DefaultPolicy(),
		Decisions:    decisions,
		Reports:      reports,
		MisuseReport: ScanMisuse(runs),
		Controls:     ScanMisuse(controlRuns(runs)),
		Parity:       CompareGeneratedInterpreted(runs),
	}
	set.FixtureSetHash = HashValue(fixtureSetHashInput(set))
	return set, ValidateFixtureSet(set)
}

func BuildReport(active ActivePath, events []HealthEvent, degradation DegradationReport, failover FailoverDecision) PathHealthReport {
	report := PathHealthReport{
		Version:               string(Version),
		ActivePathID:          active.ActivePathID,
		CandidateID:           active.CandidateID,
		InitialState:          string(HealthHealthy),
		FinalState:            string(active.CurrentHealthState),
		EventCount:            len(events),
		BlackholeLikeFailures: degradation.BlackholeLikeFailures,
		ResetLikeFailures:     degradation.ResetLikeFailures,
		StallEvents:           degradation.StallEvents,
		RelayBurnSignals:      boolCount(degradation.RelayBurnDetected),
		ReconnectAttempts:     reconnectAttempts(events),
		FailoverTriggered:     failover.Outcome != OutcomeNoFailoverNeeded,
		FailoverCompleted:     failover.NewCandidateID != "",
		NewCandidateID:        failover.NewCandidateID,
		Conclusion:            "passed",
	}
	for _, event := range events {
		if event.Kind == HealthEventUsefulByteObserved {
			report.UsefulEvents++
		}
		report.PayloadLogged = report.PayloadLogged || event.PayloadLogged
		report.SecretLogged = report.SecretLogged || event.SecretLogged
	}
	if report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	report.ReportHash = HashValue(reportHashInput(report))
	return report
}

func CompareFixtureSets(oldSet, newSet PathHealthFixtureSet) PathHealthComparisonReport {
	report := PathHealthComparisonReport{Version: string(Version), OldHash: oldSet.FixtureSetHash, NewHash: newSet.FixtureSetHash, Conclusion: "passed"}
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

func reportHashInput(report PathHealthReport) PathHealthReport {
	report.ReportHash = ""
	return report
}

func fixtureSetHashInput(set PathHealthFixtureSet) PathHealthFixtureSet {
	set.FixtureSetHash = ""
	return set
}

func boolCount(v bool) int {
	if v {
		return 1
	}
	return 0
}

func reconnectAttempts(events []HealthEvent) int {
	out := 0
	for _, event := range events {
		if event.Kind == HealthEventReconnectAttempt {
			out++
		}
	}
	return out
}
