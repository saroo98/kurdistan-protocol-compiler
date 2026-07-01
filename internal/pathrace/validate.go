// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import (
	"encoding/json"
	"fmt"
)

func ValidateScenario(s RaceScenario) error {
	if s.ScenarioID == "" || s.RaceMode == "" || s.BundleMode == "" || s.CandidateCount <= 0 {
		return ErrInvalidRace
	}
	return ScanForLeak(s)
}

func ValidateSchedulerPolicy(p RaceSchedulerPolicy) error {
	if p.PolicyID == "" || p.MaxParallelCandidates <= 0 || p.DeterministicTieBreak == "" {
		return ErrInvalidRace
	}
	if p.PolicyHash != "" && p.PolicyHash != HashValue(policyHashInput(p)) {
		return fmt.Errorf("%w: scheduler policy hash mismatch", ErrInvalidRace)
	}
	return ScanForLeak(p)
}

func ValidateScoringPolicy(p ShortLivedScoringPolicy) error {
	if p.PolicyID == "" || p.SuccessTTLClass == "" || p.FailureTTLClass == "" {
		return ErrInvalidRace
	}
	if p.PolicyHash != "" && p.PolicyHash != HashValue(scoringPolicyHashInput(p)) {
		return fmt.Errorf("%w: scoring policy hash mismatch", ErrInvalidRace)
	}
	return ScanForLeak(p)
}

func ValidateRun(run PathRaceRun) error {
	if err := ValidateScenario(run.Scenario); err != nil {
		return err
	}
	if err := ValidateSchedulerPolicy(run.Policy); err != nil {
		return err
	}
	if err := ValidateScoringPolicy(run.Scoring); err != nil {
		return err
	}
	if len(run.Candidates) == 0 || len(run.Events) == 0 || len(run.Outcomes) != len(run.Candidates) || len(run.Scores) != len(run.Candidates) {
		return ErrInvalidRace
	}
	if run.Report.ReportHash != HashValue(reportHashInput(run.Report)) {
		return fmt.Errorf("%w: report hash mismatch", ErrInvalidRace)
	}
	if run.Scenario.Control {
		if run.Report.Conclusion != "control_failed" {
			return fmt.Errorf("%w: control scenario did not fail", ErrInvalidRace)
		}
	} else if run.Report.Conclusion != run.Scenario.ExpectedConclusion {
		return fmt.Errorf("%w: scenario conclusion mismatch", ErrInvalidRace)
	}
	return ScanForLeak(run)
}

func ValidateFixtureSet(set PathRaceFixtureSet) error {
	if set.Version != string(Version) || len(set.Scenarios) == 0 || len(set.Runs) == 0 || set.PayloadLogged || set.SecretLogged {
		return ErrInvalidRace
	}
	controlsDetected := false
	for _, run := range set.Runs {
		if err := ValidateRun(run); err != nil {
			return err
		}
		if run.Scenario.Control {
			controlsDetected = true
		}
	}
	if !controlsDetected || set.Controls.Conclusion != "failed" || len(set.Controls.MisuseFindings) == 0 {
		return fmt.Errorf("%w: controls not detected", ErrInvalidRace)
	}
	if set.MisuseReport.Conclusion != "failed" {
		return fmt.Errorf("%w: misuse controls missing", ErrInvalidRace)
	}
	if set.Parity.Conclusion != "passed" {
		return fmt.Errorf("%w: parity failed", ErrInvalidRace)
	}
	if set.FixtureSetHash != "" && set.FixtureSetHash != HashValue(fixtureSetHashInput(set)) {
		return fmt.Errorf("%w: fixture hash mismatch", ErrInvalidRace)
	}
	return ScanForLeak(set)
}

func ValidateJSON(raw []byte) error {
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	return ScanForLeak(decoded)
}

func ValidateReportJSON(raw []byte) error {
	var report PathRaceReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return err
	}
	if report.Version == string(Version) && report.ReportHash != "" && report.ReportHash != HashValue(reportHashInput(report)) {
		return fmt.Errorf("%w: report hash mismatch", ErrInvalidRace)
	}
	return ScanForLeak(report)
}
