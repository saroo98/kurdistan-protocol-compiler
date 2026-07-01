// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

import (
	"encoding/json"
	"fmt"
)

func ValidateScenario(s HealthScenario) error {
	if s.ScenarioID == "" || s.RaceMode == "" || s.BundleMode == "" || !scenarioIDExists(s.ScenarioID) {
		return ErrInvalidHealth
	}
	return ScanForLeak(s)
}

func ValidateEvent(e HealthEvent) error {
	if e.EventID == "" || e.ActivePathID == "" || e.CandidateID == "" || e.Kind == "" || e.LogicalTick < 0 {
		return ErrInvalidHealth
	}
	if !knownEventKind(e.Kind) {
		return ErrInvalidHealth
	}
	return ScanForLeak(e)
}

func ValidateRun(run PathHealthRun) error {
	if err := ValidateScenario(run.Scenario); err != nil {
		return err
	}
	if run.ActivePath.ActivePathID == "" || len(run.Events) == 0 || run.Report.Version != string(Version) {
		return ErrInvalidHealth
	}
	if run.Policy.PolicyHash != HashValue(policyHashInput(run.Policy)) {
		return fmt.Errorf("%w: policy hash mismatch", ErrInvalidHealth)
	}
	if run.Report.ReportHash != HashValue(reportHashInput(run.Report)) {
		return fmt.Errorf("%w: report hash mismatch", ErrInvalidHealth)
	}
	if run.Scenario.Control {
		if run.Report.Conclusion != "control_failed" {
			return fmt.Errorf("%w: control scenario did not fail", ErrInvalidHealth)
		}
	} else if run.Report.Conclusion != run.Scenario.ExpectedConclusion {
		return fmt.Errorf("%w: scenario conclusion mismatch", ErrInvalidHealth)
	}
	if !run.Scenario.Control && run.Report.FinalState != run.Scenario.ExpectedFinalState {
		return fmt.Errorf("%w: final state mismatch", ErrInvalidHealth)
	}
	return ScanForLeak(run)
}

func ValidateFixtureSet(set PathHealthFixtureSet) error {
	if set.Version != string(Version) || len(set.Scenarios) == 0 || len(set.Runs) == 0 || set.PayloadLogged || set.SecretLogged {
		return ErrInvalidHealth
	}
	for _, run := range set.Runs {
		if err := ValidateRun(run); err != nil {
			return err
		}
	}
	if set.Controls.Conclusion != "failed" || len(set.Controls.MisuseFindings) == 0 {
		return fmt.Errorf("%w: controls not detected", ErrInvalidHealth)
	}
	if set.Parity.Conclusion != "passed" {
		return fmt.Errorf("%w: parity failed", ErrInvalidHealth)
	}
	if set.FixtureSetHash != "" && set.FixtureSetHash != HashValue(fixtureSetHashInput(set)) {
		return fmt.Errorf("%w: fixture hash mismatch", ErrInvalidHealth)
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
	var report PathHealthReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return err
	}
	if report.Version == string(Version) && report.ReportHash != "" && report.ReportHash != HashValue(reportHashInput(report)) {
		return fmt.Errorf("%w: report hash mismatch", ErrInvalidHealth)
	}
	return ScanForLeak(report)
}

func knownEventKind(kind HealthEventKind) bool {
	for _, candidate := range HealthEventKinds() {
		if candidate == string(kind) {
			return true
		}
	}
	return false
}

func HealthStates() []string {
	return []string{string(HealthUnknown), string(HealthHealthy), string(HealthDegraded), string(HealthStalled), string(HealthFailing), string(HealthFailed), string(HealthRecovering), string(HealthFailoverPending), string(HealthFailedOver), string(HealthQuarantined)}
}

func HealthEventKinds() []string {
	return []string{string(HealthEventActivated), string(HealthEventUsefulByteObserved), string(HealthEventNoProgress), string(HealthEventStallDetected), string(HealthEventResetLikeFailure), string(HealthEventBlackholeLikeFailure), string(HealthEventRelayBurnSignal), string(HealthEventScoreDecayed), string(HealthEventConfidenceExpired), string(HealthEventReconnectAttempt), string(HealthEventReconnectSucceeded), string(HealthEventReconnectFailed), string(HealthEventFailoverTriggered), string(HealthEventFailoverCompleted), string(HealthEventQuarantined)}
}

func FailoverOutcomes() []string {
	return []string{OutcomeNoFailoverNeeded, OutcomeFailoverNotPossible, OutcomeFailoverPending, OutcomeFailoverVerified, OutcomeFailoverFallback, OutcomeFailoverBlockedHighRisk, OutcomeFailoverBlockedExperiment, OutcomeFailoverQuarantined}
}
