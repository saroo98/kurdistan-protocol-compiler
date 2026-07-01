// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

import (
	"context"
	"fmt"

	"kurdistan/internal/pathrace"
	"kurdistan/internal/transportbundle"
)

type HealthScenario struct {
	ScenarioID              string                     `json:"scenario_id"`
	BundleMode              transportbundle.BundleMode `json:"bundle_mode"`
	RaceMode                pathrace.RaceMode          `json:"race_mode"`
	RaceScenarioID          string                     `json:"race_scenario_id"`
	ActiveCandidateClass    string                     `json:"active_candidate_class"`
	ExpectedFinalState      string                     `json:"expected_final_state"`
	ExpectedFailover        bool                       `json:"expected_failover"`
	ExpectedFailoverOutcome string                     `json:"expected_failover_outcome"`
	ExpectedConclusion      string                     `json:"expected_conclusion"`
	Control                 bool                       `json:"control"`
	PayloadLogged           bool                       `json:"payload_logged"`
	SecretLogged            bool                       `json:"secret_logged"`
}

func DefaultScenarios() []HealthScenario {
	return []HealthScenario{
		{"stable_active_path", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeVerifiedUsable, "https_like_fast_success", "https_like_tcp", string(HealthHealthy), false, OutcomeNoFailoverNeeded, "passed", false, false, false},
		{"brief_no_progress_recovers", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeVerifiedUsable, "https_like_fast_success", "https_like_tcp", string(HealthHealthy), false, OutcomeNoFailoverNeeded, "passed", false, false, false},
		{"stall_after_handshake_failover", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeVerifiedUsable, "https_like_fast_success", "https_like_tcp", string(HealthFailedOver), true, OutcomeFailoverFallback, "passed", false, false, false},
		{"stall_after_data_failover", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeVerifiedUsable, "https_like_fast_success", "https_like_tcp", string(HealthFailedOver), true, OutcomeFailoverFallback, "passed", false, false, false},
		{"reset_burst_failover", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeVerifiedUsable, "https_like_fast_success", "https_like_tcp", string(HealthFailedOver), true, OutcomeFailoverFallback, "passed", false, false, false},
		{"blackhole_after_success_failover", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeVerifiedUsable, "https_like_fast_success", "https_like_tcp", string(HealthFailedOver), true, OutcomeFailoverFallback, "passed", false, false, false},
		{"relay_burn_immediate_quarantine", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeVerifiedUsable, "relay_burn_rejects_candidate", "https_like_tcp", string(HealthQuarantined), true, OutcomeFailoverQuarantined, "passed", false, false, false},
		{"confidence_expiry_degrades", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeVerifiedUsable, "https_like_fast_success", "https_like_tcp", string(HealthDegraded), false, OutcomeNoFailoverNeeded, "passed", false, false, false},
		{"reconnect_loop_failover", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeVerifiedUsable, "https_like_fast_success", "https_like_tcp", string(HealthFailedOver), true, OutcomeFailoverFallback, "passed", false, false, false},
		{"flapping_path_penalized", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeVerifiedUsable, "https_like_fast_success", "https_like_tcp", string(HealthDegraded), false, OutcomeNoFailoverNeeded, "passed", false, false, false},
		{"all_alternates_fail", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeVerifiedUsable, "https_like_fast_success", "https_like_tcp", string(HealthFailed), true, OutcomeFailoverNotPossible, "passed", false, false, false},
		{"high_risk_alternate_blocked", transportbundle.BundleModeHighRiskReview, pathrace.RaceModeConservative, "high_risk_candidate_gated", "https_like_tcp", string(HealthFailed), true, OutcomeFailoverBlockedHighRisk, "passed", false, false, false},
		{"experimental_alternate_blocked", transportbundle.BundleModeExperimentalMix, pathrace.RaceModeExperimentalGated, "experimental_candidate_gated", "https_like_tcp", string(HealthFailed), true, OutcomeFailoverBlockedExperiment, "passed", false, false, false},
		{"control_no_health_monitoring", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeControlCollapsed, "control_first_candidate_always_wins", "collapsed_control", string(HealthHealthy), false, OutcomeNoFailoverNeeded, "control_failed", true, false, false},
		{"control_over_eager_failover", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeControlCollapsed, "control_first_candidate_always_wins", "collapsed_control", string(HealthFailedOver), true, OutcomeFailoverVerified, "control_failed", true, false, false},
		{"control_under_eager_failover", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeControlCollapsed, "control_first_candidate_always_wins", "collapsed_control", string(HealthHealthy), false, OutcomeNoFailoverNeeded, "control_failed", true, false, false},
		{"control_failover_to_burned_relay", transportbundle.BundleModeBalancedAdaptive, pathrace.RaceModeControlCollapsed, "control_first_candidate_always_wins", "collapsed_control", string(HealthFailedOver), true, OutcomeFailoverVerified, "control_failed", true, false, false},
	}
}

func QuickScenarios() []HealthScenario {
	all := DefaultScenarios()
	return []HealthScenario{all[0], all[2], all[6], all[13]}
}

func RunScenario(ctx context.Context, scenario HealthScenario) (PathHealthRun, error) {
	raceScenario := raceScenarioFor(scenario)
	raceRun, err := pathrace.RunScenario(ctx, raceScenario)
	if err != nil {
		return PathHealthRun{}, err
	}
	active, err := CreateActivePathFromRace(raceRun)
	if err != nil {
		return PathHealthRun{}, err
	}
	events := timelineForScenario(scenario, active)
	monitored, err := MonitorActivePath(active, candidatesForScenario(scenario, raceRun.Candidates, active.CandidateID), events, DefaultPolicy())
	if err != nil {
		return PathHealthRun{}, err
	}
	monitored.Scenario = scenario
	if scenario.Control {
		applyControlScenario(&monitored)
	}
	monitored.Report.ReportHash = HashValue(reportHashInput(monitored.Report))
	monitored.PayloadLogged = monitored.Report.PayloadLogged
	monitored.SecretLogged = monitored.Report.SecretLogged
	return monitored, ValidateRun(monitored)
}

func raceScenarioFor(s HealthScenario) pathrace.RaceScenario {
	for _, scenario := range pathrace.DefaultScenarios() {
		if scenario.ScenarioID == s.RaceScenarioID {
			scenario.RaceMode = s.RaceMode
			scenario.BundleMode = s.BundleMode
			scenario.CandidateCount = 0
			return scenario
		}
	}
	return pathrace.DefaultScenarios()[1]
}

func timelineForScenario(s HealthScenario, active ActivePath) []HealthEvent {
	a := active.ActivePathID
	c := active.CandidateID
	switch s.ScenarioID {
	case "stable_active_path":
		return []HealthEvent{healthEvent(a, c, HealthEventActivated, 0, "activated", "", "", "", active.InitialScoreBucket, ""), healthEvent(a, c, HealthEventUsefulByteObserved, 1, "useful_recent", "", "", "", "score_high", "")}
	case "brief_no_progress_recovers":
		return []HealthEvent{healthEvent(a, c, HealthEventActivated, 0, "activated", "", "", "", active.InitialScoreBucket, ""), healthEvent(a, c, HealthEventNoProgress, 1, "none", "brief", "", "", "score_medium", ""), healthEvent(a, c, HealthEventUsefulByteObserved, 2, "useful_recent", "", "", "", "score_medium", "")}
	case "stall_after_handshake_failover":
		return []HealthEvent{healthEvent(a, c, HealthEventActivated, 0, "activated", "", "", "", active.InitialScoreBucket, ""), healthEvent(a, c, HealthEventStallDetected, 2, "none", "stall_after_handshake", "stall", "", "score_low", ""), healthEvent(a, c, HealthEventStallDetected, 3, "none", "stall_after_handshake", "stall", "", "score_zero", "")}
	case "stall_after_data_failover":
		return []HealthEvent{healthEvent(a, c, HealthEventUsefulByteObserved, 1, "useful_recent", "", "", "", "score_high", ""), healthEvent(a, c, HealthEventStallDetected, 3, "none", "stall_after_data", "stall", "", "score_low", ""), healthEvent(a, c, HealthEventStallDetected, 4, "none", "stall_after_data", "stall", "", "score_zero", "")}
	case "reset_burst_failover":
		return []HealthEvent{healthEvent(a, c, HealthEventResetLikeFailure, 1, "none", "", "reset_like", "", "score_low", ""), healthEvent(a, c, HealthEventResetLikeFailure, 2, "none", "", "reset_like", "", "score_zero", "")}
	case "blackhole_after_success_failover":
		return []HealthEvent{healthEvent(a, c, HealthEventUsefulByteObserved, 1, "useful_recent", "", "", "", "score_high", ""), healthEvent(a, c, HealthEventBlackholeLikeFailure, 3, "none", "", "blackhole_like", "", "score_zero", "")}
	case "relay_burn_immediate_quarantine":
		return []HealthEvent{healthEvent(a, c, HealthEventRelayBurnSignal, 1, "none", "", "relay_burn", "", "score_zero", "")}
	case "confidence_expiry_degrades":
		return []HealthEvent{healthEvent(a, c, HealthEventConfidenceExpired, 5, "none", "", "", "", "score_low", "ttl_expired")}
	case "reconnect_loop_failover":
		return []HealthEvent{healthEvent(a, c, HealthEventReconnectAttempt, 1, "none", "", "", "attempt", "score_low", ""), healthEvent(a, c, HealthEventReconnectFailed, 2, "none", "", "reconnect_failed", "failed", "score_low", ""), healthEvent(a, c, HealthEventReconnectFailed, 3, "none", "", "reconnect_failed", "failed", "score_zero", "")}
	case "flapping_path_penalized":
		return []HealthEvent{healthEvent(a, c, HealthEventNoProgress, 1, "none", "brief", "", "", "score_medium", ""), healthEvent(a, c, HealthEventUsefulByteObserved, 2, "useful_sparse", "", "", "", "score_medium", ""), healthEvent(a, c, HealthEventNoProgress, 3, "none", "brief", "", "", "score_low", ""), healthEvent(a, c, HealthEventUsefulByteObserved, 4, "useful_sparse", "", "", "", "score_low", ""), healthEvent(a, c, HealthEventScoreDecayed, 5, "none", "", "", "", "score_low", "")}
	default:
		return []HealthEvent{healthEvent(a, c, HealthEventBlackholeLikeFailure, 1, "none", "", "blackhole_like", "", "score_zero", "")}
	}
}

func candidatesForScenario(s HealthScenario, candidates []pathrace.RaceCandidate, activeID string) []pathrace.RaceCandidate {
	out := append([]pathrace.RaceCandidate(nil), candidates...)
	switch s.ScenarioID {
	case "all_alternates_fail":
		for i := range out {
			if out[i].CandidateID != activeID {
				out[i].RelayRiskBucket = "burned"
			}
		}
	case "high_risk_alternate_blocked":
		for i := range out {
			if out[i].CandidateID != activeID {
				out[i].HighRisk = true
				out[i].Gated = true
				out[i].Experimental = false
				out[i].RelayRiskBucket = "medium"
			}
		}
	case "experimental_alternate_blocked":
		for i := range out {
			if out[i].CandidateID != activeID {
				out[i].Experimental = true
				out[i].HighRisk = false
				out[i].RelayRiskBucket = "medium"
			}
		}
	}
	return out
}

func applyControlScenario(run *PathHealthRun) {
	switch run.Scenario.ScenarioID {
	case "control_no_health_monitoring", "control_under_eager_failover":
		run.Report.FinalState = string(HealthHealthy)
		run.Report.FailoverTriggered = false
		run.Failover.Outcome = OutcomeNoFailoverNeeded
	case "control_over_eager_failover":
		run.Failover.Trigger = "single_minor_event"
		run.Failover.Outcome = OutcomeFailoverVerified
		run.Report.FailoverTriggered = true
	case "control_failover_to_burned_relay":
		run.Failover.Outcome = OutcomeFailoverVerified
		run.Failover.NewCandidateID = "burned_candidate_bucket"
		run.Report.FailoverTriggered = true
		run.Report.NewCandidateID = run.Failover.NewCandidateID
	}
	run.Report.Conclusion = "control_failed"
}

func scenarioIDExists(id string) bool {
	for _, scenario := range DefaultScenarios() {
		if scenario.ScenarioID == id {
			return true
		}
	}
	return false
}

func scenarioName(index int) string {
	scenarios := DefaultScenarios()
	if index < 0 || index >= len(scenarios) {
		return fmt.Sprintf("scenario_%d", index)
	}
	return scenarios[index].ScenarioID
}
