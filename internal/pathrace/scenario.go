// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import (
	"context"
	"fmt"

	"kurdistan/internal/adaptivepath"
	"kurdistan/internal/transportbundle"
)

type RaceScenario struct {
	ScenarioID          string                     `json:"scenario_id"`
	RaceMode            RaceMode                   `json:"race_mode"`
	BundleMode          transportbundle.BundleMode `json:"bundle_mode"`
	CandidateCount      int                        `json:"candidate_count"`
	ExpectedWinnerClass string                     `json:"expected_winner_class"`
	ExpectedRejected    int                        `json:"expected_rejected"`
	ExpectedVerified    int                        `json:"expected_verified"`
	ExpectedGated       int                        `json:"expected_gated"`
	ExpectedConclusion  string                     `json:"expected_conclusion"`
	Control             bool                       `json:"control"`
	PayloadLogged       bool                       `json:"payload_logged"`
	SecretLogged        bool                       `json:"secret_logged"`
}

func DefaultScenarios() []RaceScenario {
	return []RaceScenario{
		{"all_candidates_unknown", RaceModeVerifiedUsable, transportbundle.BundleModeBalancedAdaptive, 6, "", 0, 0, 2, "no_winner", false, false, false},
		{"https_like_fast_success", RaceModeFirstUsable, transportbundle.BundleModeBalancedAdaptive, 6, string(adaptivepath.CandidateHTTPSLikeTCP), 0, 1, 2, "passed", false, false, false},
		{"dns_survival_slow_success", RaceModeSurvivalFallback, transportbundle.BundleModeSurvivalDNS, 5, string(adaptivepath.CandidateDNSSurvival), 0, 1, 0, "passed", false, false, false},
		{"tcp_blackhole_then_dns_success", RaceModeVerifiedUsable, transportbundle.BundleModeSurvivalDNS, 5, string(adaptivepath.CandidateDNSSurvival), 1, 1, 0, "passed", false, false, false},
		{"udp_blocked_https_success", RaceModeVerifiedUsable, transportbundle.BundleModeExperimentalMix, 5, string(adaptivepath.CandidateHTTPSLikeTCP), 1, 1, 1, "passed", false, false, false},
		{"relay_burn_rejects_candidate", RaceModeConservative, transportbundle.BundleModeBalancedAdaptive, 6, string(adaptivepath.CandidateHTTPSLikeTCP), 1, 1, 2, "passed", false, false, false},
		{"handshake_ok_data_stalls", RaceModeVerifiedUsable, transportbundle.BundleModeBalancedAdaptive, 6, string(adaptivepath.CandidateDNSSurvival), 0, 1, 2, "passed", false, false, false},
		{"brief_success_then_failure", RaceModeConservative, transportbundle.BundleModeBalancedAdaptive, 6, string(adaptivepath.CandidateDNSSurvival), 1, 1, 2, "passed", false, false, false},
		{"high_risk_candidate_gated", RaceModeConservative, transportbundle.BundleModeHighRiskReview, 4, string(adaptivepath.CandidateHTTPSLikeTCP), 0, 1, 2, "passed", false, false, false},
		{"experimental_candidate_gated", RaceModeExperimentalGated, transportbundle.BundleModeExperimentalMix, 5, string(adaptivepath.CandidateHTTPSLikeTCP), 0, 2, 0, "passed", false, false, false},
		{"all_candidates_fail", RaceModeConservative, transportbundle.BundleModeBalancedAdaptive, 6, "", 4, 0, 2, "no_winner", false, false, false},
		{"control_first_candidate_always_wins", RaceModeControlCollapsed, transportbundle.BundleModeControlCollapsed, 5, "collapsed_control", 0, 5, 0, "control_failed", true, false, false},
		{"control_stale_success_wins", RaceModeControlCollapsed, transportbundle.BundleModeBalancedAdaptive, 6, string(adaptivepath.CandidateHTTPSLikeTCP), 0, 2, 0, "control_failed", true, false, false},
		{"control_high_risk_wins", RaceModeControlCollapsed, transportbundle.BundleModeHighRiskReview, 4, string(adaptivepath.CandidateDomesticMediaRisk), 0, 2, 0, "control_failed", true, false, false},
	}
}

func QuickScenarios() []RaceScenario {
	all := DefaultScenarios()
	return []RaceScenario{all[1], all[3], all[8], all[11]}
}

func RunScenario(ctx context.Context, scenario RaceScenario) (PathRaceRun, error) {
	compiled, err := transportbundle.Compile(ctx, transportbundle.DefaultPolicy(12345, scenario.BundleMode))
	if err != nil {
		return PathRaceRun{}, err
	}
	return RunScenarioWithManifest(scenario, compiled.Manifest)
}

func RunScenarioWithManifest(scenario RaceScenario, manifest transportbundle.TransportBundleManifest) (PathRaceRun, error) {
	candidates := CandidatesFromBundle(manifest)
	if scenario.CandidateCount > 0 && len(candidates) != scenario.CandidateCount {
		return PathRaceRun{}, fmt.Errorf("%w: scenario candidate count mismatch", ErrInvalidRace)
	}
	raceID := fmt.Sprintf("race_%s_%s", scenario.ScenarioID, manifest.BundleID)
	scheduler := DefaultSchedulerPolicy(scenario.RaceMode)
	scoring := DefaultScoringPolicy()
	events := ScheduleStarts(raceID, candidates, scheduler)
	events = append(events, scenarioEvents(raceID, scenario, candidates)...)
	outcomes := make([]RaceOutcome, 0, len(candidates))
	scores := make([]CandidateScore, 0, len(candidates))
	for _, candidate := range candidates {
		candidateEvents := eventsForCandidate(events, candidate.CandidateID)
		verification := VerifyCandidate(candidate, candidateEvents, scheduler)
		score := ScoreCandidate(candidate, verification, candidateEvents, scoring)
		outcome := BuildOutcome(raceID, candidate, verification, score, candidateEvents)
		scores = append(scores, score)
		outcomes = append(outcomes, outcome)
	}
	ranking := RankCandidates(candidates, outcomes, scores)
	if scenario.Control {
		applyControlOutcome(scenario, candidates, outcomes, scores, &ranking)
	}
	report := BuildReport(scenario, manifest.BundleID, candidates, outcomes, ranking)
	events = append(events, raceEvent(raceID, "", RaceEventRaceCompleted, 99, "none", "none", "none", report.Conclusion))
	return PathRaceRun{
		Scenario: scenario, Bundle: manifest.BundleID, Mode: scenario.BundleMode, Policy: scheduler, Scoring: scoring,
		Candidates: candidates, Events: events, Outcomes: outcomes, Scores: scores, Ranking: ranking, Report: report,
	}, nil
}

func scenarioEvents(raceID string, scenario RaceScenario, candidates []RaceCandidate) []RaceEvent {
	events := []RaceEvent{}
	addSuccess := func(family adaptivepath.CandidateFamily, tick int, latency string) {
		if c, ok := firstCandidateByFamily(candidates, family); ok {
			events = append(events,
				raceEvent(raceID, c.CandidateID, RaceEventHandshakeObserved, tick, latency, "none", "none", "handshake"),
				raceEvent(raceID, c.CandidateID, RaceEventFirstUsefulByte, tick+1, latency, "first_byte_"+latency, "none", "useful_byte"),
				raceEvent(raceID, c.CandidateID, RaceEventCandidateVerified, tick+2, latency, "first_byte_"+latency, "none", "verified_usable"),
			)
		}
	}
	addFailure := func(family adaptivepath.CandidateFamily, tick int, failure string) {
		for _, c := range candidates {
			if c.Family == family {
				events = append(events, raceEvent(raceID, c.CandidateID, RaceEventCandidateFailed, tick, "none", "none", failure, "failed"))
			}
		}
	}
	switch scenario.ScenarioID {
	case "https_like_fast_success":
		addSuccess(adaptivepath.CandidateHTTPSLikeTCP, 1, "fast")
	case "dns_survival_slow_success":
		addSuccess(adaptivepath.CandidateDNSSurvival, 2, "slow")
	case "tcp_blackhole_then_dns_success":
		addFailure(adaptivepath.CandidateHTTPSLikeTCP, 1, "blackhole_like_failure")
		addSuccess(adaptivepath.CandidateDNSSurvival, 3, "slow")
	case "udp_blocked_https_success":
		addFailure(adaptivepath.CandidateExperimentalUDP, 1, "udp_blocked")
		addSuccess(adaptivepath.CandidateHTTPSLikeTCP, 2, "fast")
	case "relay_burn_rejects_candidate":
		addFailure(adaptivepath.CandidateRelayRotation, 1, "relay_burn")
		addSuccess(adaptivepath.CandidateHTTPSLikeTCP, 2, "fast")
	case "handshake_ok_data_stalls":
		if c, ok := firstCandidateByFamily(candidates, adaptivepath.CandidateHTTPSLikeTCP); ok {
			events = append(events,
				raceEvent(raceID, c.CandidateID, RaceEventHandshakeObserved, 1, "fast", "none", "none", "handshake"),
				raceEvent(raceID, c.CandidateID, RaceEventCandidateStalled, 2, "fast", "none", "stall_after_handshake", "stalled"),
			)
		}
		addSuccess(adaptivepath.CandidateDNSSurvival, 3, "slow")
	case "brief_success_then_failure":
		if c, ok := firstCandidateByFamily(candidates, adaptivepath.CandidateHTTPSLikeTCP); ok {
			events = append(events,
				raceEvent(raceID, c.CandidateID, RaceEventHandshakeObserved, 1, "fast", "none", "none", "handshake"),
				raceEvent(raceID, c.CandidateID, RaceEventFirstUsefulByte, 2, "fast", "first_byte_fast", "none", "stale_success"),
				raceEvent(raceID, c.CandidateID, RaceEventCandidateFailed, 3, "fast", "first_byte_fast", "recent_failure", "failed"),
			)
		}
		addSuccess(adaptivepath.CandidateDNSSurvival, 4, "slow")
	case "high_risk_candidate_gated":
		addSuccess(adaptivepath.CandidateDomesticMediaRisk, 1, "fast")
		addSuccess(adaptivepath.CandidateHTTPSLikeTCP, 2, "medium")
	case "experimental_candidate_gated":
		addSuccess(adaptivepath.CandidateExperimentalUDP, 1, "fast")
		addSuccess(adaptivepath.CandidateHTTPSLikeTCP, 2, "medium")
	case "all_candidates_fail":
		for _, candidate := range candidates {
			events = append(events, raceEvent(raceID, candidate.CandidateID, RaceEventCandidateFailed, 1, "none", "none", "blocked", "failed"))
		}
	case "control_first_candidate_always_wins", "control_stale_success_wins", "control_high_risk_wins":
		for i, candidate := range candidates {
			events = append(events, raceEvent(raceID, candidate.CandidateID, RaceEventCandidateVerified, i+1, "same", "first_byte_same", "none", "verified_usable"))
		}
	}
	return events
}

func firstCandidateByFamily(candidates []RaceCandidate, family adaptivepath.CandidateFamily) (RaceCandidate, bool) {
	for _, candidate := range candidates {
		if candidate.Family == family {
			return candidate, true
		}
	}
	return RaceCandidate{}, false
}

func applyControlOutcome(scenario RaceScenario, candidates []RaceCandidate, outcomes []RaceOutcome, scores []CandidateScore, ranking *CandidateRankingReport) {
	if len(candidates) == 0 {
		return
	}
	switch scenario.ScenarioID {
	case "control_high_risk_wins":
		for _, c := range candidates {
			if c.HighRisk {
				ranking.WinnerCandidateID = c.CandidateID
				ranking.WinnerFamily = string(c.Family)
				break
			}
		}
	default:
		ranking.WinnerCandidateID = candidates[0].CandidateID
		ranking.WinnerFamily = string(candidates[0].Family)
	}
	if ranking.WinnerCandidateID == "" {
		ranking.WinnerCandidateID = candidates[0].CandidateID
		ranking.WinnerFamily = string(candidates[0].Family)
	}
	ranking.Conclusion = "control_failed"
	_ = outcomes
	_ = scores
}
