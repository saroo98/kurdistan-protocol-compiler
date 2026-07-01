// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import (
	"kurdistan/internal/adaptivepath"
	"kurdistan/internal/transportbundle"
)

type PathRaceVersion string
type RaceID string
type RaceMode string

const Version PathRaceVersion = "pathrace-v1"

const (
	RaceModeFirstUsable       RaceMode = "first_usable"
	RaceModeVerifiedUsable    RaceMode = "verified_usable"
	RaceModeConservative      RaceMode = "conservative"
	RaceModeSurvivalFallback  RaceMode = "survival_fallback"
	RaceModeExperimentalGated RaceMode = "experimental_gated"
	RaceModeControlCollapsed  RaceMode = "control_collapsed"
)

type RaceEventKind string

const (
	RaceEventCandidateStarted  RaceEventKind = "candidate_started"
	RaceEventHandshakeObserved RaceEventKind = "handshake_observed"
	RaceEventFirstUsefulByte   RaceEventKind = "first_useful_byte"
	RaceEventCandidateStalled  RaceEventKind = "candidate_stalled"
	RaceEventCandidateFailed   RaceEventKind = "candidate_failed"
	RaceEventCandidateVerified RaceEventKind = "candidate_verified"
	RaceEventCandidateRejected RaceEventKind = "candidate_rejected"
	RaceEventRaceCompleted     RaceEventKind = "race_completed"
)

type CandidateRaceState string

const (
	RaceStatePending   CandidateRaceState = "pending"
	RaceStateStarted   CandidateRaceState = "started"
	RaceStateVerifying CandidateRaceState = "verifying"
	RaceStateVerified  CandidateRaceState = "verified"
	RaceStateStalled   CandidateRaceState = "stalled"
	RaceStateFailed    CandidateRaceState = "failed"
	RaceStateRejected  CandidateRaceState = "rejected"
	RaceStateGated     CandidateRaceState = "gated"
)

type RaceCandidate struct {
	CandidateID        string                       `json:"candidate_id"`
	Family             adaptivepath.CandidateFamily `json:"family"`
	Role               string                       `json:"role"`
	BundleID           string                       `json:"bundle_id"`
	ProfileSeed        int                          `json:"profile_seed"`
	WirePolicyHash     string                       `json:"wire_policy_hash"`
	RelayRiskBucket    string                       `json:"relay_risk_bucket"`
	MetadataRiskBucket string                       `json:"metadata_risk_bucket"`
	FreshnessTTLClass  string                       `json:"freshness_ttl_class"`
	Gated              bool                         `json:"gated"`
	HighRisk           bool                         `json:"high_risk"`
	Experimental       bool                         `json:"experimental"`
	PayloadLogged      bool                         `json:"payload_logged"`
	SecretLogged       bool                         `json:"secret_logged"`
}

type RaceEvent struct {
	EventID                string        `json:"event_id"`
	RaceID                 string        `json:"race_id"`
	CandidateID            string        `json:"candidate_id"`
	Kind                   RaceEventKind `json:"kind"`
	LogicalTick            int           `json:"logical_tick"`
	LatencyBucket          string        `json:"latency_bucket"`
	TimeToUsefulByteBucket string        `json:"time_to_useful_byte_bucket"`
	FailureBucket          string        `json:"failure_bucket"`
	VerificationBucket     string        `json:"verification_bucket"`
	PayloadLogged          bool          `json:"payload_logged"`
	SecretLogged           bool          `json:"secret_logged"`
}

type RaceOutcome struct {
	RaceID                 string             `json:"race_id"`
	CandidateID            string             `json:"candidate_id"`
	Family                 string             `json:"family"`
	FinalState             CandidateRaceState `json:"final_state"`
	VerifiedUsable         bool               `json:"verified_usable"`
	RejectedReason         string             `json:"rejected_reason"`
	LatencyBucket          string             `json:"latency_bucket"`
	TimeToUsefulByteBucket string             `json:"time_to_useful_byte_bucket"`
	FailureBucket          string             `json:"failure_bucket"`
	ScoreBucket            string             `json:"score_bucket"`
	PayloadLogged          bool               `json:"payload_logged"`
	SecretLogged           bool               `json:"secret_logged"`
}

type PathRaceReport struct {
	Version            string   `json:"version"`
	RaceID             string   `json:"race_id"`
	RaceMode           RaceMode `json:"race_mode"`
	ScenarioID         string   `json:"scenario_id"`
	BundleID           string   `json:"bundle_id"`
	CandidateCount     int      `json:"candidate_count"`
	StartedCandidates  int      `json:"started_candidates"`
	VerifiedCandidates int      `json:"verified_candidates"`
	FailedCandidates   int      `json:"failed_candidates"`
	StalledCandidates  int      `json:"stalled_candidates"`
	RejectedCandidates int      `json:"rejected_candidates"`
	GatedCandidates    int      `json:"gated_candidates"`
	RankedCandidates   []string `json:"ranked_candidates"`
	WinnerCandidateID  string   `json:"winner_candidate_id"`
	WinnerFamily       string   `json:"winner_family"`
	WinnerDeclared     bool     `json:"winner_declared"`
	SyntheticOnly      bool     `json:"synthetic_only"`
	PayloadLogged      bool     `json:"payload_logged"`
	SecretLogged       bool     `json:"secret_logged"`
	ReportHash         string   `json:"report_hash"`
	Conclusion         string   `json:"conclusion"`
}

type PathRaceRun struct {
	Scenario   RaceScenario               `json:"scenario"`
	Bundle     string                     `json:"bundle_id"`
	Mode       transportbundle.BundleMode `json:"bundle_mode"`
	Policy     RaceSchedulerPolicy        `json:"policy"`
	Scoring    ShortLivedScoringPolicy    `json:"scoring_policy"`
	Candidates []RaceCandidate            `json:"candidates"`
	Events     []RaceEvent                `json:"events"`
	Outcomes   []RaceOutcome              `json:"outcomes"`
	Scores     []CandidateScore           `json:"scores"`
	Ranking    CandidateRankingReport     `json:"ranking"`
	Report     PathRaceReport             `json:"report"`
}
