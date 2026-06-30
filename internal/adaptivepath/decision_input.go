// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

import "sort"

type CandidateDecisionInput struct {
	CandidateID         string `json:"candidate_id"`
	Family              string `json:"family"`
	CurrentState        string `json:"current_state"`
	FreshnessClass      string `json:"freshness_class"`
	UncertaintyBucket   string `json:"uncertainty_bucket"`
	RecentSuccessBucket string `json:"recent_success_bucket"`
	RecentFailureBucket string `json:"recent_failure_bucket"`
	RelayRiskBucket     string `json:"relay_risk_bucket"`
	MetadataRiskBucket  string `json:"metadata_risk_bucket"`
	LastFailureBucket   string `json:"last_failure_bucket"`
	DecisionHash        string `json:"decision_hash"`
	PayloadLogged       bool   `json:"payload_logged"`
	SecretLogged        bool   `json:"secret_logged"`
}

type CandidateDecisionSet struct {
	Version            string                   `json:"version"`
	CandidateCount     int                      `json:"candidate_count"`
	ObservationCount   int                      `json:"observation_count"`
	Inputs             []CandidateDecisionInput `json:"inputs"`
	HighRiskCandidates int                      `json:"high_risk_candidates"`
	RejectedCandidates int                      `json:"rejected_candidates"`
	UnknownCandidates  int                      `json:"unknown_candidates"`
	DecisionSetHash    string                   `json:"decision_set_hash"`
	PayloadLogged      bool                     `json:"payload_logged"`
	SecretLogged       bool                     `json:"secret_logged"`
}

func BuildDecisionSet(candidates []PathCandidate, observations []PathObservation) CandidateDecisionSet {
	reports := EvaluateAll(candidates, observations)
	inputs := make([]CandidateDecisionInput, 0, len(reports))
	candidatesByID := map[string]PathCandidate{}
	for _, candidate := range candidates {
		candidatesByID[string(candidate.CandidateID)] = candidate
	}
	set := CandidateDecisionSet{Version: string(Version), CandidateCount: len(candidates), ObservationCount: len(observations)}
	for _, report := range reports {
		candidate := candidatesByID[report.CandidateID]
		input := CandidateDecisionInput{
			CandidateID:         report.CandidateID,
			Family:              report.Family,
			CurrentState:        report.CurrentState,
			FreshnessClass:      report.FreshnessClass,
			UncertaintyBucket:   report.UncertaintyBucket,
			RecentSuccessBucket: report.RecentSuccessBucket,
			RecentFailureBucket: report.RecentFailureBucket,
			RelayRiskBucket:     report.RelayRiskBucket,
			MetadataRiskBucket:  report.MetadataRiskBucket,
			LastFailureBucket:   report.LastFailureBucket,
		}
		input.DecisionHash = HashValue(decisionHashInput(input))
		inputs = append(inputs, input)
		if desc, ok := FamilyDescriptor(candidate.Family); ok && desc.HighRisk {
			set.HighRiskCandidates++
		}
		if report.CurrentState == string(CandidateRejected) || report.CurrentState == string(CandidateBlocked) || report.CurrentState == string(CandidateBurned) {
			set.RejectedCandidates++
		}
		if report.CurrentState == string(CandidateUnknown) {
			set.UnknownCandidates++
		}
	}
	sort.Slice(inputs, func(i, j int) bool {
		if inputs[i].CurrentState != inputs[j].CurrentState {
			return stateRank(inputs[i].CurrentState) < stateRank(inputs[j].CurrentState)
		}
		return inputs[i].CandidateID < inputs[j].CandidateID
	})
	set.Inputs = inputs
	set.DecisionSetHash = HashValue(decisionSetHashInput(set))
	return set
}

func decisionHashInput(input CandidateDecisionInput) CandidateDecisionInput {
	input.DecisionHash = ""
	return input
}

func decisionSetHashInput(set CandidateDecisionSet) CandidateDecisionSet {
	set.DecisionSetHash = ""
	return set
}

func stateRank(state string) int {
	switch state {
	case string(CandidateLikelyUsable):
		return 0
	case string(CandidateDegraded), string(CandidateUnstable):
		return 1
	case string(CandidateUnknown):
		return 2
	default:
		return 3
	}
}
