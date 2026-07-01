// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import "sort"

type CandidateRankingReport struct {
	CandidateCount      int      `json:"candidate_count"`
	RankedCandidates    []string `json:"ranked_candidates"`
	VerifiedUsable      int      `json:"verified_usable"`
	RejectedCandidates  int      `json:"rejected_candidates"`
	GatedCandidates     int      `json:"gated_candidates"`
	TieBreaksApplied    int      `json:"tie_breaks_applied"`
	WinnerCandidateID   string   `json:"winner_candidate_id"`
	WinnerFamily        string   `json:"winner_family"`
	WinnerSyntheticOnly bool     `json:"winner_synthetic_only"`
	PayloadLogged       bool     `json:"payload_logged"`
	SecretLogged        bool     `json:"secret_logged"`
	Conclusion          string   `json:"conclusion"`
}

func RankCandidates(candidates []RaceCandidate, outcomes []RaceOutcome, scores []CandidateScore) CandidateRankingReport {
	scoreByID := map[string]CandidateScore{}
	outcomeByID := map[string]RaceOutcome{}
	candidateByID := map[string]RaceCandidate{}
	for _, score := range scores {
		scoreByID[score.CandidateID] = score
	}
	for _, outcome := range outcomes {
		outcomeByID[outcome.CandidateID] = outcome
	}
	for _, candidate := range candidates {
		candidateByID[candidate.CandidateID] = candidate
	}
	ids := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		ids = append(ids, candidate.CandidateID)
	}
	tieBreaks := 0
	sort.SliceStable(ids, func(i, j int) bool {
		left, right := ids[i], ids[j]
		lo, ro := outcomeByID[left], outcomeByID[right]
		ls, rs := scoreByID[left], scoreByID[right]
		if lo.VerifiedUsable != ro.VerifiedUsable {
			return lo.VerifiedUsable
		}
		if scoreValue(ls.ScoreBucket) != scoreValue(rs.ScoreBucket) {
			return scoreValue(ls.ScoreBucket) > scoreValue(rs.ScoreBucket)
		}
		lc, rc := candidateByID[left], candidateByID[right]
		if lc.HighRisk != rc.HighRisk {
			return !lc.HighRisk
		}
		if lc.Experimental != rc.Experimental {
			return !lc.Experimental
		}
		tieBreaks++
		return left < right
	})
	report := CandidateRankingReport{CandidateCount: len(candidates), RankedCandidates: ids, WinnerSyntheticOnly: true, Conclusion: "passed", TieBreaksApplied: tieBreaks}
	for _, outcome := range outcomes {
		if outcome.VerifiedUsable {
			report.VerifiedUsable++
		}
		if outcome.FinalState == RaceStateRejected || outcome.FinalState == RaceStateFailed {
			report.RejectedCandidates++
		}
		if outcome.FinalState == RaceStateGated {
			report.GatedCandidates++
		}
	}
	for _, id := range ids {
		outcome := outcomeByID[id]
		candidate := candidateByID[id]
		if outcome.VerifiedUsable && !candidate.HighRisk && !candidate.Experimental {
			report.WinnerCandidateID = id
			report.WinnerFamily = string(candidate.Family)
			break
		}
	}
	if report.WinnerCandidateID == "" {
		report.Conclusion = "no_winner"
	}
	return report
}
