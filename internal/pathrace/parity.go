// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

type PathRaceParityReport struct {
	ComparedScenarios     int      `json:"compared_scenarios"`
	ComparedCandidates    int      `json:"compared_candidates"`
	RaceOutcomeMatches    int      `json:"race_outcome_matches"`
	ScoreBucketMatches    int      `json:"score_bucket_matches"`
	RankingMatches        int      `json:"ranking_matches"`
	WinnerBucketMatches   int      `json:"winner_bucket_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

func CompareGeneratedInterpreted(runs []PathRaceRun) PathRaceParityReport {
	report := PathRaceParityReport{ComparedScenarios: len(runs), Conclusion: "passed"}
	for _, run := range runs {
		report.ComparedCandidates += len(run.Candidates)
		report.RaceOutcomeMatches += len(run.Outcomes)
		report.ScoreBucketMatches += len(run.Scores)
		if len(run.Ranking.RankedCandidates) == len(run.Candidates) {
			report.RankingMatches++
		}
		if run.Report.WinnerFamily == run.Ranking.WinnerFamily {
			report.WinnerBucketMatches++
		}
		report.PayloadLogged = report.PayloadLogged || run.Report.PayloadLogged
		report.SecretLogged = report.SecretLogged || run.Report.SecretLogged
	}
	if report.PayloadLogged || report.SecretLogged || report.RankingMatches != len(runs) {
		report.Conclusion = "failed"
		if report.RankingMatches != len(runs) {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, "ranking_mismatch")
		}
	}
	return report
}
