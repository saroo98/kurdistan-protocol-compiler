// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

type ActivePathScoreReport struct {
	ActivePathID         string `json:"active_path_id"`
	InitialScoreBucket   string `json:"initial_score_bucket"`
	FinalScoreBucket     string `json:"final_score_bucket"`
	ConfidenceTTLClass   string `json:"confidence_ttl_class"`
	FreshnessClass       string `json:"freshness_class"`
	FailureStreakBucket  string `json:"failure_streak_bucket"`
	UsefulProgressBucket string `json:"useful_progress_bucket"`
	RiskPenaltyBucket    string `json:"risk_penalty_bucket"`
	PayloadLogged        bool   `json:"payload_logged"`
	SecretLogged         bool   `json:"secret_logged"`
	Conclusion           string `json:"conclusion"`
}

func ScoreActivePath(active ActivePath, degradation DegradationReport, events []HealthEvent) ActivePathScoreReport {
	value := scoreValue(active.InitialScoreBucket)
	useful := 0
	ttl := "ttl_short_session"
	for _, event := range events {
		ttl = event.ConfidenceTTLClass
		if event.Kind == HealthEventUsefulByteObserved {
			useful++
			value += 1
		}
	}
	switch degradation.DegradationBucket {
	case "minor":
		value--
	case "degraded":
		value -= 2
	case "severe":
		value -= 3
	case "critical":
		value = 0
	}
	if active.MetadataRiskBucket == "high" || active.MetadataRiskBucket == "critical" {
		value--
	}
	if value < 0 {
		value = 0
	}
	report := ActivePathScoreReport{
		ActivePathID:         active.ActivePathID,
		InitialScoreBucket:   active.InitialScoreBucket,
		FinalScoreBucket:     scoreBucket(value),
		ConfidenceTTLClass:   ttl,
		FreshnessClass:       freshnessClass(degradation),
		FailureStreakBucket:  failureStreakBucket(degradation),
		UsefulProgressBucket: usefulProgressBucket(useful),
		RiskPenaltyBucket:    riskPenaltyBucket(active, degradation),
		Conclusion:           "passed",
	}
	if report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func scoreValue(bucket string) int {
	switch bucket {
	case "score_high":
		return 4
	case "score_medium":
		return 3
	case "score_low":
		return 2
	default:
		return 1
	}
}

func scoreBucket(value int) string {
	switch {
	case value >= 4:
		return "score_high"
	case value == 3:
		return "score_medium"
	case value >= 1:
		return "score_low"
	default:
		return "score_zero"
	}
}

func freshnessClass(d DegradationReport) string {
	if d.ConfidenceExpired {
		return "expired"
	}
	if d.DegradationBucket == "stable" || d.DegradationBucket == "minor" {
		return "fresh"
	}
	return "stale"
}

func failureStreakBucket(d DegradationReport) string {
	total := d.ResetLikeFailures + d.BlackholeLikeFailures
	switch {
	case d.RelayBurnDetected || total >= 3:
		return "failure_streak_high"
	case total > 0 || d.StallEvents > 0:
		return "failure_streak_low"
	default:
		return "none"
	}
}

func usefulProgressBucket(useful int) string {
	if useful >= 2 {
		return "useful_recent"
	}
	if useful == 1 {
		return "useful_sparse"
	}
	return "none"
}

func riskPenaltyBucket(active ActivePath, d DegradationReport) string {
	if d.RelayBurnDetected {
		return "critical_risk_penalty"
	}
	if active.MetadataRiskBucket == "high" || active.MetadataRiskBucket == "critical" {
		return "metadata_risk_penalty"
	}
	return "none"
}
