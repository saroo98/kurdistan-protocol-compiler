// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

type DegradationReport struct {
	ActivePathID          string `json:"active_path_id"`
	EventCount            int    `json:"event_count"`
	NoProgressEvents      int    `json:"no_progress_events"`
	StallEvents           int    `json:"stall_events"`
	ResetLikeFailures     int    `json:"reset_like_failures"`
	BlackholeLikeFailures int    `json:"blackhole_like_failures"`
	ConfidenceExpired     bool   `json:"confidence_expired"`
	ScoreDecayed          bool   `json:"score_decayed"`
	RelayBurnDetected     bool   `json:"relay_burn_detected"`
	ReconnectLoopDetected bool   `json:"reconnect_loop_detected"`
	FlappingDetected      bool   `json:"flapping_detected"`
	DegradationBucket     string `json:"degradation_bucket"`
	PayloadLogged         bool   `json:"payload_logged"`
	SecretLogged          bool   `json:"secret_logged"`
	Conclusion            string `json:"conclusion"`
}

func DetectDegradation(active ActivePath, events []HealthEvent) DegradationReport {
	report := DegradationReport{ActivePathID: active.ActivePathID, EventCount: len(events), DegradationBucket: "stable", Conclusion: "passed"}
	reconnectFailures := 0
	stateSwitches := 0
	lastKind := HealthEventKind("")
	for _, event := range events {
		switch event.Kind {
		case HealthEventNoProgress:
			report.NoProgressEvents++
		case HealthEventStallDetected:
			report.StallEvents++
		case HealthEventResetLikeFailure:
			report.ResetLikeFailures++
		case HealthEventBlackholeLikeFailure:
			report.BlackholeLikeFailures++
		case HealthEventConfidenceExpired:
			report.ConfidenceExpired = true
		case HealthEventScoreDecayed:
			report.ScoreDecayed = true
		case HealthEventRelayBurnSignal:
			report.RelayBurnDetected = true
		case HealthEventReconnectFailed:
			reconnectFailures++
		}
		if lastKind != "" && lastKind != event.Kind {
			stateSwitches++
		}
		lastKind = event.Kind
		report.PayloadLogged = report.PayloadLogged || event.PayloadLogged
		report.SecretLogged = report.SecretLogged || event.SecretLogged
	}
	report.ReconnectLoopDetected = reconnectFailures >= 2
	report.FlappingDetected = stateSwitches >= 5
	switch {
	case report.RelayBurnDetected || report.BlackholeLikeFailures > 0:
		report.DegradationBucket = "critical"
	case report.ReconnectLoopDetected || report.ResetLikeFailures >= 2 || report.StallEvents > 0:
		report.DegradationBucket = "severe"
	case report.NoProgressEvents >= 3 || report.ConfidenceExpired || report.ScoreDecayed || report.FlappingDetected:
		report.DegradationBucket = "degraded"
	case report.NoProgressEvents > 0:
		report.DegradationBucket = "minor"
	}
	if report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}
