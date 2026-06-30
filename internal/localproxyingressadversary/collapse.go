// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

type CollapseReport struct {
	Scenario          string   `json:"scenario"`
	ProfileCount      int      `json:"profile_count"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	DiversityScore    float64  `json:"diversity_score"`
	Conclusion        string   `json:"conclusion"`
	PayloadLogged     bool     `json:"payload_logged"`
	SecretLogged      bool     `json:"secret_logged"`
}

func ScanCollapse(vectors []FeatureVector, scenario string) CollapseReport {
	report := CollapseReport{Scenario: scenario, ProfileCount: len(vectors), DiversityScore: 1, Conclusion: "passed"}
	if len(vectors) == 0 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "no_vectors")
	}
	for _, vector := range vectors {
		report.PayloadLogged = report.PayloadLogged || vector.PayloadLogged
		report.SecretLogged = report.SecretLogged || vector.SecretLogged
		switch scenario {
		case ScenarioFixedTargetDescriptor:
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "same_target_binding")
		case ScenarioFixedStreamMapping:
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "same_mapping_for_every_request")
		case ScenarioBackpressureIgnored:
			if vector.BackpressureEvents == 0 {
				report.SuspiciousMetrics = append(report.SuspiciousMetrics, "backpressure_ignored")
			}
		case ScenarioInvalidTargetsAccepted:
			if vector.RejectedRequests == 0 {
				report.SuspiciousMetrics = append(report.SuspiciousMetrics, "invalid_targets_accepted")
			}
		case ScenarioPayloadLoggedControl:
			if vector.PayloadLogged {
				report.SuspiciousMetrics = append(report.SuspiciousMetrics, "payload_hygiene_failed")
			}
		case ScenarioSecretLoggedControl:
			if vector.SecretLogged {
				report.SuspiciousMetrics = append(report.SuspiciousMetrics, "secret_hygiene_failed")
			}
		}
	}
	if len(report.SuspiciousMetrics) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
		report.DiversityScore = 0
	}
	return report
}
