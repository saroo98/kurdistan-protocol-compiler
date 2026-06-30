// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import "sort"

func Detect(aggregates []HostAggregate, window ObservationWindow, model ConfidenceModel) HostDetectionReport {
	report := HostDetectionReport{Version: string(Version), Window: window, Threshold: model.Name, HostCount: len(aggregates), Conclusion: "passed"}
	flaggedControls := 0
	for _, aggregate := range aggregates {
		report.ObservationCount += aggregate.ObservationCount
		report.PayloadLogged = report.PayloadLogged || aggregate.PayloadLogged
		report.SecretLogged = report.SecretLogged || aggregate.SecretLogged
		conf := ScoreHost(aggregate, model)
		if conf.Flagged {
			report.HostsFlagged++
			report.HighRiskHosts = append(report.HighRiskHosts, string(aggregate.SyntheticHostID))
			switch aggregate.HostClass {
			case HostClassGeneratedRelay:
				report.GeneratedHostsFlagged++
			case HostClassCorpusBaseline:
				report.BaselineHostsFlagged++
			default:
				report.ControlHostsFlagged++
				flaggedControls++
			}
		}
	}
	sort.Strings(report.HighRiskHosts)
	if report.HostsFlagged > 0 {
		report.PrecisionEstimate = float64(flaggedControls) / float64(report.HostsFlagged)
	}
	if report.ControlHostsFlagged > 0 {
		report.RecallEstimate = 1
	}
	if report.PayloadLogged || report.SecretLogged || report.ControlHostsFlagged == 0 {
		report.Conclusion = "failed"
	}
	return report
}

func Resistance(aggregates []HostAggregate) HostResistanceReport {
	report := HostResistanceReport{Version: string(Version), HostCount: len(aggregates), Conclusion: "passed"}
	for _, aggregate := range aggregates {
		report.ObservationCount += aggregate.ObservationCount
		report.AvgUniqueFeatureHashes += float64(aggregate.UniqueFeatureHashes)
		report.AvgUniqueFirstNShapes += float64(aggregate.UniqueFirstNShapes)
		report.AvgConsistencyScore += aggregate.ConsistencyScore
		report.AvgRotationScore += aggregate.RotationScore
		report.PayloadLogged = report.PayloadLogged || aggregate.PayloadLogged
		report.SecretLogged = report.SecretLogged || aggregate.SecretLogged
		switch aggregate.HostClass {
		case HostClassGeneratedRelay:
			report.GeneratedHostCount++
			if aggregate.RiskBucket == "high" || aggregate.RiskBucket == "critical" {
				report.HighRiskGeneratedHosts++
			}
		case HostClassControlPadding:
			report.PaddingOnlyDetected = true
		case HostClassControlFixed:
			report.ControlCollapseDetected = true
		}
	}
	if report.HostCount > 0 {
		denom := float64(report.HostCount)
		report.AvgObservationsPerHost = float64(report.ObservationCount) / denom
		report.AvgUniqueFeatureHashes /= denom
		report.AvgUniqueFirstNShapes /= denom
		report.AvgConsistencyScore /= denom
		report.AvgRotationScore /= denom
	}
	if report.HighRiskGeneratedHosts > 0 {
		report.RecommendedNextActions = append(report.RecommendedNextActions, "increase_profile_rotation_in_repeated_host_scenarios")
	}
	if !report.ControlCollapseDetected {
		report.Conclusion = "failed"
		report.RecommendedNextActions = append(report.RecommendedNextActions, "restore_control_collapse_detection")
	}
	if !report.PaddingOnlyDetected {
		report.RecommendedNextActions = append(report.RecommendedNextActions, "restore_padding_only_control_detection")
	}
	if report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	if len(report.RecommendedNextActions) == 0 {
		report.RecommendedNextActions = []string{"continue_host_rotation_metric_tracking"}
	}
	return report
}
