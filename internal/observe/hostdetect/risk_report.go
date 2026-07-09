// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

func Collapse(aggregates []HostAggregate) HostCollapseReport {
	report := HostCollapseReport{HostCount: len(aggregates), Conclusion: "passed"}
	features := map[string]bool{}
	firstN := map[string]bool{}
	for _, aggregate := range aggregates {
		report.ObservationCount += aggregate.ObservationCount
		report.PayloadLogged = report.PayloadLogged || aggregate.PayloadLogged
		report.SecretLogged = report.SecretLogged || aggregate.SecretLogged
		if aggregate.UniqueFeatureHashes == 1 {
			report.HighConsistencyHosts++
		}
		if aggregate.HostClass == HostClassControlPadding {
			report.PaddingOnlyHosts++
		}
		if aggregate.HostClass == HostClassControlFixed {
			report.CollapsedControlDetected = true
		}
		features[string(aggregate.SyntheticHostID)+":"+aggregate.RiskBucket] = true
		firstN[string(aggregate.SyntheticHostID)+":"+aggregate.RiskBucket] = true
		if aggregate.ObservationCount >= 3 && aggregate.DominantFeatureShare >= 0.95 {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "dominant_feature_hash")
		}
		if aggregate.ObservationCount >= 3 && aggregate.DominantFirstNShare >= 0.95 {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "dominant_first_n_shape")
		}
	}
	report.UniqueFeatureHashes = len(features)
	report.UniqueFirstNShapes = len(firstN)
	if report.HostCount > 0 {
		report.DiversityScore = float64(report.UniqueFeatureHashes+report.UniqueFirstNShapes) / float64(report.HostCount*2)
	}
	if !report.CollapsedControlDetected || report.PaddingOnlyHosts == 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func SyntheticCollapsedAggregates() []HostAggregate {
	return []HostAggregate{{
		SyntheticHostID:      "host_9000",
		HostClass:            HostClassControlFixed,
		ObservationCount:     8,
		UniqueProfileSeeds:   1,
		UniqueFeatureHashes:  1,
		UniqueFirstNShapes:   1,
		UniqueFamilies:       1,
		DominantFeatureShare: 1,
		DominantFirstNShare:  1,
		DominantFamilyShare:  1,
		ConsistencyScore:     1,
		RotationScore:        0,
		RiskBucket:           "critical",
	}}
}
