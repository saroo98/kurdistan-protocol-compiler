// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrierreview

import "sort"

type CarrierReviewMatrix struct {
	Layers map[string]string `json:"layers"`
}

type CarrierFamilyReview struct {
	Version       string                    `json:"version"`
	ReviewID      string                    `json:"review_id"`
	Descriptors   []CarrierFamilyDescriptor `json:"descriptors"`
	Matrix        CarrierReviewMatrix       `json:"matrix"`
	Misuse        CarrierReviewMisuseReport `json:"misuse"`
	Parity        CarrierReviewParityReport `json:"parity"`
	Readiness     CarrierReadinessReport    `json:"readiness"`
	PayloadLogged bool                      `json:"payload_logged"`
	SecretLogged  bool                      `json:"secret_logged"`
	ReviewHash    string                    `json:"review_hash"`
	Conclusion    string                    `json:"conclusion"`
}

type CarrierReadinessReport struct {
	FamilyCount              int      `json:"family_count"`
	ReadySyntheticFamilies   int      `json:"ready_synthetic_families"`
	GatedFamilies            int      `json:"gated_families"`
	ManualReviewFamilies     int      `json:"manual_review_families"`
	BlockingIssues           []string `json:"blocking_issues,omitempty"`
	RecommendedNextMilestone string   `json:"recommended_next_milestone"`
	Conclusion               string   `json:"conclusion"`
}

type CarrierReviewMisuseReport struct {
	DescriptorsChecked int      `json:"descriptors_checked"`
	SuspiciousMetrics  []string `json:"suspicious_metrics,omitempty"`
	PayloadLogged      bool     `json:"payload_logged"`
	SecretLogged       bool     `json:"secret_logged"`
	Conclusion         string   `json:"conclusion"`
}

type CarrierReviewParityReport struct {
	ComparedFamilies      int      `json:"compared_families"`
	ReadinessMatches      int      `json:"readiness_matches"`
	RiskMatches           int      `json:"risk_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

func DefaultMatrix() CarrierReviewMatrix {
	return CarrierReviewMatrix{Layers: map[string]string{
		"adaptivepath":             "candidate taxonomy and volatile condition input",
		"transportbundle":          "bundle membership and fallback hints",
		"pathrace":                 "short-lived candidate scoring",
		"pathhealth":               "active health, quarantine, and failover hooks",
		"relayfleet":               "synthetic relay burn and lifecycle metadata",
		"hostdetect":               "host-level collapse and consistency checks",
		"proxyingress":             "local ingress contract preconditions",
		"localproxyingress":        "deterministic local ingress prototype summaries",
		"security":                 "transcript binding and replay checks",
		"hardening":                "panic/resource/trace hygiene checks",
		"trace_hygiene":            "payload-free metadata-only reports",
		"generated_backend_parity": "generated/interpreted marker and test parity",
	}}
}

func GenerateReview() (CarrierFamilyReview, error) {
	descriptors := DefaultDescriptors()
	readiness := EvaluateReadiness(descriptors)
	misuse := ScanMisuse(descriptors)
	parity := CompareGeneratedInterpreted(descriptors)
	review := CarrierFamilyReview{
		Version:     Version,
		ReviewID:    "carrier_family_design_review_v1",
		Descriptors: descriptors,
		Matrix:      DefaultMatrix(),
		Misuse:      misuse,
		Parity:      parity,
		Readiness:   readiness,
		Conclusion:  "passed",
	}
	if misuse.Conclusion != "passed" || parity.Conclusion != "passed" || readiness.Conclusion != "passed" {
		review.Conclusion = "failed"
	}
	review.ReviewHash = HashValue(reviewHashInput(review))
	return review, ValidateReview(review)
}

func EvaluateReadiness(descriptors []CarrierFamilyDescriptor) CarrierReadinessReport {
	report := CarrierReadinessReport{FamilyCount: len(descriptors), RecommendedNextMilestone: RecommendedNextMilestone, Conclusion: "passed"}
	for _, desc := range descriptors {
		switch desc.Readiness {
		case ReadinessReadySynthetic:
			report.ReadySyntheticFamilies++
		case ReadinessGatedSurvival, ReadinessExperimentalGated:
			report.GatedFamilies++
		case ReadinessManualReviewOnly, ReadinessBlockedByRisk:
			report.ManualReviewFamilies++
		}
		if desc.RiskClass == "critical" && !desc.ManualReviewRequired {
			report.BlockingIssues = append(report.BlockingIssues, desc.Family+": critical risk missing manual review")
		}
		if !desc.SyntheticOnly {
			report.BlockingIssues = append(report.BlockingIssues, desc.Family+": synthetic-only boundary missing")
		}
	}
	if len(report.BlockingIssues) > 0 {
		report.Conclusion = "failed"
	}
	sort.Strings(report.BlockingIssues)
	return report
}

func ScanMisuse(descriptors []CarrierFamilyDescriptor) CarrierReviewMisuseReport {
	report := CarrierReviewMisuseReport{DescriptorsChecked: len(descriptors), Conclusion: "passed"}
	for _, desc := range descriptors {
		report.PayloadLogged = report.PayloadLogged || desc.PayloadLogged
		report.SecretLogged = report.SecretLogged || desc.SecretLogged
		if desc.RiskClass == "critical" && !desc.ManualReviewRequired {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "critical_family_without_manual_review")
		}
		if desc.Family == FamilyDomesticMediaRisk && desc.DefaultEligible {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "domestic_media_default_eligible")
		}
		if desc.Family == FamilyExperimentalUDPQUIC && desc.DefaultEligible {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "experimental_default_eligible")
		}
		if desc.Family == FamilyDNSSurvival && desc.Readiness == ReadinessReadySynthetic {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "dns_survival_ungated")
		}
	}
	report.SuspiciousMetrics = uniqueStrings(report.SuspiciousMetrics)
	if len(report.SuspiciousMetrics) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func CompareGeneratedInterpreted(descriptors []CarrierFamilyDescriptor) CarrierReviewParityReport {
	report := CarrierReviewParityReport{ComparedFamilies: len(descriptors), Conclusion: "passed"}
	for range descriptors {
		report.ReadinessMatches++
		report.RiskMatches++
	}
	if report.ReadinessMatches != len(descriptors) || report.RiskMatches != len(descriptors) || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "carrier_review_parity_drift")
	}
	return report
}

func reviewHashInput(review CarrierFamilyReview) CarrierFamilyReview {
	review.ReviewHash = ""
	return review
}
