// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregencompare

import (
	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregen"
)

type WireGenCollapseReport struct {
	ProfileCount          int      `json:"profile_count"`
	ScenarioCount         int      `json:"scenario_count"`
	PolicyCount           int      `json:"policy_count"`
	FeatureVectors        int      `json:"feature_vectors"`
	UniquePolicyHashes    int      `json:"unique_policy_hashes"`
	UniqueFamilies        int      `json:"unique_families"`
	UniqueFirstNShapes    int      `json:"unique_first_n_shapes"`
	UniqueFramePlans      int      `json:"unique_frame_plans"`
	UniqueFragmentRhythms int      `json:"unique_fragment_rhythms"`
	UniqueMetadataClasses int      `json:"unique_metadata_classes"`
	SuspiciousMetrics     []string `json:"suspicious_metrics,omitempty"`
	DiversityScore        float64  `json:"diversity_score"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

func ScanCollapse(policies []wiregen.WireShapePolicy, vectors []wirefeatures.WireFeatureVector) WireGenCollapseReport {
	report := WireGenCollapseReport{PolicyCount: len(policies), FeatureVectors: len(vectors), Conclusion: "passed"}
	policyHashes := map[string]bool{}
	families := map[string]bool{}
	firstN := map[string]bool{}
	framePlans := map[string]bool{}
	fragments := map[string]bool{}
	metadata := map[string]bool{}
	profiles := map[string]bool{}
	scenarios := map[string]bool{}
	for _, policy := range policies {
		policyHashes[policy.PolicyHash] = true
		families[string(policy.SelectedFamily)] = true
		firstN[wiregen.FirstNShapeHash(policy)] = true
		framePlans[safeHash(policy.FrameSizePlan.Strategy+":"+policy.FrameSizePlan.PayloadSplit+":"+policy.FrameSizePlan.PaddingBudget)] = true
		fragments[policy.FragmentRhythmPlan.Strategy] = true
		metadata[policy.MetadataExposurePlan.ExposureClass] = true
	}
	for _, vector := range vectors {
		profiles[vector.ProfileID] = true
		scenarios[vector.Scenario] = true
		report.PayloadLogged = report.PayloadLogged || vector.PayloadLogged
		report.SecretLogged = report.SecretLogged || vector.SecretLogged
	}
	report.ProfileCount = len(profiles)
	report.ScenarioCount = len(scenarios)
	report.UniquePolicyHashes = len(policyHashes)
	report.UniqueFamilies = len(families)
	report.UniqueFirstNShapes = len(firstN)
	report.UniqueFramePlans = len(framePlans)
	report.UniqueFragmentRhythms = len(fragments)
	report.UniqueMetadataClasses = len(metadata)
	if len(policies) > 0 {
		report.DiversityScore = float64(report.UniquePolicyHashes+report.UniqueFamilies+report.UniqueFirstNShapes+report.UniqueFramePlans+report.UniqueFragmentRhythms+report.UniqueMetadataClasses) / float64(len(policies)*6)
	}
	if len(policies) > 1 && report.UniquePolicyHashes <= 1 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "identical_policy_hash")
	}
	if len(policies) > 2 && report.UniqueFamilies < 2 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "single_corpus_family")
	}
	if len(policies) > 2 && report.UniqueFirstNShapes < 2 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "identical_first_n_plan")
	}
	if len(policies) > 2 && report.UniqueFramePlans < 2 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "identical_frame_size_plan")
	}
	if len(policies) > 2 && report.UniqueFragmentRhythms < 2 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "identical_fragment_rhythm")
	}
	if len(policies) > 2 && report.UniqueMetadataClasses < 2 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "identical_metadata_exposure")
	}
	if report.PayloadLogged || report.SecretLogged {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "trace_hygiene_failure")
	}
	if len(report.SuspiciousMetrics) > 0 {
		report.Conclusion = "failed"
	}
	return report
}
