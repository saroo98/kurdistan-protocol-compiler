// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

type WireFeatureCollapseReport struct {
	ProfileCount          int      `json:"profile_count"`
	ScenarioCount         int      `json:"scenario_count"`
	FeatureVectors        int      `json:"feature_vectors"`
	UniqueFeatureHashes   int      `json:"unique_feature_hashes"`
	UniqueFirstNShapes    int      `json:"unique_first_n_shapes"`
	UniquePhaseShapes     int      `json:"unique_phase_shapes"`
	UniqueFieldLayouts    int      `json:"unique_field_layouts"`
	UniqueMetadataClasses int      `json:"unique_metadata_classes"`
	SuspiciousMetrics     []string `json:"suspicious_metrics,omitempty"`
	DiversityScore        float64  `json:"diversity_score"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

func ScanCollapse(vectors []WireFeatureVector) WireFeatureCollapseReport {
	report := WireFeatureCollapseReport{FeatureVectors: len(vectors), Conclusion: "passed"}
	profiles := map[string]bool{}
	scenarios := map[string]bool{}
	featureHashes := map[string]bool{}
	firstN := map[string]bool{}
	phases := map[string]bool{}
	layouts := map[string]bool{}
	metadata := map[string]bool{}
	for _, vector := range vectors {
		profiles[vector.ProfileID] = true
		scenarios[vector.Scenario] = true
		featureHashes[vector.FeatureHash] = true
		firstN[vector.FirstNPacketShape] = true
		phases[vector.PhaseShape] = true
		layouts[vector.FieldLayoutClass] = true
		metadata[vector.MetadataExposure] = true
		report.PayloadLogged = report.PayloadLogged || vector.PayloadLogged
		report.SecretLogged = report.SecretLogged || vector.SecretLogged
	}
	report.ProfileCount = len(profiles)
	report.ScenarioCount = len(scenarios)
	report.UniqueFeatureHashes = len(featureHashes)
	report.UniqueFirstNShapes = len(firstN)
	report.UniquePhaseShapes = len(phases)
	report.UniqueFieldLayouts = len(layouts)
	report.UniqueMetadataClasses = len(metadata)
	if len(vectors) > 0 {
		report.DiversityScore = float64(report.UniqueFeatureHashes+report.UniqueFirstNShapes+report.UniquePhaseShapes+report.UniqueFieldLayouts+report.UniqueMetadataClasses) / float64(len(vectors)*5)
	}
	if len(vectors) > 1 && report.UniqueFeatureHashes <= 1 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "identical_feature_hash")
	}
	if report.ProfileCount > 1 && report.UniqueFirstNShapes <= 1 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "identical_firstn_shape")
	}
	if report.UniquePhaseShapes <= 1 && report.ScenarioCount > 1 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "scenario_insensitive_phase_shape")
	}
	if report.UniqueMetadataClasses <= 1 && report.ProfileCount > 1 {
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
