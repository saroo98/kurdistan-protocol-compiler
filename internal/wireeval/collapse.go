// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

type ObservableDiversityReport struct {
	DatasetVersion          string  `json:"dataset_version"`
	ProfileCount            int     `json:"profile_count"`
	ScenarioCount           int     `json:"scenario_count"`
	RecordCount             int     `json:"record_count"`
	UniqueFeatureHashes     int     `json:"unique_feature_hashes"`
	UniqueFirstNShapes      int     `json:"unique_first_n_shapes"`
	UniqueFamilies          int     `json:"unique_families"`
	UniquePhaseShapes       int     `json:"unique_phase_shapes"`
	UniqueFieldLayouts      int     `json:"unique_field_layouts"`
	UniqueMetadataClasses   int     `json:"unique_metadata_classes"`
	UniqueFragmentRhythms   int     `json:"unique_fragment_rhythms"`
	PaddingOnlyRecords      int     `json:"padding_only_records"`
	CollapsedRecords        int     `json:"collapsed_records"`
	ControlFailuresDetected int     `json:"control_failures_detected"`
	DiversityScore          float64 `json:"diversity_score"`
	PayloadLogged           bool    `json:"payload_logged"`
	SecretLogged            bool    `json:"secret_logged"`
	Conclusion              string  `json:"conclusion"`
}

func AnalyzeObservableDiversity(records []WireEvalRecord) ObservableDiversityReport {
	profiles, scenarios := map[int]bool{}, map[string]bool{}
	features, firstN, families := map[string]bool{}, map[string]bool{}, map[string]bool{}
	phases, layouts, metadata, fragments := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	report := ObservableDiversityReport{DatasetVersion: string(Version), RecordCount: len(records), Conclusion: "passed"}
	for _, record := range records {
		profiles[record.ProfileSeed] = true
		scenarios[record.Scenario] = true
		features[record.FeatureHash] = true
		firstN[record.FirstNShapeHash] = true
		families[record.SelectedFamily] = true
		phases[record.PhaseShape] = true
		layouts[record.FieldLayoutClass] = true
		metadata[record.MetadataExposure] = true
		fragments[record.FragmentRhythm] = true
		report.PayloadLogged = report.PayloadLogged || record.PayloadLogged
		report.SecretLogged = report.SecretLogged || record.SecretLogged
		if record.Label == LabelControlPaddingOnly {
			report.PaddingOnlyRecords++
		}
		if record.Label == LabelControlCollapsed || record.FirstNShapeHash == "fixed_firstn_shape" {
			report.CollapsedRecords++
			report.ControlFailuresDetected++
		}
	}
	report.ProfileCount = len(profiles)
	report.ScenarioCount = len(scenarios)
	report.UniqueFeatureHashes = len(features)
	report.UniqueFirstNShapes = len(firstN)
	report.UniqueFamilies = len(families)
	report.UniquePhaseShapes = len(phases)
	report.UniqueFieldLayouts = len(layouts)
	report.UniqueMetadataClasses = len(metadata)
	report.UniqueFragmentRhythms = len(fragments)
	if len(records) > 0 {
		report.DiversityScore = float64(report.UniqueFeatureHashes+report.UniqueFirstNShapes+report.UniqueFamilies+report.UniqueFragmentRhythms) / float64(len(records)+report.ProfileCount)
	}
	if report.PayloadLogged || report.SecretLogged || report.UniqueFeatureHashes < 2 || report.ControlFailuresDetected == 0 {
		report.Conclusion = "failed"
	}
	return report
}
