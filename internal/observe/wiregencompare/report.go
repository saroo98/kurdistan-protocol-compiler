// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregencompare

type AuditSummary struct {
	Version            string                        `json:"version"`
	CorpusVersion      string                        `json:"corpus_version"`
	CorpusEntries      int                           `json:"corpus_entries"`
	Policies           int                           `json:"policies"`
	FeatureVectors     int                           `json:"feature_vectors"`
	ProfileCount       int                           `json:"profile_count"`
	ScenarioCount      int                           `json:"scenario_count"`
	Comparison         PolicyFeatureComparisonReport `json:"comparison"`
	Collapse           WireGenCollapseReport         `json:"collapse"`
	BaselineComparison BaselineCompareReport         `json:"baseline_comparison"`
	PayloadLogged      bool                          `json:"payload_logged"`
	SecretLogged       bool                          `json:"secret_logged"`
	Conclusion         string                        `json:"conclusion"`
}
