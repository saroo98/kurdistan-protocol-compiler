// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

type AuditSummary struct {
	Version            string                    `json:"version"`
	CorpusVersion      string                    `json:"corpus_version"`
	CorpusEntries      int                       `json:"corpus_entries"`
	FeatureVectors     int                       `json:"feature_vectors"`
	ProfileCount       int                       `json:"profile_count"`
	ScenarioCount      int                       `json:"scenario_count"`
	Comparison         CorpusComparisonReport    `json:"comparison"`
	Collapse           WireFeatureCollapseReport `json:"collapse"`
	Extraction         FeatureExtractionReport   `json:"extraction"`
	BaselineComparison BaselineCompareReport     `json:"baseline_comparison"`
	PayloadLogged      bool                      `json:"payload_logged"`
	SecretLogged       bool                      `json:"secret_logged"`
	Conclusion         string                    `json:"conclusion"`
}
