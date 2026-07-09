// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

type WireEvalDatasetManifest struct {
	DatasetVersion       string         `json:"dataset_version"`
	CorpusVersion        string         `json:"corpus_version"`
	WiregenPolicyVersion string         `json:"wiregen_policy_version"`
	FeatureSchemaVersion string         `json:"feature_schema_version"`
	GeneratedAt          string         `json:"generated_at"`
	RecordCount          int            `json:"record_count"`
	ProfileCount         int            `json:"profile_count"`
	ScenarioCount        int            `json:"scenario_count"`
	SplitCounts          map[string]int `json:"split_counts"`
	LabelCounts          map[string]int `json:"label_counts"`
	PayloadLogged        bool           `json:"payload_logged"`
	SecretLogged         bool           `json:"secret_logged"`
	DatasetHash          string         `json:"dataset_hash"`
}

type Dataset struct {
	Manifest WireEvalDatasetManifest `json:"manifest"`
	Records  []WireEvalRecord        `json:"records"`
}

type BuildOptions struct {
	Seeds     []int
	Scenarios []string
	SplitMode string
	Backend   string
	Controls  bool
}

type SplitManifest struct {
	Mode         string              `json:"mode"`
	SplitCounts  map[string]int      `json:"split_counts"`
	ProfileSets  map[string][]int    `json:"profile_sets,omitempty"`
	ScenarioSets map[string][]string `json:"scenario_sets,omitempty"`
	FamilySets   map[string][]string `json:"family_sets,omitempty"`
	Passed       bool                `json:"passed"`
	Conclusion   string              `json:"conclusion"`
}
