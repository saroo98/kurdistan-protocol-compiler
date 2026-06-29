// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

const SchemaVersion = "wirefeatures-v1"

type WireFeatureVector struct {
	ProfileID           string   `json:"profile_id"`
	ProfileSeed         int      `json:"profile_seed"`
	Scenario            string   `json:"scenario"`
	Backend             string   `json:"backend"`
	PhaseShape          string   `json:"phase_shape"`
	FieldLayoutClass    string   `json:"field_layout_class"`
	FirstFlightBucket   string   `json:"first_flight_bucket"`
	FirstNPacketShape   string   `json:"first_n_packet_shape"`
	DirectionPattern    string   `json:"direction_pattern"`
	FrameSizeBuckets    []string `json:"frame_size_buckets"`
	FragmentRhythm      string   `json:"fragment_rhythm"`
	ControlRichness     string   `json:"control_richness"`
	MetadataExposure    string   `json:"metadata_exposure"`
	PayloadVisibility   string   `json:"payload_visibility"`
	SequenceBehavior    string   `json:"sequence_behavior"`
	BackpressurePattern string   `json:"backpressure_pattern"`
	ResetClosePattern   string   `json:"reset_close_pattern"`
	ErrorMappingPattern string   `json:"error_mapping_pattern"`
	ByteShapeHash       string   `json:"byte_shape_hash"`
	FeatureHash         string   `json:"feature_hash"`
	PayloadLogged       bool     `json:"payload_logged"`
	SecretLogged        bool     `json:"secret_logged"`
	WirePolicyID        string   `json:"wire_policy_id,omitempty"`
	WirePolicyHash      string   `json:"wire_policy_hash,omitempty"`
	WireSelectedFamily  string   `json:"wire_selected_family,omitempty"`
	WireCorpusEntry     string   `json:"wire_corpus_entry,omitempty"`
}

type FeatureExtractionReport struct {
	FixtureCount    int      `json:"fixture_count"`
	FeatureCount    int      `json:"feature_count"`
	ProfileCount    int      `json:"profile_count"`
	ScenarioCount   int      `json:"scenario_count"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	InvalidFeatures []string `json:"invalid_features,omitempty"`
	Conclusion      string   `json:"conclusion"`
}
