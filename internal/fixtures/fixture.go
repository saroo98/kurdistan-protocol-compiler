// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

const (
	SchemaVersion = "bytepath-fixture-v1"
	BackendLab    = "interpreted"
	BackendGen    = "generated"
)

type FixtureKind string

const (
	FixtureBytePath       FixtureKind = "byte_path"
	FixtureMalformedBytes FixtureKind = "malformed_bytes"
	FixtureParity         FixtureKind = "parity"
	FixturePerformance    FixtureKind = "performance"
)

type FixtureEntry struct {
	Name           string      `json:"name"`
	Kind           FixtureKind `json:"kind"`
	ProfileID      string      `json:"profile_id,omitempty"`
	ProfileSeed    int         `json:"profile_seed,omitempty"`
	Scenario       string      `json:"scenario,omitempty"`
	Backend        string      `json:"backend,omitempty"`
	SummaryHash    string      `json:"summary_hash"`
	TraceHash      string      `json:"trace_hash"`
	ByteShapeHash  string      `json:"byte_shape_hash"`
	ExpectedResult string      `json:"expected_result"`
	PayloadLogged  bool        `json:"payload_logged"`
	SecretLogged   bool        `json:"secret_logged"`
}

type BytePathFixtureSummary struct {
	ProfileID            string   `json:"profile_id"`
	ProfileSeed          int      `json:"profile_seed"`
	Scenario             string   `json:"scenario"`
	Backend              string   `json:"backend"`
	FramesEncoded        int      `json:"frames_encoded"`
	FramesDecoded        int      `json:"frames_decoded"`
	FragmentsCreated     int      `json:"fragments_created"`
	FragmentsReassembled int      `json:"fragments_reassembled"`
	BytesWrittenBucket   string   `json:"bytes_written_bucket"`
	BytesReadBucket      string   `json:"bytes_read_bucket"`
	BackpressureEvents   int      `json:"backpressure_events"`
	SequenceRejected     int      `json:"sequence_rejected"`
	MalformedRejected    int      `json:"malformed_rejected"`
	CorruptionRejected   int      `json:"corruption_rejected"`
	ReplaysRejected      int      `json:"replays_rejected"`
	RuntimeStreamsMapped int      `json:"runtime_streams_mapped"`
	TargetErrors         int      `json:"target_errors"`
	TargetResets         int      `json:"target_resets"`
	SinkCompleted        bool     `json:"sink_completed"`
	PayloadLogged        bool     `json:"payload_logged"`
	SecretLogged         bool     `json:"secret_logged"`
	WirePolicyID         string   `json:"wire_policy_id,omitempty"`
	WirePolicyHash       string   `json:"wire_policy_hash,omitempty"`
	WireSelectedFamily   string   `json:"wire_selected_family,omitempty"`
	WireCorpusEntry      string   `json:"wire_corpus_entry,omitempty"`
	WirePhaseShape       string   `json:"wire_phase_shape,omitempty"`
	WireFieldLayoutClass string   `json:"wire_field_layout_class,omitempty"`
	WireFirstFlightClass string   `json:"wire_first_flight_class,omitempty"`
	WireFirstNShape      string   `json:"wire_first_n_shape,omitempty"`
	WireFrameSizeBuckets []string `json:"wire_frame_size_buckets,omitempty"`
	WireFragmentRhythm   string   `json:"wire_fragment_rhythm,omitempty"`
	WireControlRichness  string   `json:"wire_control_richness,omitempty"`
	WireMetadataExposure string   `json:"wire_metadata_exposure,omitempty"`
}

type ByteShapeSummary struct {
	Scenario             string `json:"scenario"`
	Backend              string `json:"backend"`
	FramesEncoded        int    `json:"frames_encoded"`
	FramesDecoded        int    `json:"frames_decoded"`
	FragmentsCreated     int    `json:"fragments_created"`
	FragmentsReassembled int    `json:"fragments_reassembled"`
	BytesWrittenBucket   string `json:"bytes_written_bucket"`
	BytesReadBucket      string `json:"bytes_read_bucket"`
	BackpressureBucket   string `json:"backpressure_bucket"`
	SequenceRejected     int    `json:"sequence_rejected"`
	MalformedRejected    int    `json:"malformed_rejected"`
	CorruptionRejected   int    `json:"corruption_rejected"`
	ReplaysRejected      int    `json:"replays_rejected"`
	WirePolicyHash       string `json:"wire_policy_hash,omitempty"`
	WireFirstNShape      string `json:"wire_first_n_shape,omitempty"`
	WireFragmentRhythm   string `json:"wire_fragment_rhythm,omitempty"`
	WireMetadataExposure string `json:"wire_metadata_exposure,omitempty"`
}

type ManifestOptions struct {
	FixtureSet     string
	Backend        string
	GeneratedAt    string
	ProfileSeeds   []int
	ScenarioNames  []string
	BackendVersion string
}

func DefaultSeeds() []int {
	return []int{12345, 12346, 12347}
}

func DefaultScenarios() []string {
	return []string{
		"byte_single_flow_echo",
		"byte_many_small_flows",
		"byte_large_flow_fragmented",
		"byte_mixed_flows",
		"byte_reset_isolation",
		"byte_corruption_rejection",
		"byte_replay_rejection",
	}
}

func FixedGeneratedAt() string {
	return "2026-06-29T00:00:00Z"
}
