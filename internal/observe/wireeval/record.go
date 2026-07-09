// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

type DatasetVersion string
type DatasetSplit string
type WireEvalLabel string

const (
	Version          DatasetVersion = "wireeval-v1"
	FixedGeneratedAt                = "2026-06-30T00:00:00Z"

	SplitTrain   DatasetSplit = "train"
	SplitTest    DatasetSplit = "test"
	SplitOOD     DatasetSplit = "ood"
	SplitHoldout DatasetSplit = "holdout"

	LabelGeneratedKurdistan WireEvalLabel = "generated_kurdistan"
	LabelCorpusBaseline     WireEvalLabel = "corpus_baseline"
	LabelControlCollapsed   WireEvalLabel = "control_collapsed"
	LabelControlPaddingOnly WireEvalLabel = "control_padding_only"
	LabelControlFixedShape  WireEvalLabel = "control_fixed_shape"
	LabelControlNoise       WireEvalLabel = "control_random_bucket_noise"
)

type WireEvalRecord struct {
	DatasetVersion      string        `json:"dataset_version"`
	RecordID            string        `json:"record_id"`
	ProfileID           string        `json:"profile_id"`
	ProfileSeed         int           `json:"profile_seed"`
	Scenario            string        `json:"scenario"`
	Backend             string        `json:"backend"`
	Split               DatasetSplit  `json:"split"`
	Label               WireEvalLabel `json:"label"`
	SelectedFamily      string        `json:"selected_family"`
	SelectedCorpusEntry string        `json:"selected_corpus_entry"`
	PhaseShape          string        `json:"phase_shape"`
	FieldLayoutClass    string        `json:"field_layout_class"`
	FirstNShapeHash     string        `json:"first_n_shape_hash"`
	DirectionSequence   []string      `json:"direction_sequence"`
	PacketSizeBuckets   []string      `json:"packet_size_buckets"`
	FrameSizeBuckets    []string      `json:"frame_size_buckets"`
	FragmentRhythm      string        `json:"fragment_rhythm"`
	ControlRichness     string        `json:"control_richness"`
	MetadataExposure    string        `json:"metadata_exposure"`
	BackpressureClass   string        `json:"backpressure_class"`
	ResetCloseClass     string        `json:"reset_close_class"`
	ErrorMappingClass   string        `json:"error_mapping_class"`
	FeatureHash         string        `json:"feature_hash"`
	ByteShapeHash       string        `json:"byte_shape_hash"`
	PayloadLogged       bool          `json:"payload_logged"`
	SecretLogged        bool          `json:"secret_logged"`
}

func RequiredColumns() []string {
	return []string{
		"record_id", "profile_id", "profile_seed", "scenario", "backend",
		"split", "label", "selected_family", "selected_corpus_entry",
		"phase_shape", "field_layout_class", "first_n_shape_hash",
		"direction_sequence", "packet_size_buckets", "frame_size_buckets",
		"fragment_rhythm", "control_richness", "metadata_exposure",
		"backpressure_class", "reset_close_class", "error_mapping_class",
		"feature_hash", "byte_shape_hash",
	}
}

func ForbiddenColumns() []string {
	return []string{
		"payload", "raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes",
		"ciphertext", "plaintext", "packet_dump", "pcap", "capture_bytes",
		"destination_address", "proxy_ip", "server_ip", "domain", "sni",
		"host_header", "url", "ip_address", "secret", "derived_key", "nonce",
		"auth_tag", "proof_material",
	}
}
