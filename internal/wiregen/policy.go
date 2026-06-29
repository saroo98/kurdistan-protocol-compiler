// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import "kurdistan/internal/protocorpus"

const (
	PolicyVersion    = "wiregen-policy-v1"
	FixedGeneratedAt = "2026-06-29T00:00:00Z"
)

type WireShapePolicy struct {
	Version              string                     `json:"version"`
	CorpusVersion        string                     `json:"corpus_version"`
	PolicyID             string                     `json:"policy_id"`
	ProfileSeed          int                        `json:"profile_seed"`
	SelectedFamily       protocorpus.ProtocolFamily `json:"selected_family"`
	SelectedCorpusEntry  string                     `json:"selected_corpus_entry"`
	PhasePlan            PhasePlan                  `json:"phase_plan"`
	FieldLayoutPlan      FieldLayoutPlan            `json:"field_layout_plan"`
	FirstFlightPlan      FirstFlightPlan            `json:"first_flight_plan"`
	FirstNPlan           FirstNPlan                 `json:"first_n_plan"`
	FrameSizePlan        FrameSizePlan              `json:"frame_size_plan"`
	FragmentRhythmPlan   FragmentRhythmPlan         `json:"fragment_rhythm_plan"`
	ControlPlan          ControlPlan                `json:"control_plan"`
	MetadataExposurePlan MetadataExposurePlan       `json:"metadata_exposure_plan"`
	LengthAlonePlan      LengthAlonePlan            `json:"length_alone_plan"`
	PolicyHash           string                     `json:"policy_hash"`
}

type PhasePlan struct {
	PhaseSequence       []protocorpus.ProtocolPhase `json:"phase_sequence"`
	HandshakeRTTBucket  string                      `json:"handshake_rtt_bucket"`
	DirectionPattern    string                      `json:"direction_pattern"`
	ControlPhaseEnabled bool                        `json:"control_phase_enabled"`
}

type FieldLayoutPlan struct {
	LayoutClass       string                                                `json:"layout_class"`
	FieldOrder        []protocorpus.FieldKind                               `json:"field_order"`
	VisibilityByField map[protocorpus.FieldKind]protocorpus.VisibilityClass `json:"visibility_by_field"`
	SizeBucketByField map[protocorpus.FieldKind]string                      `json:"size_bucket_by_field"`
	PayloadPosition   string                                                `json:"payload_position"`
}

type FirstFlightPlan struct {
	PacketCountBucket string   `json:"packet_count_bucket"`
	DirectionPattern  string   `json:"direction_pattern"`
	SizeBuckets       []string `json:"size_buckets"`
	ControlIncluded   bool     `json:"control_included"`
}

type FirstNPlan struct {
	N              int    `json:"n"`
	ShapeClass     string `json:"shape_class"`
	DirectionClass string `json:"direction_class"`
	SizeClass      string `json:"size_class"`
}

type FrameSizePlan struct {
	Strategy      string   `json:"strategy"`
	SizeBuckets   []string `json:"size_buckets"`
	PaddingBudget string   `json:"padding_budget"`
	PayloadSplit  string   `json:"payload_split"`
}

type FragmentRhythmPlan struct {
	Strategy          string   `json:"strategy"`
	FragmentBuckets   []string `json:"fragment_buckets"`
	ReorderPermitted  bool     `json:"reorder_permitted"`
	ReassemblyPattern string   `json:"reassembly_pattern"`
}

type ControlPlan struct {
	Richness        string `json:"richness"`
	PreDataControls int    `json:"pre_data_controls"`
	InterleaveClass string `json:"interleave_class"`
	CloseClass      string `json:"close_class"`
	ResetClass      string `json:"reset_class"`
}

type MetadataExposurePlan struct {
	ExposureClass     string                  `json:"exposure_class"`
	CleartextFields   []protocorpus.FieldKind `json:"cleartext_fields"`
	EncryptedFields   []protocorpus.FieldKind `json:"encrypted_fields"`
	DerivedOnlyFields []protocorpus.FieldKind `json:"derived_only_fields"`
}

type LengthAlonePlan struct {
	Enabled      bool   `json:"enabled"`
	TriggerClass string `json:"trigger_class"`
}
