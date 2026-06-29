// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import "kurdistan/internal/protocorpus"

type PolicySummary struct {
	PolicyID            string   `json:"policy_id"`
	PolicyHash          string   `json:"policy_hash"`
	ProfileSeed         int      `json:"profile_seed"`
	SelectedFamily      string   `json:"selected_family"`
	SelectedCorpusEntry string   `json:"selected_corpus_entry"`
	PhaseShape          string   `json:"phase_shape"`
	FieldLayoutClass    string   `json:"field_layout_class"`
	FirstFlightClass    string   `json:"first_flight_class"`
	FirstNShapeClass    string   `json:"first_n_shape_class"`
	FrameSizeBuckets    []string `json:"frame_size_buckets"`
	FragmentRhythm      string   `json:"fragment_rhythm"`
	ControlRichness     string   `json:"control_richness"`
	MetadataExposure    string   `json:"metadata_exposure"`
	LengthAloneEnabled  bool     `json:"length_alone_enabled"`
	PayloadLogged       bool     `json:"payload_logged"`
	SecretLogged        bool     `json:"secret_logged"`
}

func SummarizePolicy(policy WireShapePolicy) PolicySummary {
	return PolicySummary{
		PolicyID:            policy.PolicyID,
		PolicyHash:          policy.PolicyHash,
		ProfileSeed:         policy.ProfileSeed,
		SelectedFamily:      string(policy.SelectedFamily),
		SelectedCorpusEntry: policy.SelectedCorpusEntry,
		PhaseShape:          phaseShape(policy.PhasePlan),
		FieldLayoutClass:    policy.FieldLayoutPlan.LayoutClass,
		FirstFlightClass:    policy.FirstFlightPlan.PacketCountBucket + "/" + policy.FirstFlightPlan.DirectionPattern,
		FirstNShapeClass:    policy.FirstNPlan.ShapeClass,
		FrameSizeBuckets:    append([]string(nil), policy.FrameSizePlan.SizeBuckets...),
		FragmentRhythm:      policy.FragmentRhythmPlan.Strategy,
		ControlRichness:     policy.ControlPlan.Richness,
		MetadataExposure:    policy.MetadataExposurePlan.ExposureClass,
		LengthAloneEnabled:  policy.LengthAlonePlan.Enabled,
	}
}

func shortFamily(family protocorpus.ProtocolFamily) string {
	value := string(family)
	if len(value) <= 18 {
		return value
	}
	return value[:18]
}
