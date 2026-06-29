// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import (
	"strings"

	"kurdistan/internal/ir"
	"kurdistan/internal/protocorpus"
)

func FirstNShapeHash(policy WireShapePolicy) string {
	hash, err := HashValue(policy.FirstNPlan)
	if err != nil {
		return "firstn_hash_error"
	}
	return hash
}

func FragmentPolicyFor(policy WireShapePolicy) string {
	switch policy.FragmentRhythmPlan.Strategy {
	case "no_fragment", "fixed_fragment", "profile_bucket_fragment", "carrier_aware_fragment", "backpressure_aware_fragment":
		return policy.FragmentRhythmPlan.Strategy
	case "randomized_bucket_fragment":
		return "profile_bucket_fragment"
	default:
		if strings.Contains(policy.FragmentRhythmPlan.Strategy, "large") {
			return "carrier_aware_fragment"
		}
		return "fixed_fragment"
	}
}

func ByteCountForBucket(bucket string) int {
	switch bucket {
	case "size_1_3":
		return 3
	case "size_4_8":
		return 8
	case "size_9_16":
		return 16
	case "size_17_32":
		return 32
	case "size_33_64":
		return 64
	case "size_65_128":
		return 128
	case "size_129_512":
		return 512
	case "size_513_1500":
		return 1500
	case "size_1501_4096":
		return 4096
	case "size_4097_plus":
		return 8192
	default:
		return 128
	}
}

func ToIRPolicy(policy WireShapePolicy) ir.WireShapePolicy {
	return ir.WireShapePolicy{
		Version:             policy.Version,
		CorpusVersion:       policy.CorpusVersion,
		PolicyID:            policy.PolicyID,
		ProfileSeed:         policy.ProfileSeed,
		SelectedFamily:      string(policy.SelectedFamily),
		SelectedCorpusEntry: policy.SelectedCorpusEntry,
		PhasePlan: ir.WirePhasePlan{
			PhaseSequence:       stringPhases(policy.PhasePlan.PhaseSequence),
			HandshakeRTTBucket:  policy.PhasePlan.HandshakeRTTBucket,
			DirectionPattern:    policy.PhasePlan.DirectionPattern,
			ControlPhaseEnabled: policy.PhasePlan.ControlPhaseEnabled,
		},
		FieldLayoutPlan: ir.WireFieldLayoutPlan{
			LayoutClass:       policy.FieldLayoutPlan.LayoutClass,
			FieldOrder:        stringFields(policy.FieldLayoutPlan.FieldOrder),
			VisibilityByField: stringVisibilityMap(policy.FieldLayoutPlan.VisibilityByField),
			SizeBucketByField: stringSizeMap(policy.FieldLayoutPlan.SizeBucketByField),
			PayloadPosition:   policy.FieldLayoutPlan.PayloadPosition,
		},
		FirstFlightPlan: ir.WireFirstFlightPlan{
			PacketCountBucket: policy.FirstFlightPlan.PacketCountBucket,
			DirectionPattern:  policy.FirstFlightPlan.DirectionPattern,
			SizeBuckets:       append([]string(nil), policy.FirstFlightPlan.SizeBuckets...),
			ControlIncluded:   policy.FirstFlightPlan.ControlIncluded,
		},
		FirstNPlan: ir.WireFirstNPlan{
			N:              policy.FirstNPlan.N,
			ShapeClass:     policy.FirstNPlan.ShapeClass,
			DirectionClass: policy.FirstNPlan.DirectionClass,
			SizeClass:      policy.FirstNPlan.SizeClass,
		},
		FrameSizePlan: ir.WireFrameSizePlan{
			Strategy:      policy.FrameSizePlan.Strategy,
			SizeBuckets:   append([]string(nil), policy.FrameSizePlan.SizeBuckets...),
			PaddingBudget: policy.FrameSizePlan.PaddingBudget,
			PayloadSplit:  policy.FrameSizePlan.PayloadSplit,
		},
		FragmentRhythmPlan: ir.WireFragmentRhythmPlan{
			Strategy:          policy.FragmentRhythmPlan.Strategy,
			FragmentBuckets:   append([]string(nil), policy.FragmentRhythmPlan.FragmentBuckets...),
			ReorderPermitted:  policy.FragmentRhythmPlan.ReorderPermitted,
			ReassemblyPattern: policy.FragmentRhythmPlan.ReassemblyPattern,
		},
		ControlPlan: ir.WireControlPlan{
			Richness:        policy.ControlPlan.Richness,
			PreDataControls: policy.ControlPlan.PreDataControls,
			InterleaveClass: policy.ControlPlan.InterleaveClass,
			CloseClass:      policy.ControlPlan.CloseClass,
			ResetClass:      policy.ControlPlan.ResetClass,
		},
		MetadataExposurePlan: ir.WireMetadataExposurePlan{
			ExposureClass:     policy.MetadataExposurePlan.ExposureClass,
			CleartextFields:   stringFields(policy.MetadataExposurePlan.CleartextFields),
			EncryptedFields:   stringFields(policy.MetadataExposurePlan.EncryptedFields),
			DerivedOnlyFields: stringFields(policy.MetadataExposurePlan.DerivedOnlyFields),
		},
		LengthAlonePlan: ir.WireLengthAlonePlan{
			Enabled:      policy.LengthAlonePlan.Enabled,
			TriggerClass: policy.LengthAlonePlan.TriggerClass,
		},
		PolicyHash: policy.PolicyHash,
	}
}

func FromIRPolicy(policy ir.WireShapePolicy) WireShapePolicy {
	return WireShapePolicy{
		Version:             policy.Version,
		CorpusVersion:       policy.CorpusVersion,
		PolicyID:            policy.PolicyID,
		ProfileSeed:         policy.ProfileSeed,
		SelectedFamily:      protocorpus.ProtocolFamily(policy.SelectedFamily),
		SelectedCorpusEntry: policy.SelectedCorpusEntry,
		PhasePlan: PhasePlan{
			PhaseSequence:       protocolPhases(policy.PhasePlan.PhaseSequence),
			HandshakeRTTBucket:  policy.PhasePlan.HandshakeRTTBucket,
			DirectionPattern:    policy.PhasePlan.DirectionPattern,
			ControlPhaseEnabled: policy.PhasePlan.ControlPhaseEnabled,
		},
		FieldLayoutPlan: FieldLayoutPlan{
			LayoutClass:       policy.FieldLayoutPlan.LayoutClass,
			FieldOrder:        protocolFields(policy.FieldLayoutPlan.FieldOrder),
			VisibilityByField: protocolVisibilityMap(policy.FieldLayoutPlan.VisibilityByField),
			SizeBucketByField: protocolSizeMap(policy.FieldLayoutPlan.SizeBucketByField),
			PayloadPosition:   policy.FieldLayoutPlan.PayloadPosition,
		},
		FirstFlightPlan: FirstFlightPlan{
			PacketCountBucket: policy.FirstFlightPlan.PacketCountBucket,
			DirectionPattern:  policy.FirstFlightPlan.DirectionPattern,
			SizeBuckets:       append([]string(nil), policy.FirstFlightPlan.SizeBuckets...),
			ControlIncluded:   policy.FirstFlightPlan.ControlIncluded,
		},
		FirstNPlan: FirstNPlan{
			N:              policy.FirstNPlan.N,
			ShapeClass:     policy.FirstNPlan.ShapeClass,
			DirectionClass: policy.FirstNPlan.DirectionClass,
			SizeClass:      policy.FirstNPlan.SizeClass,
		},
		FrameSizePlan: FrameSizePlan{
			Strategy:      policy.FrameSizePlan.Strategy,
			SizeBuckets:   append([]string(nil), policy.FrameSizePlan.SizeBuckets...),
			PaddingBudget: policy.FrameSizePlan.PaddingBudget,
			PayloadSplit:  policy.FrameSizePlan.PayloadSplit,
		},
		FragmentRhythmPlan: FragmentRhythmPlan{
			Strategy:          policy.FragmentRhythmPlan.Strategy,
			FragmentBuckets:   append([]string(nil), policy.FragmentRhythmPlan.FragmentBuckets...),
			ReorderPermitted:  policy.FragmentRhythmPlan.ReorderPermitted,
			ReassemblyPattern: policy.FragmentRhythmPlan.ReassemblyPattern,
		},
		ControlPlan: ControlPlan{
			Richness:        policy.ControlPlan.Richness,
			PreDataControls: policy.ControlPlan.PreDataControls,
			InterleaveClass: policy.ControlPlan.InterleaveClass,
			CloseClass:      policy.ControlPlan.CloseClass,
			ResetClass:      policy.ControlPlan.ResetClass,
		},
		MetadataExposurePlan: MetadataExposurePlan{
			ExposureClass:     policy.MetadataExposurePlan.ExposureClass,
			CleartextFields:   protocolFields(policy.MetadataExposurePlan.CleartextFields),
			EncryptedFields:   protocolFields(policy.MetadataExposurePlan.EncryptedFields),
			DerivedOnlyFields: protocolFields(policy.MetadataExposurePlan.DerivedOnlyFields),
		},
		LengthAlonePlan: LengthAlonePlan{
			Enabled:      policy.LengthAlonePlan.Enabled,
			TriggerClass: policy.LengthAlonePlan.TriggerClass,
		},
		PolicyHash: policy.PolicyHash,
	}
}

func stringPhases(values []protocorpus.ProtocolPhase) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func protocolPhases(values []string) []protocorpus.ProtocolPhase {
	out := make([]protocorpus.ProtocolPhase, 0, len(values))
	for _, value := range values {
		out = append(out, protocorpus.ProtocolPhase(value))
	}
	return out
}

func stringFields(values []protocorpus.FieldKind) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func protocolFields(values []string) []protocorpus.FieldKind {
	out := make([]protocorpus.FieldKind, 0, len(values))
	for _, value := range values {
		out = append(out, protocorpus.FieldKind(value))
	}
	return out
}

func stringVisibilityMap(values map[protocorpus.FieldKind]protocorpus.VisibilityClass) map[string]string {
	out := map[string]string{}
	for key, value := range values {
		out[string(key)] = string(value)
	}
	return out
}

func protocolVisibilityMap(values map[string]string) map[protocorpus.FieldKind]protocorpus.VisibilityClass {
	out := map[protocorpus.FieldKind]protocorpus.VisibilityClass{}
	for key, value := range values {
		out[protocorpus.FieldKind(key)] = protocorpus.VisibilityClass(value)
	}
	return out
}

func stringSizeMap(values map[protocorpus.FieldKind]string) map[string]string {
	out := map[string]string{}
	for key, value := range values {
		out[string(key)] = value
	}
	return out
}

func protocolSizeMap(values map[string]string) map[protocorpus.FieldKind]string {
	out := map[protocorpus.FieldKind]string{}
	for key, value := range values {
		out[protocorpus.FieldKind(key)] = value
	}
	return out
}
