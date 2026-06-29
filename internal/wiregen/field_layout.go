// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import "kurdistan/internal/protocorpus"

func fieldLayoutPlan(seed int64, entry protocorpus.ProtocolShapeEntry) FieldLayoutPlan {
	plan := FieldLayoutPlan{
		LayoutClass:       layoutClass(entry, seed),
		VisibilityByField: map[protocorpus.FieldKind]protocorpus.VisibilityClass{},
		SizeBucketByField: map[protocorpus.FieldKind]string{},
		PayloadPosition:   "absent",
	}
	seen := map[protocorpus.FieldKind]bool{}
	for _, phase := range entry.Phases {
		for _, field := range phase.Fields {
			if !seen[field.Kind] {
				plan.FieldOrder = append(plan.FieldOrder, field.Kind)
				seen[field.Kind] = true
			}
			plan.VisibilityByField[field.Kind] = field.Visibility
			plan.SizeBucketByField[field.Kind] = field.SizeBucket
			if field.Kind == protocorpus.FieldPayload {
				plan.PayloadPosition = field.PositionBucket
			}
		}
	}
	if len(plan.FieldOrder) > 1 {
		rotate := stableIndex(seed, "field-order:"+entry.Name, len(plan.FieldOrder))
		plan.FieldOrder = append(append([]protocorpus.FieldKind(nil), plan.FieldOrder[rotate:]...), plan.FieldOrder[:rotate]...)
	}
	return plan
}

func layoutClass(entry protocorpus.ProtocolShapeEntry, seed int64) string {
	switch entry.Family {
	case protocorpus.FamilyLengthPrefixed:
		return "length_prefix_visible"
	case protocorpus.FamilyMessageOriented:
		return "message_boundary_visible"
	case protocorpus.FamilyFullyEncrypted:
		return "opaque_encrypted_fields"
	case protocorpus.FamilyControlRich:
		return "control_header_mixed"
	default:
		if stableIndex(seed, "layout:"+entry.Name, 2) == 0 {
			return "compact_ordered_fields"
		}
		return "split_ordered_fields"
	}
}
