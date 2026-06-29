// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import "kurdistan/internal/protocorpus"

func metadataExposurePlan(layout FieldLayoutPlan, entry protocorpus.ProtocolShapeEntry) MetadataExposurePlan {
	plan := MetadataExposurePlan{ExposureClass: entry.MetadataExposure}
	for _, field := range layout.FieldOrder {
		switch layout.VisibilityByField[field] {
		case protocorpus.VisibilityCleartext:
			plan.CleartextFields = append(plan.CleartextFields, field)
		case protocorpus.VisibilityEncrypted:
			plan.EncryptedFields = append(plan.EncryptedFields, field)
		case protocorpus.VisibilityDerived:
			plan.DerivedOnlyFields = append(plan.DerivedOnlyFields, field)
		}
	}
	return plan
}

func lengthAlonePlan(seed int64, entry protocorpus.ProtocolShapeEntry) LengthAlonePlan {
	enabled := entry.Family == protocorpus.FamilyLengthPrefixed || stableIndex(seed, "length-alone:"+entry.Name, 5) == 0
	trigger := "disabled"
	if enabled {
		trigger = []string{"pre_data", "control_only", "large_response"}[stableIndex(seed, "length-trigger:"+entry.Name, 3)]
	}
	return LengthAlonePlan{Enabled: enabled, TriggerClass: trigger}
}
