// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

func ControlRecords(source []WireEvalRecord) []WireEvalRecord {
	if len(source) == 0 {
		return nil
	}
	templates := []struct {
		label    WireEvalLabel
		scenario string
		mutate   func(*WireEvalRecord, int)
	}{
		{LabelControlCollapsed, "control_collapsed_fixed_shape", func(r *WireEvalRecord, _ int) {
			r.FirstNShapeHash = "fixed_firstn_shape"
			r.FeatureHash = "fixed_feature_hash"
			r.FragmentRhythm = "fixed_fragment"
			r.MetadataExposure = "fixed_metadata"
		}},
		{LabelControlPaddingOnly, "control_padding_only_variation", func(r *WireEvalRecord, i int) {
			r.FirstNShapeHash = "fixed_firstn_shape"
			r.FragmentRhythm = "fixed_fragment"
			r.MetadataExposure = "fixed_metadata"
			r.FrameSizeBuckets = []string{[]string{"size_33_64", "size_65_128", "size_129_256"}[i%3]}
			r.FeatureHash = "padding_only_" + r.FrameSizeBuckets[0]
		}},
		{LabelControlFixedShape, "control_fixed_firstn_shape", func(r *WireEvalRecord, i int) {
			r.FirstNShapeHash = "fixed_firstn_shape"
			r.FeatureHash = HashValue(r.ProfileID + r.Scenario + string(r.Label) + string(rune('a'+i)))
		}},
		{LabelControlNoise, "control_random_bucket_noise", func(r *WireEvalRecord, i int) {
			r.SelectedFamily = "control_noise"
			r.FrameSizeBuckets = []string{[]string{"size_4_8", "size_17_32", "size_257_512"}[i%3]}
			r.FeatureHash = HashValue(r.RecordID + ":noise")
		}},
	}
	out := make([]WireEvalRecord, 0, len(templates)*min(4, len(source)))
	limit := min(4, len(source))
	for ti, template := range templates {
		for i := 0; i < limit; i++ {
			r := source[i]
			r.DatasetVersion = string(Version)
			r.Label = template.label
			r.Split = SplitHoldout
			r.Scenario = template.scenario
			r.Backend = "control"
			r.ProfileID = "control-profile-" + string(rune('a'+ti)) + "-" + string(rune('a'+i))
			template.mutate(&r, i)
			r.ByteShapeHash = HashValue(r.FeatureHash + ":byte_shape")
			r.RecordID = StableRecordID(r)
			out = append(out, r)
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
