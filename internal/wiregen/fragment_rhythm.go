// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import "kurdistan/internal/protocorpus"

func fragmentRhythmPlan(seed int64, entry protocorpus.ProtocolShapeEntry) FragmentRhythmPlan {
	strategy := entry.FragmentRhythm
	if strategy == "" {
		strategy = "fixed_fragment"
	}
	reorder := stableIndex(seed, "fragment-reorder:"+entry.Name, 4) == 0
	return FragmentRhythmPlan{
		Strategy:          strategy,
		FragmentBuckets:   append([]string(nil), entry.FrameSizeBuckets...),
		ReorderPermitted:  reorder,
		ReassemblyPattern: []string{"ordered", "bounded_out_of_order", "reset_clears"}[stableIndex(seed, "reassembly:"+entry.Name, 3)],
	}
}
