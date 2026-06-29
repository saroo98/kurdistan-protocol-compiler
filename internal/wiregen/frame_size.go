// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import "kurdistan/internal/protocorpus"

func frameSizePlan(seed int64, entry protocorpus.ProtocolShapeEntry) FrameSizePlan {
	strategies := []string{"corpus_bucketed", "phase_bucketed", "first_flight_weighted", "control_weighted"}
	strategy := strategies[stableIndex(seed, "frame-size:"+entry.Name, len(strategies))]
	split := "single_payload"
	if entry.Family == protocorpus.FamilyStreamOriented || entry.Family == protocorpus.FamilyControlRich {
		split = "split_payload"
	}
	budget := []string{"none", "small", "medium"}[stableIndex(seed, "padding-budget:"+entry.Name, 3)]
	return FrameSizePlan{
		Strategy:      strategy,
		SizeBuckets:   append([]string(nil), entry.FrameSizeBuckets...),
		PaddingBudget: budget,
		PayloadSplit:  split,
	}
}
