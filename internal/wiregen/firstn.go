// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import "kurdistan/internal/protocorpus"

func firstNPlan(seed int64, entry protocorpus.ProtocolShapeEntry, first FirstFlightPlan) FirstNPlan {
	sizeClass := "mixed"
	if len(first.SizeBuckets) == 1 {
		sizeClass = "small"
	}
	if stableIndex(seed, "firstn-size:"+entry.Name, 3) == 2 {
		sizeClass = "large"
	}
	return FirstNPlan{
		N:              4,
		ShapeClass:     entry.FirstNPacketBucket + "_" + shortFamily(entry.Family),
		DirectionClass: first.DirectionPattern,
		SizeClass:      sizeClass,
	}
}
