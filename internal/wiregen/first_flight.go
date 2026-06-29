// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import "kurdistan/internal/protocorpus"

func firstFlightPlan(seed int64, entry protocorpus.ProtocolShapeEntry) FirstFlightPlan {
	count := "count_2_3"
	if len(entry.Phases) <= 3 {
		count = "count_1"
	}
	if len(entry.Phases) >= 5 {
		count = "count_4_8"
	}
	sizes := append([]string(nil), entry.FrameSizeBuckets...)
	if len(sizes) == 0 {
		sizes = []string{entry.FirstFlightBucket}
	}
	if len(sizes) > 1 {
		rotate := stableIndex(seed, "first-flight:"+entry.Name, len(sizes))
		sizes = append(append([]string(nil), sizes[rotate:]...), sizes[:rotate]...)
	}
	if len(sizes) > 3 {
		sizes = sizes[:3]
	}
	return FirstFlightPlan{
		PacketCountBucket: count,
		DirectionPattern:  firstDirection(entry),
		SizeBuckets:       sizes,
		ControlIncluded:   hasPhase(entry, protocorpus.PhaseControl),
	}
}

func firstDirection(entry protocorpus.ProtocolShapeEntry) string {
	if len(entry.Phases) == 0 {
		return "unknown"
	}
	return entry.Phases[0].DirectionPattern
}
