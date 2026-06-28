package scheduler

import (
	"testing"

	"kurdistan/internal/ir"
)

func BenchmarkPlanStreamsFour(b *testing.B) {
	benchmarkPlanStreams(b, 4)
}

func BenchmarkPlanStreamsSixteen(b *testing.B) {
	benchmarkPlanStreams(b, 16)
}

func benchmarkPlanStreams(b *testing.B, streams int) {
	items := make([]StreamItem, 0, streams*2)
	for id := 1; id <= streams; id++ {
		priority := "bulk"
		if id%2 == 0 {
			priority = "interactive"
		}
		items = append(items,
			StreamItem{StreamID: uint32(id), PayloadBytes: 256, Priority: priority},
			StreamItem{StreamID: uint32(id), PayloadBytes: 512, Priority: priority},
		)
	}
	streamPolicy := ir.StreamPolicy{PriorityPolicy: "weighted_round_robin"}
	policy := ir.SchedulerPolicy{MaxBatchBytes: 4096, MaxInFlightFrames: 16}
	for i := 0; i < b.N; i++ {
		_ = PlanStreams(streamPolicy, policy, items)
	}
}
