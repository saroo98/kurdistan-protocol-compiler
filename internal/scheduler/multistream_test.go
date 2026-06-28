package scheduler

import (
	"testing"

	"kurdistan/internal/ir"
)

func TestPlanStreamsInteractiveFirstAndSkipsBlocked(t *testing.T) {
	items := []StreamItem{
		{StreamID: 1, PayloadBytes: 1024, Priority: "bulk"},
		{StreamID: 2, PayloadBytes: 16, Priority: "interactive"},
		{StreamID: 3, PayloadBytes: 16, Priority: "bulk", Blocked: true},
	}
	flushes := PlanStreams(ir.StreamPolicy{PriorityPolicy: "interactive_first"}, ir.SchedulerPolicy{MaxBatchBytes: 4096, MaxInFlightFrames: 4}, items)
	if len(flushes) == 0 || len(flushes[0].Items) < 2 {
		t.Fatalf("unexpected stream flushes: %+v", flushes)
	}
	if flushes[0].Items[0].StreamID != 2 {
		t.Fatalf("interactive stream was not first: %+v", flushes[0].Items)
	}
	for _, item := range flushes[0].Items {
		if item.StreamID == 3 {
			t.Fatalf("blocked stream was scheduled: %+v", flushes[0].Items)
		}
	}
}

func TestPlanStreamsWeightedRoundRobinGivesAllStreamsProgress(t *testing.T) {
	items := []StreamItem{
		{StreamID: 1, PayloadBytes: 100, Priority: "bulk"},
		{StreamID: 1, PayloadBytes: 100, Priority: "bulk"},
		{StreamID: 2, PayloadBytes: 100, Priority: "interactive"},
		{StreamID: 2, PayloadBytes: 100, Priority: "interactive"},
	}
	flushes := PlanStreams(ir.StreamPolicy{PriorityPolicy: "weighted_round_robin"}, ir.SchedulerPolicy{MaxBatchBytes: 1000, MaxInFlightFrames: 8}, items)
	seen := map[uint32]bool{}
	for _, flush := range flushes {
		for _, item := range flush.Items {
			seen[item.StreamID] = true
		}
	}
	if !seen[1] || !seen[2] {
		t.Fatalf("weighted round robin did not schedule all streams: %+v", flushes)
	}
}
