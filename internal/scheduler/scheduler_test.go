package scheduler

import (
	"testing"

	"kurdistan/internal/ir"
)

func TestMaxSpeedFlushesFastest(t *testing.T) {
	items := []Item{{PayloadBytes: 100}, {PayloadBytes: 100}}
	fast := Plan(ir.SchedulerPolicy{Mode: "max_speed", MaxBatchBytes: 100, FlushIntervalMs: 0, MaxInFlightFrames: 4, PriorityMode: "fifo"}, items)
	balanced := Plan(ir.SchedulerPolicy{Mode: "balanced", MaxBatchBytes: 100, FlushIntervalMs: 10, MaxInFlightFrames: 4, PriorityMode: "mixed"}, items)
	if fast[len(fast)-1].AtMillis >= balanced[len(balanced)-1].AtMillis {
		t.Fatal("max_speed did not flush faster")
	}
}

func TestBalancedBatchesMoreThanMaxSpeed(t *testing.T) {
	items := []Item{{PayloadBytes: 100}, {PayloadBytes: 100}, {PayloadBytes: 100}}
	fast := Plan(ir.SchedulerPolicy{Mode: "max_speed", MaxBatchBytes: 100, FlushIntervalMs: 0, MaxInFlightFrames: 4, PriorityMode: "fifo"}, items)
	balanced := Plan(ir.SchedulerPolicy{Mode: "balanced", MaxBatchBytes: 300, FlushIntervalMs: 10, MaxInFlightFrames: 4, PriorityMode: "mixed"}, items)
	if len(balanced) >= len(fast) {
		t.Fatal("balanced did not batch more")
	}
}

func TestInteractiveFirstPrioritizesSmallFrames(t *testing.T) {
	items := []Item{{PayloadBytes: 1000}, {PayloadBytes: 10, Interactive: true}}
	flushes := Plan(ir.SchedulerPolicy{Mode: "interactive_first", MaxBatchBytes: 2000, FlushIntervalMs: 1, MaxInFlightFrames: 4, PriorityMode: "small_first"}, items)
	if !flushes[0].Items[0].Interactive {
		t.Fatal("interactive item was not prioritized")
	}
}

func TestMaxBatchEnforced(t *testing.T) {
	items := []Item{{PayloadBytes: 100}, {PayloadBytes: 100}, {PayloadBytes: 100}}
	flushes := Plan(ir.SchedulerPolicy{Mode: "balanced", MaxBatchBytes: 200, FlushIntervalMs: 1, MaxInFlightFrames: 4, PriorityMode: "mixed"}, items)
	for _, flush := range flushes {
		if flush.Bytes > 200 {
			t.Fatal("batch exceeded max")
		}
	}
}
