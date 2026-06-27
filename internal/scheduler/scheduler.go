package scheduler

import (
	"sort"

	"kurdistan/internal/ir"
)

type Item struct {
	Semantic     string
	PayloadBytes int
	Interactive  bool
}

type Flush struct {
	AtMillis int
	Items    []Item
	Bytes    int
	Reason   string
}

func Plan(policy ir.SchedulerPolicy, items []Item) []Flush {
	queue := append([]Item(nil), items...)
	switch policy.Mode {
	case "interactive_first":
		sort.SliceStable(queue, func(i, j int) bool {
			if queue[i].Interactive != queue[j].Interactive {
				return queue[i].Interactive
			}
			return queue[i].PayloadBytes < queue[j].PayloadBytes
		})
	case "bulk_first":
		sort.SliceStable(queue, func(i, j int) bool { return queue[i].PayloadBytes > queue[j].PayloadBytes })
	}

	flushes := []Flush{}
	inFlight := 0
	now := 0
	for len(queue) > 0 {
		batch := Flush{AtMillis: now, Reason: policy.Mode}
		for len(queue) > 0 && batch.Bytes+queue[0].PayloadBytes <= policy.MaxBatchBytes && inFlight < policy.MaxInFlightFrames {
			batch.Items = append(batch.Items, queue[0])
			batch.Bytes += queue[0].PayloadBytes
			queue = queue[1:]
			inFlight++
		}
		if len(batch.Items) == 0 {
			item := queue[0]
			queue = queue[1:]
			batch.Items = append(batch.Items, item)
			batch.Bytes = item.PayloadBytes
			inFlight++
		}
		flushes = append(flushes, batch)
		if inFlight >= policy.MaxInFlightFrames {
			inFlight = 0
		}
		now += policy.FlushIntervalMs
	}
	return flushes
}

func FragmentSizes(p *ir.Profile, payloadLen int) []int {
	if payloadLen <= 0 {
		return []int{0}
	}
	maxChunk := p.Scheduler.MaxBatchBytes
	if maxChunk <= 0 || maxChunk > p.Limits.MaxFrameBytes-512 {
		maxChunk = p.Limits.MaxFrameBytes - 512
	}
	switch p.FrameGrammar.FragmentationMode {
	case "fixed_size_chunks":
		maxChunk = min(maxChunk, 4096)
	case "bounded_variable_chunks":
		maxChunk = min(maxChunk, 6144)
	case "scheduler_controlled_chunks":
		maxChunk = min(maxChunk, p.Scheduler.MaxBatchBytes)
	default:
		maxChunk = min(maxChunk, 16*1024)
	}
	if maxChunk < 1 {
		maxChunk = 1
	}
	var sizes []int
	remaining := payloadLen
	for remaining > 0 {
		n := min(maxChunk, remaining)
		sizes = append(sizes, n)
		remaining -= n
	}
	return sizes
}
