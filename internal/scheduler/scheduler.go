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

type StreamItem struct {
	StreamID     uint32
	Semantic     string
	PayloadBytes int
	Priority     string
	Blocked      bool
	Closed       bool
}

type StreamFlush struct {
	AtMillis int
	Items    []StreamItem
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

func PlanStreams(streamPolicy ir.StreamPolicy, policy ir.SchedulerPolicy, items []StreamItem) []StreamFlush {
	queue := make([]StreamItem, 0, len(items))
	for _, item := range items {
		if item.Blocked || item.Closed {
			continue
		}
		queue = append(queue, item)
	}
	switch streamPolicy.PriorityPolicy {
	case "interactive_first":
		sort.SliceStable(queue, func(i, j int) bool {
			if queue[i].Priority != queue[j].Priority {
				return queue[i].Priority == "interactive"
			}
			return queue[i].PayloadBytes < queue[j].PayloadBytes
		})
	case "smallest_pending_first":
		sort.SliceStable(queue, func(i, j int) bool {
			if queue[i].PayloadBytes == queue[j].PayloadBytes {
				return queue[i].StreamID < queue[j].StreamID
			}
			return queue[i].PayloadBytes < queue[j].PayloadBytes
		})
	case "weighted_round_robin":
		queue = roundRobin(queue)
	default:
		sort.SliceStable(queue, func(i, j int) bool { return queue[i].StreamID < queue[j].StreamID })
	}
	maxBatch := policy.MaxBatchBytes
	if maxBatch <= 0 {
		maxBatch = 32 * 1024
	}
	maxInFlight := policy.MaxInFlightFrames
	if maxInFlight <= 0 {
		maxInFlight = 4
	}
	flushes := []StreamFlush{}
	now := 0
	for len(queue) > 0 {
		flush := StreamFlush{AtMillis: now, Reason: streamPolicy.PriorityPolicy}
		for len(queue) > 0 && len(flush.Items) < maxInFlight && flush.Bytes+queue[0].PayloadBytes <= maxBatch {
			flush.Items = append(flush.Items, queue[0])
			flush.Bytes += queue[0].PayloadBytes
			queue = queue[1:]
		}
		if len(flush.Items) == 0 {
			flush.Items = append(flush.Items, queue[0])
			flush.Bytes = queue[0].PayloadBytes
			queue = queue[1:]
		}
		flushes = append(flushes, flush)
		now += policy.FlushIntervalMs
	}
	return flushes
}

func roundRobin(items []StreamItem) []StreamItem {
	byStream := map[uint32][]StreamItem{}
	order := []uint32{}
	for _, item := range items {
		if _, ok := byStream[item.StreamID]; !ok {
			order = append(order, item.StreamID)
		}
		byStream[item.StreamID] = append(byStream[item.StreamID], item)
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i] < order[j] })
	out := make([]StreamItem, 0, len(items))
	for len(out) < len(items) {
		progress := false
		for _, id := range order {
			queue := byStream[id]
			if len(queue) == 0 {
				continue
			}
			out = append(out, queue[0])
			byStream[id] = queue[1:]
			progress = true
		}
		if !progress {
			break
		}
	}
	return out
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
