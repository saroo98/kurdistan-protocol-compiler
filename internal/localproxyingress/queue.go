// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

type IngressQueueStats struct {
	EventsQueued      int  `json:"events_queued"`
	EventsDropped     int  `json:"events_dropped"`
	OverflowRejected  int  `json:"overflow_rejected"`
	DuplicateRejected int  `json:"duplicate_rejected"`
	MaxDepthObserved  int  `json:"max_depth_observed"`
	PayloadLogged     bool `json:"payload_logged"`
	SecretLogged      bool `json:"secret_logged"`
}

type IngressQueue struct {
	max    int
	seen   map[string]bool
	events []SyntheticIngressEvent
	Stats  IngressQueueStats
}

func NewQueue(max int) *IngressQueue {
	return &IngressQueue{max: max, seen: map[string]bool{}}
}

func (q *IngressQueue) Enqueue(event SyntheticIngressEvent) error {
	if q.seen[event.EventID] {
		q.Stats.DuplicateRejected++
		return ErrDuplicateEvent
	}
	if len(q.events) >= q.max {
		q.Stats.OverflowRejected++
		q.Stats.EventsDropped++
		return ErrQueueOverflow
	}
	q.seen[event.EventID] = true
	q.events = append(q.events, event)
	q.Stats.EventsQueued++
	if len(q.events) > q.Stats.MaxDepthObserved {
		q.Stats.MaxDepthObserved = len(q.events)
	}
	return nil
}

func (q *IngressQueue) Drain() []SyntheticIngressEvent {
	out := append([]SyntheticIngressEvent(nil), q.events...)
	q.events = nil
	return out
}
