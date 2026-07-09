// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"fmt"
	"sync"
)

type ReplayWindow struct {
	mu         sync.Mutex
	WindowSize int
	Policy     string
	highest    uint64
	seen       map[uint64]bool
}

func NewReplayWindow(policy string, windowSize int) *ReplayWindow {
	if policy == "" {
		policy = "ordered_only"
	}
	if windowSize <= 0 {
		windowSize = 64
	}
	return &ReplayWindow{Policy: policy, WindowSize: windowSize, seen: map[uint64]bool{}}
}

func (r *ReplayWindow) Accept(seq uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if seq == 0 {
		return fmt.Errorf("%w: sequence zero", ErrReplay)
	}
	if r.seen[seq] {
		return fmt.Errorf("%w: duplicate sequence", ErrReplay)
	}
	switch r.Policy {
	case "ordered_only", "strict_no_reorder":
		if seq != r.highest+1 {
			return fmt.Errorf("%w: out-of-order sequence", ErrReplay)
		}
	case "bounded_reorder", "windowed_replay":
		if r.highest == 0 {
			if seq > uint64(r.WindowSize) {
				return fmt.Errorf("%w: future sequence outside window", ErrReplay)
			}
		} else {
			if seq > r.highest+uint64(r.WindowSize) {
				return fmt.Errorf("%w: future sequence outside window", ErrReplay)
			}
			if seq+uint64(r.WindowSize) <= r.highest {
				return fmt.Errorf("%w: old sequence outside window", ErrReplay)
			}
		}
	default:
		return fmt.Errorf("%w: unknown replay policy %q", ErrInvalidConfig, r.Policy)
	}
	r.seen[seq] = true
	if seq > r.highest {
		r.highest = seq
	}
	for old := range r.seen {
		if old+uint64(r.WindowSize) <= r.highest {
			delete(r.seen, old)
		}
	}
	return nil
}

func (r *ReplayWindow) Metadata() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return map[string]any{
		"policy":      r.Policy,
		"window_size": r.WindowSize,
		"highest":     r.highest,
		"seen_count":  len(r.seen),
	}
}
