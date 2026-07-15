// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"fmt"
	"math"
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
	return r.commit(seq)
}

func (r *ReplayWindow) precheck(seq uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkLocked(seq)
}

func (r *ReplayWindow) commit(seq uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkLocked(seq); err != nil {
		return err
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

func (r *ReplayWindow) checkLocked(seq uint64) error {
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

const (
	ReplayPolicyOrderedOnlyV1    = "ordered_only"
	ReplayPolicyBoundedReorderV1 = "bounded_reorder"
	ReplayPolicyWindowedReplayV1 = "windowed_replay"
	replayWindowMinimumV1        = 2
	replayWindowMaximumV1        = 4096
)

// ReplayMetadataV1 is a read-only value snapshot. Numeric zero is independent
// from Initialized, so an accepted first sequence zero is representable.
type ReplayMetadataV1 struct {
	Policy      string
	WindowSize  uint32
	Initialized bool
	Highest     uint64
	SeenCount   int
}

// ReplayWindowV1 is the strict authentication-before-commit replay primitive.
// A caller may inspect plausibility before authentication, but only a successful
// authentication path may call CommitAuthenticated.
type ReplayWindowV1 struct {
	state *replayWindowStateV1
}

type replayWindowStateV1 struct {
	mu          sync.Mutex
	policy      string
	window      uint64
	initialized bool
	highest     uint64
	seen        map[uint64]struct{}
}

func NewReplayWindowV1(policy string, windowSize int) (*ReplayWindowV1, error) {
	if err := validateReplayPolicyV1(policy, windowSize); err != nil {
		return nil, err
	}
	return &ReplayWindowV1{
		state: &replayWindowStateV1{
			policy: policy, window: uint64(windowSize), seen: make(map[uint64]struct{}),
		},
	}, nil
}

func (r *ReplayWindowV1) Plausible(sequence uint64) error {
	if r == nil || r.state == nil {
		return ErrPolicyInvalid
	}
	state := r.state
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.checkV1Locked(sequence)
}

func (r *ReplayWindowV1) CommitAuthenticated(sequence uint64) error {
	if r == nil || r.state == nil {
		return ErrPolicyInvalid
	}
	state := r.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if err := state.checkV1Locked(sequence); err != nil {
		return err
	}
	state.seen[sequence] = struct{}{}
	if !state.initialized || sequence > state.highest {
		state.highest = sequence
	}
	state.initialized = true
	state.pruneV1Locked()
	return nil
}

func (r *ReplayWindowV1) MetadataV1() ReplayMetadataV1 {
	if r == nil || r.state == nil {
		return ReplayMetadataV1{}
	}
	state := r.state
	state.mu.Lock()
	defer state.mu.Unlock()
	return ReplayMetadataV1{
		Policy: state.policy, WindowSize: uint32(state.window), Initialized: state.initialized,
		Highest: state.highest, SeenCount: len(state.seen),
	}
}

func validateReplayPolicyV1(policy string, windowSize int) error {
	if windowSize < replayWindowMinimumV1 || windowSize > replayWindowMaximumV1 {
		return ErrPolicyInvalid
	}
	switch policy {
	case ReplayPolicyOrderedOnlyV1, ReplayPolicyBoundedReorderV1, ReplayPolicyWindowedReplayV1:
		return nil
	default:
		return ErrPolicyInvalid
	}
}

func (r *replayWindowStateV1) checkV1Locked(sequence uint64) error {
	if _, duplicate := r.seen[sequence]; duplicate {
		return ErrReplayDuplicate
	}
	switch r.policy {
	case ReplayPolicyOrderedOnlyV1:
		return r.checkOrderedV1Locked(sequence)
	case ReplayPolicyBoundedReorderV1:
		return r.checkBoundedV1Locked(sequence)
	case ReplayPolicyWindowedReplayV1:
		return r.checkWindowedV1Locked(sequence)
	default:
		return ErrPolicyInvalid
	}
}

func (r *replayWindowStateV1) checkOrderedV1Locked(sequence uint64) error {
	if !r.initialized {
		if sequence == 0 {
			return nil
		}
		if sequence <= r.window {
			return ErrReplayOutOfOrder
		}
		return ErrReplayTooFarFuture
	}
	if r.highest == math.MaxUint64 {
		return ErrReplayExhausted
	}
	next := r.highest + 1
	if sequence == next {
		return nil
	}
	if sequence < next {
		return ErrReplayStale
	}
	if next > math.MaxUint64-r.window || sequence <= next+r.window {
		return ErrReplayOutOfOrder
	}
	return ErrReplayTooFarFuture
}

func (r *replayWindowStateV1) checkBoundedV1Locked(sequence uint64) error {
	if !r.initialized {
		if sequence <= r.window {
			return nil
		}
		return ErrReplayTooFarFuture
	}
	lower := replayLowerBoundV1(r.highest, r.window)
	if sequence < lower {
		return ErrReplayStale
	}
	if sequence <= r.highest {
		return nil
	}
	if sequence-r.highest > r.window {
		return ErrReplayTooFarFuture
	}
	return nil
}

func (r *replayWindowStateV1) checkWindowedV1Locked(sequence uint64) error {
	// A standard sliding window accepts an arbitrary unseen first value and every
	// unseen forward jump. It is deliberately not bounded_reorder.
	if !r.initialized || sequence > r.highest {
		return nil
	}
	if sequence < replayLowerBoundV1(r.highest, r.window) {
		return ErrReplayStale
	}
	return nil
}

func replayLowerBoundV1(highest, window uint64) uint64 {
	if highest < window {
		return 0
	}
	return highest - window + 1
}

func (r *replayWindowStateV1) pruneV1Locked() {
	lower := replayLowerBoundV1(r.highest, r.window)
	for sequence := range r.seen {
		if sequence < lower {
			delete(r.seen, sequence)
		}
	}
}
