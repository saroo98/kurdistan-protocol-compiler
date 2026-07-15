// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"sync"
	"testing"
)

func TestReplayV1LegacyCharacterization(t *testing.T) {
	t.Run("empty-policy-positive-window", func(t *testing.T) {
		defaults := NewReplayWindow("", 7)
		if defaults.Policy != "ordered_only" || defaults.WindowSize != 7 {
			t.Fatalf("legacy empty policy = (%q,%d)", defaults.Policy, defaults.WindowSize)
		}
	})
	for _, tc := range []struct {
		name   string
		window int
	}{{"explicit-policy-zero-window", 0}, {"explicit-policy-negative-window", -1}} {
		t.Run(tc.name, func(t *testing.T) {
			defaults := NewReplayWindow("bounded_reorder", tc.window)
			if defaults.Policy != "bounded_reorder" || defaults.WindowSize != 64 {
				t.Fatalf("legacy explicit policy/window %d = (%q,%d)", tc.window, defaults.Policy, defaults.WindowSize)
			}
		})
	}

	tests := []struct {
		name  string
		make  func() *ReplayWindow
		seq   uint64
		want  string
		class error
	}{
		{"zero", func() *ReplayWindow { return NewReplayWindow("ordered_only", 4) }, 0, "replay rejected: sequence zero", ErrReplay},
		{"ordered", func() *ReplayWindow { return NewReplayWindow("ordered_only", 4) }, 2, "replay rejected: out-of-order sequence", ErrReplay},
		{"future", func() *ReplayWindow { return NewReplayWindow("windowed_replay", 4) }, 99, "replay rejected: future sequence outside window", ErrReplay},
		{"unknown", func() *ReplayWindow { return NewReplayWindow("unknown", 4) }, 1, `invalid security config: unknown replay policy "unknown"`, ErrInvalidConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.make().Accept(tt.seq)
			if !errors.Is(err, tt.class) || err.Error() != tt.want {
				t.Fatalf("error = %v, want %q class %v", err, tt.want, tt.class)
			}
		})
	}

	duplicate := NewReplayWindow("windowed_replay", 4)
	if err := duplicate.Accept(1); err != nil {
		t.Fatal(err)
	}
	if err := duplicate.Accept(1); !errors.Is(err, ErrReplay) || err.Error() != "replay rejected: duplicate sequence" {
		t.Fatalf("duplicate error = %v", err)
	}

	old := NewReplayWindow("bounded_reorder", 4)
	if err := old.Accept(1); err != nil {
		t.Fatal(err)
	}
	if err := old.Accept(5); err != nil {
		t.Fatal(err)
	}
	if err := old.Accept(1); !errors.Is(err, ErrReplay) || err.Error() != "replay rejected: old sequence outside window" {
		t.Fatalf("old error = %v", err)
	}

	alias := NewReplayWindow("strict_no_reorder", 4)
	if err := alias.Accept(1); err != nil {
		t.Fatalf("strict_no_reorder legacy alias = %v", err)
	}

	overflow := NewReplayWindow("ordered_only", 4)
	overflow.highest = math.MaxUint64
	if err := overflow.Accept(1); !errors.Is(err, ErrReplay) || err.Error() != "replay rejected: out-of-order sequence" {
		t.Fatalf("legacy ordered overflow behavior = %v", err)
	}

	before := duplicate.Metadata()
	before["highest"] = uint64(99)
	if got := duplicate.Metadata(); reflect.DeepEqual(got, before) || got["highest"] != uint64(1) {
		t.Fatalf("metadata alias or value changed: got=%v mutated-copy=%v", got, before)
	}
}

func TestPolicyMatrixCoveringArrayOwnerWitnessReplaySentinelV1(t *testing.T) {
	caseIDs := map[string]string{ReplayPolicyOrderedOnlyV1: "pm-owner:replay/ordered_only", ReplayPolicyBoundedReorderV1: "pm-owner:replay/bounded_reorder", ReplayPolicyWindowedReplayV1: "pm-owner:replay/windowed_replay", "2": "pm-owner:replay_window/2", "4096": "pm-owner:replay_window/4096"}
	type row struct {
		name, policy string
		window       int
		setup        []uint64
		sequence     uint64
		want         error
	}
	rows := []row{
		{"ordered-duplicate/2", ReplayPolicyOrderedOnlyV1, 2, []uint64{0}, 0, ErrReplayDuplicate},
		{"ordered-out-of-order/4096", ReplayPolicyOrderedOnlyV1, 4096, []uint64{0}, 2, ErrReplayOutOfOrder},
		{"ordered-too-far/2", ReplayPolicyOrderedOnlyV1, 2, []uint64{0}, 4, ErrReplayTooFarFuture},
		{"ordered-stale/2", ReplayPolicyOrderedOnlyV1, 2, []uint64{0, 1, 2, 3}, 0, ErrReplayStale},
		{"bounded-duplicate/2", ReplayPolicyBoundedReorderV1, 2, []uint64{0, 2}, 2, ErrReplayDuplicate},
		{"bounded-too-far/4096", ReplayPolicyBoundedReorderV1, 4096, nil, 4097, ErrReplayTooFarFuture},
		{"windowed-stale/2", ReplayPolicyWindowedReplayV1, 2, []uint64{4}, 2, ErrReplayStale},
		{"windowed-duplicate/4096", ReplayPolicyWindowedReplayV1, 4096, []uint64{8192}, 8192, ErrReplayDuplicate},
	}
	for _, tc := range rows {
		id := caseIDs[tc.policy] + "/" + caseIDs[strconv.Itoa(tc.window)]
		t.Run(id+"/"+tc.name, func(t *testing.T) {
			replay, err := NewReplayWindowV1(tc.policy, tc.window)
			if err != nil || replay.MetadataV1().WindowSize != uint32(tc.window) {
				t.Fatalf("valid replay owner reached=%#v err=%v", replay.MetadataV1(), err)
			}
			for _, sequence := range tc.setup {
				if err := replay.CommitAuthenticated(sequence); err != nil {
					t.Fatalf("setup %d: %v", sequence, err)
				}
			}
			mutations := 1
			actual := replay.Plausible(tc.sequence)
			if mutations != 1 || actual == nil || !errors.Is(actual, tc.want) || actual.Error() != tc.want.Error() {
				t.Fatalf("mutations=%d sequence=%d error=%v want=%v", mutations, tc.sequence, actual, tc.want)
			}
		})
	}
	exhausted, err := NewReplayWindowV1(ReplayPolicyOrderedOnlyV1, 2)
	if err != nil {
		t.Fatal(err)
	}
	exhausted.state.initialized, exhausted.state.highest = true, math.MaxUint64
	actual := exhausted.Plausible(1)
	if actual == nil || !errors.Is(actual, ErrReplayExhausted) || actual.Error() != ErrReplayExhausted.Error() {
		t.Fatalf("exhausted precedence=%v", actual)
	}
}

func TestReplayV1SequenceZeroAndOrderedWindow(t *testing.T) {
	for _, window := range []int{2, 4, 32, 64, 128, 256, 4096} {
		for _, policy := range []string{ReplayPolicyOrderedOnlyV1, ReplayPolicyBoundedReorderV1, ReplayPolicyWindowedReplayV1} {
			t.Run(policy+"/window", func(t *testing.T) {
				replay, err := NewReplayWindowV1(policy, window)
				if err != nil {
					t.Fatal(err)
				}
				before := replay.MetadataV1()
				if err := replay.Plausible(0); err != nil {
					t.Fatalf("plausible zero = %v", err)
				}
				if got := replay.MetadataV1(); got != before {
					t.Fatalf("plausibility mutated state: before=%#v after=%#v", before, got)
				}
				if err := replay.CommitAuthenticated(0); err != nil {
					t.Fatalf("authenticated zero = %v", err)
				}
				metadata := replay.MetadataV1()
				if !metadata.Initialized || metadata.Highest != 0 || metadata.SeenCount != 1 || metadata.WindowSize != uint32(window) {
					t.Fatalf("zero metadata = %#v", metadata)
				}
				if err := replay.CommitAuthenticated(0); !errors.Is(err, ErrReplayDuplicate) || !errors.Is(err, ErrReplay) || err.Error() != "replay_duplicate" {
					t.Fatalf("zero duplicate = %v", err)
				}
			})
		}
	}

	ordered, err := NewReplayWindowV1(ReplayPolicyOrderedOnlyV1, 4)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= 4; sequence++ {
		if err := ordered.Plausible(sequence); !errors.Is(err, ErrReplayOutOfOrder) {
			t.Fatalf("uninitialized ordered sequence %d = %v", sequence, err)
		}
	}
	if err := ordered.Plausible(5); !errors.Is(err, ErrReplayTooFarFuture) {
		t.Fatalf("uninitialized ordered sequence 5 = %v", err)
	}
	for sequence := uint64(0); sequence <= 4; sequence++ {
		if err := ordered.CommitAuthenticated(sequence); err != nil {
			t.Fatalf("ordered commit %d = %v", sequence, err)
		}
	}
	for _, sequence := range []uint64{1, 4} {
		if err := ordered.Plausible(sequence); !errors.Is(err, ErrReplayDuplicate) {
			t.Fatalf("remembered duplicate %d = %v", sequence, err)
		}
	}
	if err := ordered.Plausible(0); !errors.Is(err, ErrReplayStale) {
		t.Fatalf("pruned ordered zero = %v", err)
	}
	if err := ordered.Plausible(5); err != nil {
		t.Fatalf("ordered exact next = %v", err)
	}
	for sequence := uint64(6); sequence <= 9; sequence++ {
		if err := ordered.Plausible(sequence); !errors.Is(err, ErrReplayOutOfOrder) {
			t.Fatalf("ordered future %d = %v", sequence, err)
		}
	}
	if err := ordered.Plausible(10); !errors.Is(err, ErrReplayTooFarFuture) {
		t.Fatalf("ordered future 10 = %v", err)
	}
}

func TestReplayV1FrozenWindowBoundaries(t *testing.T) {
	for _, windowSize := range []int{2, 4, 32, 64, 128, 256, 4096} {
		window := uint64(windowSize)
		t.Run(fmt.Sprintf("ordered/%d", windowSize), func(t *testing.T) {
			replay, err := NewReplayWindowV1(ReplayPolicyOrderedOnlyV1, windowSize)
			if err != nil {
				t.Fatal(err)
			}
			assertReplayResultV1(t, replay.Plausible(window), ErrReplayOutOfOrder)
			assertReplayResultV1(t, replay.Plausible(window+1), ErrReplayTooFarFuture)
			for sequence := uint64(0); sequence <= window; sequence++ {
				if err := replay.CommitAuthenticated(sequence); err != nil {
					t.Fatalf("ordered setup sequence %d = %v", sequence, err)
				}
			}
			assertReplayResultV1(t, replay.Plausible(0), ErrReplayStale)
			assertReplayResultV1(t, replay.Plausible(window), ErrReplayDuplicate)
			if err := replay.Plausible(window + 1); err != nil {
				t.Fatalf("ordered exact next = %v", err)
			}
			assertReplayResultV1(t, replay.Plausible(2*window+1), ErrReplayOutOfOrder)
			assertReplayResultV1(t, replay.Plausible(2*window+2), ErrReplayTooFarFuture)
			if err := replay.CommitAuthenticated(window + 1); err != nil {
				t.Fatalf("ordered next commit = %v", err)
			}
			assertReplayResultV1(t, replay.Plausible(1), ErrReplayStale)
		})

		t.Run(fmt.Sprintf("bounded/%d", windowSize), func(t *testing.T) {
			replay, err := NewReplayWindowV1(ReplayPolicyBoundedReorderV1, windowSize)
			if err != nil {
				t.Fatal(err)
			}
			if err := replay.Plausible(window); err != nil {
				t.Fatalf("bounded initial upper = %v", err)
			}
			assertReplayResultV1(t, replay.Plausible(window+1), ErrReplayTooFarFuture)
			for _, sequence := range []uint64{0, window, 2 * window} {
				if err := replay.CommitAuthenticated(sequence); err != nil {
					t.Fatalf("bounded setup sequence %d = %v", sequence, err)
				}
			}
			lower, upper := window+1, 3*window
			if err := replay.Plausible(lower); err != nil {
				t.Fatalf("bounded lower %d = %v", lower, err)
			}
			if err := replay.Plausible(upper); err != nil {
				t.Fatalf("bounded upper %d = %v", upper, err)
			}
			assertReplayResultV1(t, replay.Plausible(window), ErrReplayStale)
			assertReplayResultV1(t, replay.Plausible(2*window), ErrReplayDuplicate)
			assertReplayResultV1(t, replay.Plausible(upper+1), ErrReplayTooFarFuture)
			if err := replay.CommitAuthenticated(lower); err != nil {
				t.Fatalf("bounded lower commit = %v", err)
			}
			if err := replay.CommitAuthenticated(upper); err != nil {
				t.Fatalf("bounded upper commit = %v", err)
			}
			assertReplayResultV1(t, replay.Plausible(lower), ErrReplayStale)
		})

		t.Run(fmt.Sprintf("windowed/%d", windowSize), func(t *testing.T) {
			replay, err := NewReplayWindowV1(ReplayPolicyWindowedReplayV1, windowSize)
			if err != nil {
				t.Fatal(err)
			}
			first := 2 * window
			if err := replay.CommitAuthenticated(first); err != nil {
				t.Fatalf("windowed arbitrary first = %v", err)
			}
			lower := window + 1
			if err := replay.Plausible(lower); err != nil {
				t.Fatalf("windowed lower %d = %v", lower, err)
			}
			assertReplayResultV1(t, replay.Plausible(window), ErrReplayStale)
			assertReplayResultV1(t, replay.Plausible(first), ErrReplayDuplicate)
			if err := replay.Plausible(math.MaxUint64); err != nil {
				t.Fatalf("windowed forward jump = %v", err)
			}
			if err := replay.CommitAuthenticated(lower); err != nil {
				t.Fatalf("windowed lower commit = %v", err)
			}
			if err := replay.CommitAuthenticated(3 * window); err != nil {
				t.Fatalf("windowed forward commit = %v", err)
			}
			assertReplayResultV1(t, replay.Plausible(lower), ErrReplayStale)
			assertReplayResultV1(t, replay.Plausible(first), ErrReplayStale)
			if err := replay.Plausible(2*window + 1); err != nil {
				t.Fatalf("windowed new lower = %v", err)
			}
		})
	}
}

func TestReplayV1BoundedReorderWindow(t *testing.T) {
	initial, err := NewReplayWindowV1(ReplayPolicyBoundedReorderV1, 4)
	if err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(0); sequence <= 4; sequence++ {
		if err := initial.Plausible(sequence); err != nil {
			t.Fatalf("bounded initial %d = %v", sequence, err)
		}
	}
	if err := initial.Plausible(5); !errors.Is(err, ErrReplayTooFarFuture) {
		t.Fatalf("bounded initial future = %v", err)
	}

	bounded, err := NewReplayWindowV1(ReplayPolicyBoundedReorderV1, 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []uint64{0, 4, 8} {
		if err := bounded.CommitAuthenticated(sequence); err != nil {
			t.Fatalf("bounded setup %d = %v", sequence, err)
		}
	}
	for _, tc := range []struct {
		sequence uint64
		want     error
	}{
		{5, nil}, {12, nil}, {4, ErrReplayStale}, {13, ErrReplayTooFarFuture},
	} {
		err := bounded.Plausible(tc.sequence)
		if tc.want == nil && err != nil {
			t.Fatalf("bounded boundary %d = %v", tc.sequence, err)
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Fatalf("bounded boundary %d = %v, want %v", tc.sequence, err, tc.want)
		}
	}
	if err := bounded.CommitAuthenticated(5); err != nil {
		t.Fatalf("bounded reorder commit = %v", err)
	}
	if err := bounded.CommitAuthenticated(12); err != nil {
		t.Fatalf("bounded upper commit = %v", err)
	}

	nearMax, err := NewReplayWindowV1(ReplayPolicyBoundedReorderV1, 4)
	if err != nil {
		t.Fatal(err)
	}
	nearMax.state.initialized = true
	nearMax.state.highest = math.MaxUint64 - 2
	for _, sequence := range []uint64{math.MaxUint64 - 1, math.MaxUint64} {
		if err := nearMax.Plausible(sequence); err != nil {
			t.Fatalf("bounded near-Max sequence %d = %v", sequence, err)
		}
	}
	if err := nearMax.CommitAuthenticated(math.MaxUint64); err != nil {
		t.Fatalf("bounded MaxUint64 commit = %v", err)
	}

	orderedMax, err := NewReplayWindowV1(ReplayPolicyOrderedOnlyV1, 4)
	if err != nil {
		t.Fatal(err)
	}
	orderedMax.state.initialized = true
	orderedMax.state.highest = math.MaxUint64 - 2
	if err := orderedMax.Plausible(math.MaxUint64); !errors.Is(err, ErrReplayOutOfOrder) {
		t.Fatalf("ordered Max before Max-1 = %v", err)
	}
	if err := orderedMax.CommitAuthenticated(math.MaxUint64 - 1); err != nil {
		t.Fatalf("ordered Max-1 commit = %v", err)
	}
	if err := orderedMax.CommitAuthenticated(math.MaxUint64); err != nil {
		t.Fatalf("ordered Max commit = %v", err)
	}
	if err := orderedMax.Plausible(math.MaxUint64); !errors.Is(err, ErrReplayDuplicate) {
		t.Fatalf("ordered Max duplicate precedence = %v", err)
	}
	if err := orderedMax.Plausible(1); !errors.Is(err, ErrReplayExhausted) || err.Error() != "replay_exhausted" {
		t.Fatalf("ordered unseen post-Max = %v", err)
	}
}

func TestReplayV1WindowedReplayDistinct(t *testing.T) {
	replay, err := NewReplayWindowV1(ReplayPolicyWindowedReplayV1, 4)
	if err != nil {
		t.Fatal(err)
	}
	// Standard bitmap semantics deliberately accept an arbitrary first value.
	if err := replay.CommitAuthenticated(8); err != nil {
		t.Fatalf("arbitrary first value = %v", err)
	}
	if err := replay.Plausible(5); err != nil {
		t.Fatalf("in-window reorder = %v", err)
	}
	if err := replay.Plausible(4); !errors.Is(err, ErrReplayStale) {
		t.Fatalf("outside sliding window = %v", err)
	}
	if err := replay.Plausible(math.MaxUint64); err != nil {
		t.Fatalf("unseen forward jump = %v", err)
	}
	if err := replay.CommitAuthenticated(5); err != nil {
		t.Fatalf("in-window commit = %v", err)
	}
	if err := replay.CommitAuthenticated(math.MaxUint64); err != nil {
		t.Fatalf("max forward commit = %v", err)
	}
	if err := replay.CommitAuthenticated(math.MaxUint64); !errors.Is(err, ErrReplayDuplicate) {
		t.Fatalf("max duplicate = %v", err)
	}
}

func TestReplayV1PlausibleFailedAuthenticationAndConcurrent(t *testing.T) {
	for _, policy := range []string{ReplayPolicyOrderedOnlyV1, ReplayPolicyBoundedReorderV1, ReplayPolicyWindowedReplayV1} {
		t.Run(policy, func(t *testing.T) {
			replay, err := NewReplayWindowV1(policy, 4)
			if err != nil {
				t.Fatal(err)
			}
			before := replay.MetadataV1()
			if err := replay.Plausible(0); err != nil {
				t.Fatal(err)
			}
			// Simulated forged/failed authentication: do not commit after Plausible.
			if got := replay.MetadataV1(); got != before {
				t.Fatalf("failed authentication changed state: %#v -> %#v", before, got)
			}
			if err := replay.CommitAuthenticated(0); err != nil {
				t.Fatalf("later valid zero = %v", err)
			}

			fresh, err := NewReplayWindowV1(policy, 4)
			if err != nil {
				t.Fatal(err)
			}
			copiedHandle := *fresh
			handles := [2]*ReplayWindowV1{fresh, &copiedHandle}
			const workers = 64
			results := make(chan error, workers)
			var group sync.WaitGroup
			for i := 0; i < workers; i++ {
				group.Add(1)
				handle := handles[i%len(handles)]
				go func(target *ReplayWindowV1) {
					defer group.Done()
					results <- target.CommitAuthenticated(0)
				}(handle)
			}
			group.Wait()
			close(results)
			successes := 0
			duplicates := 0
			for result := range results {
				switch {
				case result == nil:
					successes++
				case errors.Is(result, ErrReplayDuplicate):
					duplicates++
				default:
					t.Fatalf("concurrent result = %v", result)
				}
			}
			if successes != 1 || duplicates != workers-1 {
				t.Fatalf("concurrent outcomes = success %d duplicate %d", successes, duplicates)
			}
		})
	}
}

func TestReplayV1ValidationWindowAndSentinels(t *testing.T) {
	for _, window := range []int{2, 4096} {
		if _, err := NewReplayWindowV1(ReplayPolicyOrderedOnlyV1, window); err != nil {
			t.Fatalf("valid window %d = %v", window, err)
		}
	}
	for _, tc := range []struct {
		policy string
		window int
	}{
		{ReplayPolicyOrderedOnlyV1, 0},
		{ReplayPolicyOrderedOnlyV1, 1},
		{ReplayPolicyOrderedOnlyV1, 4097},
		{"", 4},
		{"unknown", 4},
		{"strict_no_reorder", 4},
	} {
		if _, err := NewReplayWindowV1(tc.policy, tc.window); !errors.Is(err, ErrPolicyInvalid) || !errors.Is(err, ErrInvalidConfig) || err.Error() != "policy_invalid" {
			t.Fatalf("invalid policy/window (%q,%d) = %v", tc.policy, tc.window, err)
		}
	}
	zero := &ReplayWindowV1{}
	for name, action := range map[string]func() error{
		"plausible": func() error { return zero.Plausible(0) },
		"commit":    func() error { return zero.CommitAuthenticated(0) },
	} {
		if err := action(); !errors.Is(err, ErrPolicyInvalid) || err.Error() != "policy_invalid" {
			t.Fatalf("zero handle %s = %v", name, err)
		}
	}
	if got := zero.MetadataV1(); got != (ReplayMetadataV1{}) {
		t.Fatalf("zero handle metadata = %#v", got)
	}

	for sentinel, want := range map[error]string{
		ErrReplayDuplicate: "replay_duplicate", ErrReplayStale: "replay_stale",
		ErrReplayOutOfOrder: "replay_out_of_order", ErrReplayTooFarFuture: "replay_too_far_future",
		ErrReplayExhausted: "replay_exhausted",
	} {
		if sentinel.Error() != want || !errors.Is(sentinel, ErrReplay) {
			t.Fatalf("strict replay sentinel = %q class=%v", sentinel, errors.Is(sentinel, ErrReplay))
		}
		assertSafeSentinelFormattingV1(t, sentinel, want)
	}

	replay, err := NewReplayWindowV1(ReplayPolicyWindowedReplayV1, 4)
	if err != nil {
		t.Fatal(err)
	}
	metadata := replay.MetadataV1()
	metadata.Highest = 99
	if got := replay.MetadataV1(); got.Highest != 0 || got.Initialized {
		t.Fatalf("metadata alias changed state: %#v", got)
	}
}

func assertReplayResultV1(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("replay result = %v, want %v", got, want)
	}
}
