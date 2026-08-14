// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"kurdistan/internal/phase17qualification"
)

type virtualCampaignClock struct {
	now       time.Time
	waits     []time.Duration
	waitError error
	jump      time.Duration
}

func (clock *virtualCampaignClock) Now() time.Time {
	return clock.now
}

func (clock *virtualCampaignClock) Wait(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clock.waits = append(clock.waits, duration)
	if clock.waitError != nil {
		return clock.waitError
	}
	clock.now = clock.now.Add(duration + clock.jump)
	clock.jump = 0
	return nil
}

func TestExecuteSoakCampaignUsesExactPolicyWithoutStressInventory(t *testing.T) {
	policy, ok := phase17qualification.CampaignPolicyForMode("Soak60m")
	if !ok {
		t.Fatal("Soak60m policy unavailable")
	}
	clock := &virtualCampaignClock{now: time.Unix(1_000, 0)}
	cycles := uint64(0)
	result, err := executeSoakCampaign(context.Background(), policy, clock, soakActions{
		cycle: func(context.Context, uint64) (uint64, error) {
			cycles++
			return 1, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cycles != policy.MinimumCycles || result.cycles != policy.MinimumCycles {
		t.Fatalf("cycles=(%d,%d), want %d", cycles, result.cycles, policy.MinimumCycles)
	}
	if result.durationMS != policy.MinimumDurationMS || result.reconnects != policy.MinimumCycles {
		t.Fatalf("result=%+v", result)
	}
	if result.restartReconnectCycles != 0 || result.profileRotationCycles != 0 || len(result.impairments) != 0 {
		t.Fatalf("soak inherited Stress inventory: %+v", result)
	}
	if len(clock.waits) != int(policy.MinimumCycles) {
		t.Fatalf("waits=%d, want %d", len(clock.waits), policy.MinimumCycles)
	}
	for index, duration := range clock.waits {
		if duration != time.Duration(policy.CadenceMS)*time.Millisecond {
			t.Fatalf("wait %d=%s", index, duration)
		}
	}
}

func TestExecuteSoakCampaignRejectsForwardSuspendGap(t *testing.T) {
	policy, _ := phase17qualification.CampaignPolicyForMode("Soak60m")
	clock := &virtualCampaignClock{now: time.Unix(2_000, 0), jump: 2 * time.Duration(policy.CadenceMS) * time.Millisecond}
	_, err := executeSoakCampaign(context.Background(), policy, clock, soakActions{
		cycle: func(context.Context, uint64) (uint64, error) { return 0, nil },
	})
	if err == nil || !errors.Is(err, errCampaignClockGap) {
		t.Fatalf("forward clock gap error=%v", err)
	}
}

func TestExecuteSoakCampaignRejectsBackwardClockJump(t *testing.T) {
	policy, _ := phase17qualification.CampaignPolicyForMode("Soak60m")
	clock := &virtualCampaignClock{now: time.Unix(3_000, 0), jump: -2 * time.Duration(policy.CadenceMS) * time.Millisecond}
	_, err := executeSoakCampaign(context.Background(), policy, clock, soakActions{
		cycle: func(context.Context, uint64) (uint64, error) { return 0, nil },
	})
	if err == nil || !errors.Is(err, errCampaignClockReversed) {
		t.Fatalf("backward clock error=%v", err)
	}
}

func TestExecuteSoakCampaignHonorsCancellationWithoutAnotherCycle(t *testing.T) {
	policy, _ := phase17qualification.CampaignPolicyForMode("Soak60m")
	ctx, cancel := context.WithCancel(context.Background())
	clock := &virtualCampaignClock{now: time.Unix(4_000, 0)}
	cycles := 0
	_, err := executeSoakCampaign(ctx, policy, clock, soakActions{
		cycle: func(context.Context, uint64) (uint64, error) {
			cycles++
			cancel()
			return 0, nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
	if cycles != 1 {
		t.Fatalf("cycles=%d, want 1", cycles)
	}
}

func TestExecuteSoakCampaignRejectsStressPolicy(t *testing.T) {
	policy, _ := phase17qualification.CampaignPolicyForMode("Stress")
	_, err := executeSoakCampaign(context.Background(), policy, &virtualCampaignClock{now: time.Unix(5_000, 0)}, soakActions{})
	if err == nil {
		t.Fatal("Stress policy accepted as soak")
	}
}
