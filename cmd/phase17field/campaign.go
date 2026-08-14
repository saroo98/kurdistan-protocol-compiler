// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"kurdistan/internal/phase17qualification"
)

var (
	errCampaignClockGap      = errors.New("campaign monotonic cadence gap")
	errCampaignClockReversed = errors.New("campaign clock reversed")
)

type campaignClock interface {
	Now() time.Time
	Wait(context.Context, time.Duration) error
}

type realCampaignClock struct{}

func (realCampaignClock) Now() time.Time {
	return time.Now()
}

func (realCampaignClock) Wait(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type soakActions struct {
	cycle    func(context.Context, uint64) (uint64, error)
	progress func(completed, total uint64, elapsed time.Duration)
}

type soakCampaignResult struct {
	durationMS             uint64
	cycles                 uint64
	reconnects             uint64
	restartReconnectCycles uint64
	profileRotationCycles  uint64
	impairments            []string
}

func executeSoakCampaign(
	ctx context.Context,
	policy phase17qualification.CampaignPolicy,
	clock campaignClock,
	actions soakActions,
) (soakCampaignResult, error) {
	result := soakCampaignResult{impairments: []string{}}
	if clock == nil || actions.cycle == nil || policy.MinimumDurationMS == 0 || policy.CadenceMS == 0 || policy.MinimumCycles == 0 ||
		policy.RestartReconnectCycles != 0 || policy.ProfileRotationCycles != 0 || len(policy.Impairments) != 0 {
		return result, errors.New("soak campaign policy rejected")
	}
	minimumDuration := time.Duration(policy.MinimumDurationMS) * time.Millisecond
	cadence := time.Duration(policy.CadenceMS) * time.Millisecond
	if policy.MinimumCycles != uint64(minimumDuration/cadence) || minimumDuration%cadence != 0 {
		return result, errors.New("soak campaign schedule rejected")
	}
	started := clock.Now()
	lastObserved := started
	for cycle := uint64(0); cycle < policy.MinimumCycles; cycle++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		observed := clock.Now()
		if observed.Before(lastObserved) {
			return result, errCampaignClockReversed
		}
		reconnects, err := actions.cycle(ctx, cycle)
		if err != nil {
			return result, fmt.Errorf("soak cycle %d failed: %w", cycle, err)
		}
		result.cycles++
		result.reconnects += reconnects

		target := started.Add(time.Duration(cycle+1) * cadence)
		afterCycle := clock.Now()
		if afterCycle.Before(observed) {
			return result, errCampaignClockReversed
		}
		if afterCycle.After(target.Add(cadence)) {
			return result, errCampaignClockGap
		}
		wait := target.Sub(afterCycle)
		if wait < 0 {
			wait = 0
		}
		if err := clock.Wait(ctx, wait); err != nil {
			return result, err
		}
		lastObserved = clock.Now()
		if lastObserved.Before(afterCycle) {
			return result, errCampaignClockReversed
		}
		if lastObserved.After(target.Add(cadence)) {
			return result, errCampaignClockGap
		}
		if actions.progress != nil {
			actions.progress(result.cycles, policy.MinimumCycles, lastObserved.Sub(started))
		}
	}
	ended := clock.Now()
	if ended.Before(started) {
		return result, errCampaignClockReversed
	}
	duration := ended.Sub(started)
	if duration < minimumDuration || duration > minimumDuration+cadence {
		return result, errors.New("soak campaign duration rejected")
	}
	result.durationMS = uint64(duration.Milliseconds())
	return result, nil
}
