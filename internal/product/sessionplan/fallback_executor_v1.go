// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package sessionplan

import (
	"context"
	"errors"
	"time"
)

const maxFallbackAttemptsV1 = 8

var ErrFallbackExecutionV1 = errors.New("permitted fallback execution rejected")

// FallbackAttemptV1 executes exactly one freshly constructed Kurd session for
// one immutable, already-admitted plan. It must not reuse handshake, replay,
// record, carrier, or delivery state from another call.
type FallbackAttemptV1 func(context.Context, Plan) error

// FallbackResultV1 contains only bounded, privacy-safe selection metadata.
type FallbackResultV1 struct {
	SelectedIndex  uint8
	AttemptCount   uint8
	StrategyFamily string
	CarrierFamily  string
	PlanDigest     [32]byte
}

// ExecutePermittedFallbackV1 tries an exact ordered set of immutable admitted
// plans. It cannot add, reorder, or retry candidates, and each attempt receives
// its own deadline bounded by the plan.
func ExecutePermittedFallbackV1(ctx context.Context, plans []Plan, attempt FallbackAttemptV1) (FallbackResultV1, error) {
	if ctx == nil || attempt == nil || len(plans) == 0 || len(plans) > maxFallbackAttemptsV1 {
		return FallbackResultV1{}, ErrFallbackExecutionV1
	}
	if err := validateFallbackPlansV1(plans); err != nil {
		return FallbackResultV1{}, err
	}
	for index, plan := range plans {
		if err := ctx.Err(); err != nil {
			return FallbackResultV1{}, ErrFallbackExecutionV1
		}
		attemptCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.DialTimeoutMs)*time.Millisecond)
		err := attempt(attemptCtx, plan)
		cancel()
		if err == nil {
			return FallbackResultV1{
				SelectedIndex:  uint8(index),
				AttemptCount:   uint8(index + 1),
				StrategyFamily: plan.StrategyFamily,
				CarrierFamily:  plan.CarrierFamily,
				PlanDigest:     plan.Digest,
			}, nil
		}
	}
	return FallbackResultV1{}, ErrFallbackExecutionV1
}

func validateFallbackPlansV1(plans []Plan) error {
	first := plans[0]
	seenPlans := make(map[[32]byte]struct{}, len(plans))
	seenDescriptors := make(map[string]struct{}, len(plans))
	for _, plan := range plans {
		if err := Validate(plan); err != nil ||
			plan.ProfileID != first.ProfileID ||
			plan.Scope != first.Scope ||
			plan.EvidenceReference != first.EvidenceReference ||
			plan.Generation != first.Generation ||
			plan.ClientID != first.ClientID {
			return ErrFallbackExecutionV1
		}
		if _, exists := seenPlans[plan.Digest]; exists {
			return ErrFallbackExecutionV1
		}
		if _, exists := seenDescriptors[plan.DescriptorID]; exists {
			return ErrFallbackExecutionV1
		}
		seenPlans[plan.Digest] = struct{}{}
		seenDescriptors[plan.DescriptorID] = struct{}{}
	}
	return nil
}
