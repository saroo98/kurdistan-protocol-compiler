// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package server

import (
	"testing"
	"time"
)

type mutableRateClock struct{ at time.Time }

func (clock *mutableRateClock) Now() time.Time { return clock.at }

func TestMemoryRateLimiterIsBoundedAndFailsOnClockRollback(t *testing.T) {
	clock := &mutableRateClock{at: time.Unix(2_000_000_000, 0)}
	limiter, err := NewMemoryRateLimiter(clock, 2, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !limiter.Allow("actor-test", "profile.issue") || !limiter.Allow("actor-test", "profile.issue") || limiter.Allow("actor-test", "profile.issue") {
		t.Fatal("capacity limit not enforced")
	}
	clock.at = clock.at.Add(time.Second)
	if !limiter.Allow("actor-test", "profile.issue") {
		t.Fatal("token was not replenished")
	}
	clock.at = clock.at.Add(-time.Minute)
	if limiter.Allow("actor-test", "profile.issue") {
		t.Fatal("clock rollback accepted")
	}
}
