// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package server

import (
	"sync"
	"time"
)

const MaxRateLimitActors = 4096

type RateClock interface {
	Now() time.Time
}

type tokenBucket struct {
	tokens float64
	at     time.Time
}

type MemoryRateLimiter struct {
	mu        sync.Mutex
	clock     RateClock
	capacity  float64
	perSecond float64
	buckets   map[string]tokenBucket
}

func NewMemoryRateLimiter(clock RateClock, capacity int, refillInterval time.Duration) (*MemoryRateLimiter, error) {
	if clock == nil || capacity < 1 || capacity > 1000 || refillInterval < time.Millisecond || refillInterval > time.Hour {
		return nil, ErrUnavailable
	}
	return &MemoryRateLimiter{
		clock: clock, capacity: float64(capacity), perSecond: 1 / refillInterval.Seconds(),
		buckets: make(map[string]tokenBucket),
	}, nil
}

func (limiter *MemoryRateLimiter) Allow(actorID, action string) bool {
	if actorID == "" || action == "" || len(actorID) > 128 || len(action) > 256 {
		return false
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	key := actorID + "\x00" + action
	now := limiter.clock.Now()
	bucket, exists := limiter.buckets[key]
	if !exists {
		if len(limiter.buckets) >= MaxRateLimitActors {
			return false
		}
		bucket = tokenBucket{tokens: limiter.capacity, at: now}
	}
	if now.Before(bucket.at) {
		return false
	}
	bucket.tokens += now.Sub(bucket.at).Seconds() * limiter.perSecond
	if bucket.tokens > limiter.capacity {
		bucket.tokens = limiter.capacity
	}
	bucket.at = now
	if bucket.tokens < 1 {
		limiter.buckets[key] = bucket
		return false
	}
	bucket.tokens--
	limiter.buckets[key] = bucket
	return true
}
