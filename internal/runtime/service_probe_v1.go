// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"time"
	"unsafe"

	"kurdistan/internal/product/envelope"
)

var (
	ErrProbeRateLimitedV1     = errors.New("probe_rate_limited")
	ErrProbeClockRegressionV1 = errors.New("probe_clock_regression")
)

// AuthenticatedProbeScopeV1 contains only a domain-separated digest. It is not
// a public request identity and cannot itself verify a signature.
type AuthenticatedProbeScopeV1 struct {
	digest [32]byte
	valid  bool
}

// ProbeRateRegistryV1 is constructor-bounded and must be injected once by the
// native owner into maintenance/session handles and by the relay across its
// reconnect admissions. Do not copy after first use. It owns no goroutines,
// payloads, profile objects, targets or networking capabilities.
type ProbeRateRegistryV1 struct {
	mu        sync.Mutex
	capacity  int
	states    []probeRateEntryV1
	lastClock time.Time
}
type probeRateEntryV1 struct {
	digest [32]byte
	state  probeRateStateV1
	live   bool
}
type probeRateStateV1 struct {
	starts    [60]time.Time
	count     int
	lastStart time.Time
}

// NewAuthenticatedProbeScopeV1 is a native verified-profile insertion seam.
// Call ONLY after verifying ProviderID, LineageID and ProfileID as one current
// authenticated authority. Never decode these values from a probe/ABI request.
// Generation/content ID are deliberately excluded. No profile bytes are kept.
func NewAuthenticatedProbeScopeV1(verified envelope.CanonicalProfileV1) (AuthenticatedProbeScopeV1, error) {
	h := sha256.New()
	h.Write([]byte("kurdistan/probe-rate/profile-scope/v1\x00"))
	for _, id := range []string{verified.ProviderID, verified.LineageID, verified.ProfileID} {
		if len(id) == 0 || len(id) > envelope.MaxCanonicalIDBytes {
			return AuthenticatedProbeScopeV1{}, ServiceNotAdmittedV1
		}
		for _, c := range id {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
				return AuthenticatedProbeScopeV1{}, ServiceNotAdmittedV1
			}
		}
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(id)))
		h.Write(length[:])
		h.Write([]byte(id))
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return AuthenticatedProbeScopeV1{digest: digest, valid: true}, nil
}
func NewProbeRateRegistryV1(capacity int) (*ProbeRateRegistryV1, error) {
	if capacity < 1 || capacity > 4096 {
		return nil, ServiceResourceLimitV1
	}
	return &ProbeRateRegistryV1{capacity: capacity, states: make([]probeRateEntryV1, capacity)}, nil
}

// OwnedBytesV1 is the fixed process-owned backing. Borrowing parents may
// conservatively attribute it, but must not reset or destroy the shared history.
func (r *ProbeRateRegistryV1) OwnedBytesV1() uint64 {
	if r == nil || r.capacity < 1 || r.capacity > 4096 || len(r.states) != r.capacity || cap(r.states) != r.capacity {
		return 0
	}
	return uint64(unsafe.Sizeof(*r)) + uint64(cap(r.states))*uint64(unsafe.Sizeof(probeRateEntryV1{}))
}

// TryStart atomically spends a token before the caller begins networking. The
// token is never refunded for failure/cancellation. A denied first attempt must
// return RATE_LIMITED; only an already-running sample operation may use NextSlot.
func (r *ProbeRateRegistryV1) TryStart(scope AuthenticatedProbeScopeV1, admission ProbeAdmissionV1, now time.Time) error {
	if r == nil {
		return ServiceInvalidRequestV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	state, next, err := r.slot(scope, admission, now)
	if err != nil {
		return err
	}
	if next.After(now) {
		return ErrProbeRateLimitedV1
	}
	// slot has pruned the rolling minute; signed starts are at least 1s apart.
	if state.count >= len(state.starts) {
		return ServiceResourceLimitV1
	}
	state.starts[state.count] = now
	state.count++
	state.lastStart = now
	index := -1
	for i := range r.states {
		if r.states[i].live && r.states[i].digest == scope.digest {
			index = i
			break
		}
		if !r.states[i].live && index < 0 {
			index = i
		}
	}
	if index < 0 {
		return ServiceResourceLimitV1
	}
	r.states[index] = probeRateEntryV1{digest: scope.digest, state: state, live: true}
	return nil
}

// NextSlot does not spend or reserve a token and never sleeps. A caller must
// retry TryStart at that time, because another operation may win it. The slot
// must be strictly before the caller's existing deadline; this never extends it.
func (r *ProbeRateRegistryV1) NextSlot(scope AuthenticatedProbeScopeV1, admission ProbeAdmissionV1, now, deadline time.Time) (time.Time, error) {
	if r == nil || !deadline.After(now) {
		return time.Time{}, ServiceInvalidRequestV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, next, err := r.slot(scope, admission, now)
	if err != nil {
		return time.Time{}, err
	}
	if !next.Before(deadline) {
		return time.Time{}, ErrProbeRateLimitedV1
	}
	return next, nil
}
func (r *ProbeRateRegistryV1) slot(scope AuthenticatedProbeScopeV1, a ProbeAdmissionV1, now time.Time) (probeRateStateV1, time.Time, error) {
	if !scope.valid || a.target.ID == 0 || a.interval < time.Second || a.interval > time.Hour || a.perMinute < 1 || a.perMinute > 60 || r.OwnedBytesV1() == 0 || now.IsZero() || now.Year() < 1 || now.Year() > 9998 {
		return probeRateStateV1{}, time.Time{}, ServiceInvalidRequestV1
	}
	if !r.lastClock.IsZero() && now.Before(r.lastClock) {
		return probeRateStateV1{}, time.Time{}, ErrProbeClockRegressionV1
	}
	r.lastClock = now
	// Keep the latest start for the maximum possible signed interval, even if
	// the old policy was weaker. Otherwise a tighter new generation could evade
	// its interval after another profile evicted the old 60s-expired entry.
	index, free := -1, false
	for i := range r.states {
		entry := &r.states[i]
		if entry.live && !now.Before(entry.state.lastStart.Add(time.Hour)) {
			*entry = probeRateEntryV1{}
		}
		if !entry.live {
			free = true
		} else if entry.digest == scope.digest {
			index = i
		}
	}
	if index < 0 && !free {
		return probeRateStateV1{}, time.Time{}, ServiceResourceLimitV1
	}
	var state probeRateStateV1
	if index >= 0 {
		state = r.states[index].state
	}
	n := 0
	for _, start := range state.starts[:state.count] {
		if now.Before(start.Add(time.Minute)) {
			state.starts[n] = start
			n++
		}
	}
	clear(state.starts[n:])
	state.count = n
	next := now
	if !state.lastStart.IsZero() && state.lastStart.Add(a.interval).After(next) {
		next = state.lastStart.Add(a.interval)
	}
	if state.count >= int(a.perMinute) {
		rolling := state.starts[state.count-int(a.perMinute)].Add(time.Minute)
		if rolling.After(next) {
			next = rolling
		}
	}
	if index >= 0 {
		r.states[index].state = state
	}
	return state, next, nil
}

type ProbePathV1 uint8

const (
	ProbeDisconnectedTCPConnectV1 ProbePathV1 = iota + 1
	ProbeActiveRelayEndToEndV1
)

type ProbeStabilityV1 uint8

const (
	ProbeNotEnoughSamplesV1 ProbeStabilityV1 = iota + 1
	ProbeStableV1
	ProbeVariableV1
)

// ProbeSampleV1 represents actual attempted work only. AttemptTimeoutMillis is
// the accepted per-attempt timeout. Unstarted/cancelled remaining samples have
// Attempted=false with no success/duration and never count as fabricated loss.
type ProbeSampleV1 struct {
	Attempted, Success   bool
	DurationMicros       uint64
	AttemptTimeoutMillis uint16
}
type ProbeAggregateV1 struct {
	Path                        ProbePathV1
	Attempted                   uint8
	HasLatency, HasJitter       bool
	LatencyMicros, JitterMicros uint64
	LossPermille                uint16
	Stability                   ProbeStabilityV1
}

// AggregateProbeSamplesV1 retains no samples or destinations. Active durations
// must be measured by the client as actual monotonic request/result elapsed
// time, not copied from relay-only connect duration. Timing is later wiring.
func AggregateProbeSamplesV1(path ProbePathV1, samples []ProbeSampleV1) (ProbeAggregateV1, error) {
	if (path != ProbeDisconnectedTCPConnectV1 && path != ProbeActiveRelayEndToEndV1) || len(samples) > 10 {
		return ProbeAggregateV1{}, ServiceInvalidRequestV1
	}
	out := ProbeAggregateV1{Path: path, Stability: ProbeNotEnoughSamplesV1}
	var successful uint8
	var sum, jitter, last uint64
	for _, s := range samples {
		if !s.Attempted {
			if s.Success || s.DurationMicros != 0 {
				return ProbeAggregateV1{}, ServiceInvalidRequestV1
			}
			continue
		}
		if s.AttemptTimeoutMillis < 1000 || s.AttemptTimeoutMillis > 30000 || s.DurationMicros > uint64(s.AttemptTimeoutMillis)*1000 || !s.Success && s.DurationMicros != 0 {
			return ProbeAggregateV1{}, ServiceInvalidRequestV1
		}
		out.Attempted++
		if !s.Success {
			continue
		}
		if math.MaxUint64-sum < s.DurationMicros {
			return ProbeAggregateV1{}, ServiceInvalidRequestV1
		}
		sum += s.DurationMicros
		if successful > 0 {
			diff := last - s.DurationMicros
			if s.DurationMicros > last {
				diff = s.DurationMicros - last
			}
			if math.MaxUint64-jitter < diff {
				return ProbeAggregateV1{}, ServiceInvalidRequestV1
			}
			jitter += diff
		}
		last = s.DurationMicros
		successful++
	}
	if successful > 0 {
		out.HasLatency = true
		out.LatencyMicros = sum / uint64(successful)
	}
	if successful > 1 {
		out.HasJitter = true
		out.JitterMicros = jitter / uint64(successful-1)
	}
	if out.Attempted > 0 {
		out.LossPermille = uint16(out.Attempted-successful) * 1000 / uint16(out.Attempted)
	}
	if out.Attempted >= 3 {
		out.Stability = ProbeVariableV1
		if successful == out.Attempted && out.HasJitter && out.JitterMicros <= out.LatencyMicros/4 {
			out.Stability = ProbeStableV1
		}
	}
	return out, nil
}
