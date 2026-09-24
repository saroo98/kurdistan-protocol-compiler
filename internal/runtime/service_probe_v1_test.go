// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"errors"
	"kurdistan/internal/product/envelope"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func probeScopeFixtureV1(t testing.TB, id string) AuthenticatedProbeScopeV1 {
	t.Helper()
	s, err := NewAuthenticatedProbeScopeV1(envelope.CanonicalProfileV1{ProviderID: "provider", LineageID: "lineage", ProfileID: id})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func probeAdmissionFixtureV1(t testing.TB) ProbeAdmissionV1 {
	t.Helper()
	p := servicePolicyFixtureV1(t)
	a, err := NewServiceAdmissionV1(p, serviceTestNowV1)
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.AdmitProbe(ProbeRequestV1{TargetID: 7, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 5000, Samples: 3}, ProbeActiveRelayV1, 1)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestServiceProbeScopeIdentityAndRegistryBounds(t *testing.T) {
	base := envelope.CanonicalProfileV1{ProviderID: "provider", LineageID: "lineage", ProfileID: "profile"}
	s, err := NewAuthenticatedProbeScopeV1(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Generation = 99
	base.ContentID = "changed"
	again, err := NewAuthenticatedProbeScopeV1(base)
	if err != nil || s != again {
		t.Fatal("generation reset scope")
	}
	base.ProviderID = "other"
	other, _ := NewAuthenticatedProbeScopeV1(base)
	if other == s {
		t.Fatal("provider collision")
	}
	base.ProviderID = "provider"
	base.LineageID = "other"
	other, _ = NewAuthenticatedProbeScopeV1(base)
	if other == s {
		t.Fatal("lineage collision")
	}
	for _, id := range []string{"", "bad id", string(make([]byte, 129))} {
		base.ProfileID = id
		if _, err := NewAuthenticatedProbeScopeV1(base); err == nil {
			t.Fatal("bad native identity")
		}
	}
	for _, capacity := range []int{0, 4097} {
		if _, err := NewProbeRateRegistryV1(capacity); err == nil {
			t.Fatal("unbounded registry")
		}
	}
	if _, err := NewProbeRateRegistryV1(4096); err != nil {
		t.Fatal(err)
	}
}

func TestServiceProbeRateAtomicAndRetainedAcrossReacquisition(t *testing.T) {
	r, _ := NewProbeRateRegistryV1(2)
	a := probeAdmissionFixtureV1(t)
	scope := probeScopeFixtureV1(t, "profile")
	var starts atomic.Int32
	var denied atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := r.TryStart(scope, a, serviceTestNowV1)
			if err == nil {
				starts.Add(1)
			} else if errors.Is(err, ErrProbeRateLimitedV1) {
				denied.Add(1)
			} else {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if starts.Load() != 1 || denied.Load() != 31 {
		t.Fatal("non-atomic token", starts.Load(), denied.Load())
	}
	fresh := probeScopeFixtureV1(t, "profile")
	if err := r.TryStart(fresh, probeAdmissionFixtureV1(t), serviceTestNowV1.Add(999*time.Millisecond)); !errors.Is(err, ErrProbeRateLimitedV1) {
		t.Fatal("new handle reset", err)
	}
	if err := r.TryStart(fresh, a, serviceTestNowV1.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := r.TryStart(fresh, a, serviceTestNowV1.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := r.TryStart(fresh, a, serviceTestNowV1.Add(3*time.Second)); !errors.Is(err, ErrProbeRateLimitedV1) {
		t.Fatal("rolling limit", err)
	}
	next, err := r.NextSlot(fresh, a, serviceTestNowV1.Add(3*time.Second), serviceTestNowV1.Add(60*time.Second))
	if err == nil {
		t.Fatal("slot at deadline cannot start", next)
	}
	next, err = r.NextSlot(fresh, a, serviceTestNowV1.Add(3*time.Second), serviceTestNowV1.Add(61*time.Second))
	if err != nil || !next.Equal(serviceTestNowV1.Add(60*time.Second)) {
		t.Fatal("next slot", next, err)
	}
	if err := r.TryStart(fresh, a, serviceTestNowV1.Add(60*time.Second-time.Nanosecond)); !errors.Is(err, ErrProbeRateLimitedV1) {
		t.Fatal("early rolling release", err)
	}
	if err := r.TryStart(fresh, a, serviceTestNowV1.Add(60*time.Second)); err != nil {
		t.Fatal("rolling boundary", err)
	}
}

func TestServiceProbeRateOwnedStorageV1(t *testing.T) {
	var absent *ProbeRateRegistryV1
	if absent.OwnedBytesV1() != 0 || (&ProbeRateRegistryV1{}).OwnedBytesV1() != 0 {
		t.Fatal("invalid owner reported storage")
	}
	r, err := NewProbeRateRegistryV1(64)
	if err != nil {
		t.Fatal(err)
	}
	before := r.OwnedBytesV1()
	if before != uint64(unsafe.Sizeof(*r))+64*uint64(unsafe.Sizeof(probeRateEntryV1{})) {
		t.Fatal("missing fixed reservation")
	}
	a := probeAdmissionFixtureV1(t)
	scope := probeScopeFixtureV1(t, "fixed-storage")
	if err := r.TryStart(scope, a, serviceTestNowV1); err != nil {
		t.Fatal(err)
	}
	if r.OwnedBytesV1() != before {
		t.Fatal("start grew admitted storage")
	}
	if err := r.TryStart(scope, a, serviceTestNowV1.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r.OwnedBytesV1() != before {
		t.Fatal("pruning changed reservation")
	}
	hour := 1
	if allocations := testing.AllocsPerRun(20, func() {
		hour++
		if e := r.TryStart(scope, a, serviceTestNowV1.Add(time.Duration(hour)*time.Hour)); e != nil {
			panic(e)
		}
	}); allocations != 0 {
		t.Fatal("rate start allocated backing", allocations)
	}
	t.Logf("root=%d entry=%d capacity64=%d", unsafe.Sizeof(*r), unsafe.Sizeof(probeRateEntryV1{}), before)
}

func TestServiceProbeRateNarrowerGenerationClockAndExpiry(t *testing.T) {
	r, _ := NewProbeRateRegistryV1(1)
	a := probeAdmissionFixtureV1(t)
	scope := probeScopeFixtureV1(t, "profile")
	other := probeScopeFixtureV1(t, "other")
	if err := r.TryStart(scope, a, serviceTestNowV1); err != nil {
		t.Fatal(err)
	}
	p := servicePolicyFixtureV1(t)
	p.Services.Probes.MinAttemptIntervalMillis = 3600000
	p.Services.Probes.MaxAttemptsPerMinute = 1
	serviceSignPolicyV1(t, &p)
	authority, _ := NewServiceAdmissionV1(p, serviceTestNowV1)
	strict, _ := authority.AdmitProbe(a.request, ProbeActiveRelayV1, 1)
	if err := r.TryStart(scope, strict, serviceTestNowV1.Add(2*time.Minute)); !errors.Is(err, ErrProbeRateLimitedV1) {
		t.Fatal("tightened generation cleared history", err)
	}
	if err := r.TryStart(other, a, serviceTestNowV1.Add(3*time.Minute)); !errors.Is(err, ServiceResourceLimitV1) {
		t.Fatal("unsafe eviction", err)
	}
	if err := r.TryStart(scope, a, serviceTestNowV1.Add(time.Minute)); !errors.Is(err, ErrProbeClockRegressionV1) {
		t.Fatal("clock regression", err)
	}
	if _, err := r.NextSlot(scope, strict, serviceTestNowV1.Add(3*time.Minute), serviceTestNowV1.Add(30*time.Minute)); !errors.Is(err, ErrProbeRateLimitedV1) {
		t.Fatal("wait exceeded deadline", err)
	}
	if err := r.TryStart(other, a, serviceTestNowV1.Add(time.Hour)); err != nil {
		t.Fatal("safe expired capacity not reused", err)
	}
	if err := r.TryStart(AuthenticatedProbeScopeV1{}, a, serviceTestNowV1.Add(time.Hour)); err == nil {
		t.Fatal("unverified zero scope")
	}
	if err := r.TryStart(other, ProbeAdmissionV1{}, serviceTestNowV1.Add(time.Hour)); err == nil {
		t.Fatal("unsigned rate")
	}
	if err := r.TryStart(other, a, time.Time{}); err == nil {
		t.Fatal("zero clock")
	}
}

func TestServiceProbeAggregates(t *testing.T) {
	success := func(us uint64) ProbeSampleV1 {
		return ProbeSampleV1{Attempted: true, Success: true, DurationMicros: us, AttemptTimeoutMillis: 1000}
	}
	failed := ProbeSampleV1{Attempted: true, AttemptTimeoutMillis: 1000}
	for _, tc := range []struct {
		name                  string
		samples               []ProbeSampleV1
		attempts              uint8
		latency, jitter       uint64
		hasLatency, hasJitter bool
		loss                  uint16
		stability             ProbeStabilityV1
	}{
		{"none", nil, 0, 0, 0, false, false, 0, ProbeNotEnoughSamplesV1},
		{"one", []ProbeSampleV1{success(100)}, 1, 100, 0, true, false, 0, ProbeNotEnoughSamplesV1},
		{"two", []ProbeSampleV1{success(100), success(120)}, 2, 110, 20, true, true, 0, ProbeNotEnoughSamplesV1},
		{"stable", []ProbeSampleV1{success(100), success(110), success(120)}, 3, 110, 10, true, true, 0, ProbeStableV1},
		{"variable", []ProbeSampleV1{success(100), success(300), success(100)}, 3, 166, 200, true, true, 0, ProbeVariableV1},
		{"mixed", []ProbeSampleV1{success(100), failed, success(200)}, 3, 150, 100, true, true, 333, ProbeVariableV1},
		{"failed", []ProbeSampleV1{failed, failed, failed}, 3, 0, 0, false, false, 1000, ProbeVariableV1},
		{"unstarted", []ProbeSampleV1{success(100), {}, {}}, 1, 100, 0, true, false, 0, ProbeNotEnoughSamplesV1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AggregateProbeSamplesV1(ProbeDisconnectedTCPConnectV1, tc.samples)
			if err != nil || got.Attempted != tc.attempts || got.LatencyMicros != tc.latency || got.JitterMicros != tc.jitter || got.HasLatency != tc.hasLatency || got.HasJitter != tc.hasJitter || got.LossPermille != tc.loss || got.Stability != tc.stability || got.Path != ProbeDisconnectedTCPConnectV1 {
				t.Fatalf("aggregate %+v %v", got, err)
			}
		})
	}
	ten := make([]ProbeSampleV1, 10)
	for i := range ten {
		ten[i] = success(1000)
	}
	got, err := AggregateProbeSamplesV1(ProbeActiveRelayEndToEndV1, ten)
	if err != nil || got.Attempted != 10 || got.Stability != ProbeStableV1 || !got.HasJitter {
		t.Fatal(got, err)
	}
	for _, samples := range [][]ProbeSampleV1{append(ten, success(1)), {{Success: true}}, {{DurationMicros: 1}}, {{Attempted: true, DurationMicros: 1, AttemptTimeoutMillis: 1000}}, {success(1000001)}, {success(^uint64(0))}, {{Attempted: true, Success: true, AttemptTimeoutMillis: 999}}} {
		if _, err := AggregateProbeSamplesV1(ProbeActiveRelayEndToEndV1, samples); err == nil {
			t.Fatal("invalid sample accepted")
		}
	}
	if _, err := AggregateProbeSamplesV1(ProbePathV1(0), nil); err == nil {
		t.Fatal("unknown path")
	}
}

func TestServiceProbeRateTighterMinuteAndSixtyStartBoundary(t *testing.T) {
	p := servicePolicyFixtureV1(t)
	p.Services.Probes.MaxAttemptsPerMinute = 60
	serviceSignPolicyV1(t, &p)
	a, _ := NewServiceAdmissionV1(p, serviceTestNowV1)
	request := ProbeRequestV1{7, 1, 1000, 5000, 3}
	admitted, _ := a.AdmitProbe(request, ProbeActiveRelayV1, 1)
	scope := probeScopeFixtureV1(t, "profile")
	r, _ := NewProbeRateRegistryV1(1)
	for i := 0; i < 60; i++ {
		if err := r.TryStart(scope, admitted, serviceTestNowV1.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal("sixty starts", i, err)
		}
	}
	p.Services.Probes.MaxAttemptsPerMinute = 1
	serviceSignPolicyV1(t, &p)
	a, _ = NewServiceAdmissionV1(p, serviceTestNowV1)
	strict, _ := a.AdmitProbe(request, ProbeActiveRelayV1, 1)
	now := serviceTestNowV1.Add(60 * time.Second)
	next, err := r.NextSlot(scope, strict, now, serviceTestNowV1.Add(120*time.Second))
	if err != nil || !next.Equal(serviceTestNowV1.Add(119*time.Second)) {
		t.Fatal("stricter rolling history", next, err)
	}
	if err := r.TryStart(scope, strict, now); !errors.Is(err, ErrProbeRateLimitedV1) {
		t.Fatal("narrow generation lost starts", err)
	}
	if err := r.TryStart(scope, admitted, now); err != nil {
		t.Fatal("sixty slot reuse", err)
	}
}
