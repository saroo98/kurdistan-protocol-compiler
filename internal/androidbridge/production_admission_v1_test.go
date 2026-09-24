// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	runtimeengine "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
)

type productionRealCurrentV1 struct {
	calls  int
	after  func()
	limits selfhost.LiveMaintenanceLimits
}

func TestProductionAdmissionV1RevisionInvalidationIsNotVerifiedRevocation(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	platform := &productionSnapshotPlatformV1{snapshot: f.current}
	o := productionAdmittedFixtureV1(t, f, platform, rates)
	if code := platform.invalidate(); code != CodeOK {
		t.Fatal("ordinary joined invalidation failed", code)
	}
	o.parent.mu.Lock()
	reason := o.parent.terminal
	o.parent.mu.Unlock()
	if reason != productionCancelledV1 {
		t.Fatalf("revision invalidation fabricated cryptographic revocation: got %d want 7", reason)
	}
}

func TestProductionAdmissionV1InitialLeaseFollowsInstalledResourcePreparation(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	platform := &productionSnapshotPlatformV1{snapshot: f.current}
	platform.acquireHook = func() {
		o := platform.expected.parent.admission
		if o.resources == nil || o.resources.installation == nil {
			t.Error("one-shot publication lease acquired before real installation")
		}
	}
	productionAdmittedFixtureV1(t, f, platform, rates)
	if platform.leases != 1 {
		t.Fatal("initial lease count", platform.leases)
	}
}

func (e *productionRealCurrentV1) VerifyProductionCurrentAt(a []byte, c envelope.ArtifactClass, s lifecycle.VerifiedState, credentials RecipientCredentials, now time.Time, limits selfhost.LiveMaintenanceLimits) (*selfhost.LiveRuntimeCurrentV1, error) {
	e.calls++
	e.limits = limits
	defer credentials.Destroy()
	v, err := selfhost.VerifyLiveRuntimeCurrentForRecipient(a, now, s, credentials.Request, credentials.Private, limits)
	if err == nil && e.after != nil {
		e.after()
	}
	return v, err
}

func productionAdmittedFixtureV1(t *testing.T, f maintenanceSignedFixture, platform *productionSnapshotPlatformV1, rates *runtimeengine.ProbeRateRegistryV1) *productionAdmissionV1 {
	t.Helper()
	ticket, s := reserveProductionSlotV1(&HandleRegistry{})
	if s != 0 {
		t.Fatal(s)
	}
	p, s := newProductionParentV1(ticket, 80<<20, time.Time{})
	if s != 0 {
		t.Fatal(s)
	}
	opening, s := p.beginUseV1(productionUseOpeningV1, productionBudgetChargeV1{})
	if s != 0 {
		t.Fatal(s)
	}
	owner, s := newProductionAdmissionV1(p, opening, f.current, projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false)), &productionRealCurrentV1{}, platform, func() time.Time { return f.now }, time.Now, rates, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 80 << 20, MaxArtifactBytes: 1 << 20, MaxPublicationBytes: 1 << 20})
	p.finishUseV1(opening)
	if s != 0 {
		if p.admission != nil {
			p.admission.closeV1(context.Background())
		}
		t.Fatal("admission fixture", s)
	}
	t.Cleanup(func() { owner.closeV1(context.Background()) })
	return owner
}

func TestProductionAdmissionV1ExpectationAllExactEncodings(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	platform := &productionSnapshotPlatformV1{snapshot: f.current}
	o := productionAdmittedFixtureV1(t, f, platform, rates)
	if !o.expected.MatchesV1(f.current) {
		t.Fatal("exact snapshot rejected")
	}
	for i := range 4 {
		for _, length := range []bool{false, true} {
			parts := productionInputPartsV1(f.current)
			parts[i] = bytes.Clone(parts[i])
			if length {
				parts[i] = parts[i][:len(parts[i])-1]
			} else {
				parts[i][len(parts[i])/2] ^= 1
			}
			if o.expected.MatchesV1(MaintenanceCurrentInputV1{parts[0], parts[1], parts[2], parts[3]}) {
				t.Fatalf("accepted mismatch index=%d length=%v", i, length)
			}
		}
	}
	copied := o.expected
	if copied.MatchesV1(f.current) || (&ProductionCurrentExpectationV1{}).MatchesV1(f.current) {
		t.Fatal("copied/zero expectation")
	}
	if o.closeV1(context.Background()) != 0 || o.expected.MatchesV1(f.current) {
		t.Fatal("retired expectation")
	}
}

func TestProductionAdmissionV1EveryOpeningPlatformReentry(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	for _, stage := range []string{"register", "revalidate", "acquire", "current", "lease-close"} {
		t.Run(stage, func(t *testing.T) {
			ticket, _ := reserveProductionSlotV1(&HandleRegistry{})
			p, _ := newProductionParentV1(ticket, 80<<20, time.Time{})
			opening, _ := p.beginUseV1(0, productionBudgetChargeV1{})
			platform := &productionSnapshotPlatformV1{snapshot: f.current, stage: stage}
			o, s := newProductionAdmissionV1(p, opening, f.current, projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false)), &productionRealCurrentV1{}, platform, func() time.Time { return f.now }, time.Now, rates, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 80 << 20, MaxArtifactBytes: 1 << 20, MaxPublicationBytes: 1 << 20})
			if o != nil || s == 0 || platform.callbackResult == CodeOK || platform.closes != 0 {
				t.Fatal("reentrant cleanup/publication", s, platform.callbackResult, platform.closes)
			}
			p.finishUseV1(opening)
			if p.admission.closeV1(context.Background()) != 0 || platform.closes != 1 {
				t.Fatal("late external cleanup")
			}
		})
	}
}

func TestProductionAdmissionV1RefusedReserveBeforeVerification(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	fixed, _ := productionParentFixedBytesV1()
	ticket, _ := reserveProductionSlotV1(&HandleRegistry{})
	p, _ := newProductionParentV1(ticket, fixed+1, time.Time{})
	opening, _ := p.beginUseV1(0, productionBudgetChargeV1{})
	e := &productionRealCurrentV1{}
	platform := &productionSnapshotPlatformV1{snapshot: f.current}
	o, s := newProductionAdmissionV1(p, opening, f.current, projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false)), e, platform, func() time.Time { return f.now }, time.Now, nil, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 80 << 20, MaxArtifactBytes: 1 << 20, MaxPublicationBytes: 1 << 20})
	if o != nil || s != 5 || e.calls != 0 || platform.registrations != 0 {
		t.Fatal("work before reservation", s, e.calls, platform.registrations)
	}
	p.finishUseV1(opening)
}

func TestProductionAdmissionV1ParentRetirementJoinsOwnership(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	platform := &productionSnapshotPlatformV1{snapshot: f.current}
	o := productionAdmittedFixtureV1(t, f, platform, rates)
	o.parent.cancelV1(7)
	if s := o.parent.retireV1(); s != 0 {
		t.Fatal(s)
	}
	if o.seedLive || o.seed != ([32]byte{}) || platform.closes != 1 {
		t.Fatal("parent retired without native authority cleanup")
	}
}

func TestProductionAdmissionV1SharedRateHistoryAcrossOwnersAndMaintenance(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	first := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
	second := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
	policy, e := runtimepolicy.DecodeRuntimeAt(f.record.Profile.Policy, f.now)
	if e != nil {
		t.Fatal(e)
	}
	service, e := runtimeengine.NewServiceAdmissionV1(policy, f.now)
	if e != nil {
		t.Fatal(e)
	}
	admitted, e := service.AdmitProbe(runtimeengine.ProbeRequestV1{TargetID: 1, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 1000, Samples: 1}, runtimeengine.ProbeActiveRelayV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	if e = rates.TryStart(first.probeScope, admitted, f.now); e != nil {
		t.Fatal(e)
	}
	if e = second.probeRates.TryStart(second.probeScope, admitted, f.now); !errors.Is(e, runtimeengine.ErrProbeRateLimitedV1) {
		t.Fatal("second parent reset shared rate", e)
	}
	registry := new(HandleRegistry)
	handle, m := OpenMaintenanceV1(registry, f.current, maintenanceRealVerifier{}, &maintenanceIntegrationPlatform{}, MaintenanceConfigV1{Now: func() time.Time { return f.now }, OwnedBudgetBytes: 128 << 20, Limits: selfhost.LiveMaintenanceLimits{MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20}, ProbeRates: rates})
	if m != MaintenanceSuccess {
		t.Fatal(m)
	}
	defer registry.Free(handle)
	maintenance, m := maintenanceParentV1(registry, handle)
	if m != MaintenanceSuccess {
		t.Fatal(m)
	}
	if maintenance.probeRates != rates {
		t.Fatal("maintenance lost process dependency")
	}
	if first.closeV1(context.Background()) != 0 {
		t.Fatal("close first")
	}
	if e = maintenance.probeRates.TryStart(second.probeScope, admitted, f.now); !errors.Is(e, runtimeengine.ErrProbeRateLimitedV1) {
		t.Fatal("close refunded maintenance history", e)
	}
	charge, s := second.parent.budget.chargeV1(second.ownerTicket)
	fixed := uint64(unsafe.Sizeof(productionAdmissionV1{})) + productionRuntimeMetadataAllowanceV1 + 2*uint64(unsafe.Sizeof(productionVerifiedArgumentsV1{}))
	if s != 0 || charge.owned != fixed+rates.OwnedBytesV1() {
		t.Fatal("shared attribution", charge, s)
	}
	if reflect.ValueOf(rates).Pointer() != reflect.ValueOf(second.probeRates).Pointer() {
		t.Fatal("copied rate owner")
	}
}

func TestProductionAdmissionV1MutationAfterVerificationCannotRebindSnapshot(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	ticket, _ := reserveProductionSlotV1(&HandleRegistry{})
	p, _ := newProductionParentV1(ticket, 80<<20, time.Time{})
	opening, _ := p.beginUseV1(0, productionBudgetChargeV1{})
	platform := &productionSnapshotPlatformV1{snapshot: f.current}
	verifier := &productionRealCurrentV1{after: func() { f.current.VerifyRequest[0] ^= 1 }}
	owner, s := newProductionAdmissionV1(p, opening, f.current, projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false)), verifier, platform, func() time.Time { return f.now }, time.Now, rates, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 80 << 20, MaxArtifactBytes: 1 << 20, MaxPublicationBytes: 1 << 20})
	p.finishUseV1(opening)
	if p.admission != nil {
		defer p.admission.closeV1(context.Background())
	}
	if owner != nil || s == 0 {
		t.Fatal("mutated current rebound after cryptographic verification")
	}
}

func TestProductionAdmissionV1ExactRecordRejections(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	mutations := map[string]func(*profile.ActivationRecord){"artifact": func(r *profile.ActivationRecord) { r.Artifact[0] ^= 1 }, "signed": func(r *profile.ActivationRecord) { r.SignedObject[0] ^= 1 }, "profile": func(r *profile.ActivationRecord) { r.Profile.Generation++ }, "status": func(r *profile.ActivationRecord) { r.State.Status = lifecycle.Status("other") }, "profile-id": func(r *profile.ActivationRecord) { r.State.ProfileID += "x" }, "scope": func(r *profile.ActivationRecord) { r.State.Scope += "x" }, "evidence": func(r *profile.ActivationRecord) { r.State.EvidenceReference += "x" }, "generation": func(r *profile.ActivationRecord) { r.State.Generation++ }, "receipt": func(r *profile.ActivationRecord) { r.State.Receipt.ContentID += "x" }}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			record, e := DecodeActivationRecord(f.current.ActivationRecord)
			if e != nil {
				t.Fatal(e)
			}
			defer destroyMaintenanceActivationRecordV1(&record)
			mutate(&record)
			encoded, e := EncodeActivationRecord(record)
			if e != nil {
				t.Fatal(e)
			}
			current := f.current
			current.ActivationRecord = encoded
			ticket, _ := reserveProductionSlotV1(&HandleRegistry{})
			p, _ := newProductionParentV1(ticket, 80<<20, time.Time{})
			opening, _ := p.beginUseV1(0, productionBudgetChargeV1{})
			platform := &productionSnapshotPlatformV1{snapshot: current}
			owner, s := newProductionAdmissionV1(p, opening, current, projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false)), &productionRealCurrentV1{}, platform, func() time.Time { return f.now }, time.Now, rates, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 80 << 20, MaxArtifactBytes: 1 << 20, MaxPublicationBytes: 8 << 20})
			p.finishUseV1(opening)
			if p.admission != nil {
				if close := p.admission.closeV1(context.Background()); close != 0 {
					t.Fatal(close)
				}
			}
			if owner != nil || s == 0 || platform.registrations != 0 {
				t.Fatal("record mismatch escaped", s, platform.registrations)
			}
			if p.admission != nil && (p.admission.seedLive || p.admission.seed != ([32]byte{})) {
				t.Fatal("failed seed retained")
			}
		})
	}
}

func TestProductionAdmissionV1CleanupUnprovenRetainsOwnership(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	ticket, _ := reserveProductionSlotV1(&HandleRegistry{})
	p, _ := newProductionParentV1(ticket, 80<<20, time.Time{})
	opening, _ := p.beginUseV1(0, productionBudgetChargeV1{})
	platform := &productionSnapshotPlatformV1{snapshot: f.current, closeCode: CodeStateCorrupt}
	owner, s := newProductionAdmissionV1(p, opening, f.current, projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false)), &productionRealCurrentV1{}, platform, func() time.Time { return f.now }, time.Now, rates, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 80 << 20, MaxArtifactBytes: 1 << 20, MaxPublicationBytes: 8 << 20})
	if owner != nil || s != 3 || p.admission.failedLease == nil {
		t.Fatal("unproven lease publication", s)
	}
	p.finishUseV1(opening)
	if p.retireV1() != 3 || p.admission.registration == nil || p.admission.registrationClosed {
		t.Fatal("unproven registration cleanup lost owner")
	}
	if _, s := p.budget.chargeV1(p.admission.ownerTicket); s != 0 {
		t.Fatal("cleanup-unproven ticket released")
	}
	if p.retireV1() != 3 || platform.closes != 1 {
		t.Fatal("retried uncertain close", platform.closes)
	}
	if p.admission.invalidateV1() == CodeOK {
		t.Fatal("uncertain cleanup acknowledged as joined")
	}
}

func TestProductionAdmissionV1AsyncInvalidationOverlapsPlatform(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	platform := &productionSnapshotPlatformV1{snapshot: f.current}
	o := productionAdmittedFixtureV1(t, f, platform, rates)
	use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
	a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
	if s != 0 {
		t.Fatal(s)
	}
	b, s := a.BorrowV1()
	if s != 0 {
		t.Fatal(s)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	platform.revalidateHook = func() { close(entered); <-release }
	checked := make(chan int32, 1)
	go func() { _, s := b.RevalidateV1(context.Background()); checked <- s }()
	<-entered
	before := o.parent.budget.owned
	// This caller is not the blocked Revalidate goroutine. The coarse guard
	// must still refuse a clean acknowledgment and retain the same ownership.
	if code := platform.invalidate(); code != CodeStateCorrupt {
		t.Error("asynchronous overlap falsely acknowledged", code)
	}
	<-o.parent.cancelContext.Done()
	if !o.seedLive || o.parent.budget.owned != before || o.parent.finishUseV1(use) != 3 || platform.closes != 0 {
		t.Error("overlap released live authority")
	}
	if _, s := o.parent.budget.chargeV1(o.ownerTicket); s != 0 {
		t.Error("overlap lost owner ticket")
	}
	closed := make(chan int32, 1)
	go func() { closed <- o.closeV1(context.Background()) }()
	select {
	case <-closed:
		t.Error("external cleanup did not join platform work")
	default:
	}
	close(release)
	if s := <-checked; s != 7 {
		t.Error("revision cancellation did not suppress revalidation", s)
	}
	if b.Close() != nil || o.resources.destroyV1() != 0 || o.parent.finishUseV1(use) != 0 {
		t.Fatal("attempt join failed")
	}
	if s := <-closed; s != 0 {
		t.Fatal("external joined cleanup", s)
	}
	if o.seedLive || platform.closes != 1 || !o.registrationClosed {
		t.Error("joined cleanup retained authority")
	}
	if _, s := o.parent.budget.chargeV1(o.ownerTicket); s == 0 {
		t.Error("joined cleanup retained owner ticket")
	}
}

// A lock-backed clock permits race coverage while only the owner accepts time.
type productionTestClockV1 struct {
	mu sync.Mutex
	at time.Time
}

func (c *productionTestClockV1) now() time.Time   { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *productionTestClockV1) set(at time.Time) { c.mu.Lock(); c.at = at; c.mu.Unlock() }

// The platform owns the actual snapshot. Matching is necessary but never
// replaces the concrete signed-current verifier used above.
type productionSnapshotPlatformV1 struct {
	snapshot                                     MaintenanceCurrentInputV1
	invalidate                                   func() ErrorCode
	expected                                     *ProductionCurrentExpectationV1
	registrations, revalidations, leases, closes int
	stage                                        string
	callbackResult                               ErrorCode
	result                                       MaintenanceResultV1
	closeCode                                    ErrorCode
	revalidateHook                               func()
	acquireHook                                  func()
}

func (p *productionSnapshotPlatformV1) at(stage string) {
	if p.stage == stage {
		p.callbackResult = p.invalidate()
	}
}
func (p *productionSnapshotPlatformV1) RegisterProductionCurrentV1(epoch uint64, expected *ProductionCurrentExpectationV1, invalidate func() ErrorCode) (MaintenanceRevisionRegistrationV1, ErrorCode) {
	p.registrations++
	p.invalidate, p.expected = invalidate, expected
	p.at("register")
	if epoch == 0 || !expected.MatchesV1(p.snapshot) {
		return nil, CodeStateCorrupt
	}
	return p, CodeOK
}
func (p *productionSnapshotPlatformV1) Revalidate(context.Context) MaintenanceResultV1 {
	p.revalidations++
	p.at("revalidate")
	if p.revalidateHook != nil {
		p.revalidateHook()
	}
	if !p.expected.MatchesV1(p.snapshot) {
		return MaintenanceInvalidState
	}
	return p.result
}
func (p *productionSnapshotPlatformV1) AcquirePublication(context.Context) (MaintenancePublicationLeaseV1, MaintenanceResultV1) {
	p.leases++
	if p.acquireHook != nil {
		p.acquireHook()
	}
	p.at("acquire")
	return productionSnapshotLeaseV1{p}, p.result
}
func (p *productionSnapshotPlatformV1) Close() ErrorCode { p.closes++; return p.closeCode }

type productionSnapshotLeaseV1 struct{ p *productionSnapshotPlatformV1 }

func (l productionSnapshotLeaseV1) IsCurrent() bool {
	l.p.at("current")
	return l.p.expected.MatchesV1(l.p.snapshot)
}
func (l productionSnapshotLeaseV1) Close() ErrorCode { l.p.at("lease-close"); return l.p.closeCode }

func TestProductionAdmissionV1ActualDefaultOpening(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	original := bytes.Clone(f.current.RecipientPrivate)
	ticket, s := reserveProductionSlotV1(&HandleRegistry{})
	if s != 0 {
		t.Fatal(s)
	}
	p, s := newProductionParentV1(ticket, 80<<20, time.Time{})
	if s != 0 {
		t.Fatal(s)
	}
	opening, s := p.beginUseV1(productionUseOpeningV1, productionBudgetChargeV1{})
	if s != 0 {
		t.Fatal(s)
	}
	env := &productionRealCurrentV1{}
	platform := &productionSnapshotPlatformV1{snapshot: f.current}
	settings := projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false))
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	owner, s := newProductionAdmissionV1(p, opening, f.current, settings, env, platform, func() time.Time { return f.now }, time.Now, rates, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 80 << 20, MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20})
	if s != 0 || owner == nil {
		t.Fatal("ordinary default opening", s)
	}
	if env.calls != 1 || platform.registrations != 1 || platform.leases != 1 {
		t.Fatal("opening repeated authority", env.calls, platform.registrations, platform.leases)
	}
	if env.limits.MaxArtifactBytes != uint32(len(f.artifact)) || env.limits.MaxPublicationBytes != 8<<20 ||
		env.limits.OwnedBudgetBytes == 0 || env.limits.OwnedBudgetBytes >= 80<<20 {
		t.Error("immutable current did not receive exact input cap with unchanged residual/publication limits", env.limits)
	}
	if !bytes.Equal(original, f.current.RecipientPrivate) {
		t.Fatal("caller private input changed")
	}
	if owner.plan.Digest == ([32]byte{}) || owner.resources == nil || !owner.seedLive {
		t.Fatal("missing retained authority")
	}
	if err := owner.planCheckV1(f.now); err != nil {
		t.Fatal("preview destruction invalidated retained plan", err)
	}
	bounds, err := owner.current.BoundsV1()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("default=%d currentReservedPeak=%d currentRetained=%d installedTotal=%d rates=%d parent=%d admission=%d verifiedArguments=%d", p.budget.cap, bounds.PeakReservedBytes, bounds.RetainedBytes, p.budget.owned, rates.OwnedBytesV1(), unsafe.Sizeof(*p), unsafe.Sizeof(*owner), unsafe.Sizeof(productionVerifiedArgumentsV1{}))
	if p.finishUseV1(opening) != 0 {
		t.Fatal("opening finish")
	}
	if s := owner.closeV1(context.Background()); s != 0 {
		t.Fatal("close", s)
	}
	if owner.seedLive || owner.seed != ([32]byte{}) || platform.closes != 1 {
		t.Fatal("ownership retirement")
	}
}

func TestProductionAdmissionV1PlatformResults(t *testing.T) {
	cases := []struct {
		in   MaintenanceResultV1
		want int32
	}{{MaintenanceSuccess, 0}, {MaintenanceNoChange, 18}, {MaintenanceNotAdmitted, 1}, {MaintenanceInvalidRequest, 2}, {MaintenanceInvalidState, 3}, {MaintenanceSizeLimit, 4}, {MaintenanceResourceLimit, 5}, {MaintenanceRateLimited, 6}, {MaintenanceCancelled, 7}, {MaintenanceTimeout, 8}, {MaintenanceNetworkUnavailable, 9}, {MaintenanceDestinationDenied, 10}, {MaintenanceTLSTrustUnavailable, 21}, {MaintenanceTLSRejected, 14}, {MaintenanceFetchRejected, 18}, {MaintenanceSignatureInvalid, 22}, {MaintenanceWrongRecipient, 23}, {MaintenanceProfileMismatch, 22}, {MaintenanceRollback, 24}, {MaintenanceExpired, 12}, {MaintenanceRevoked, 13}, {MaintenanceIncompatible, 25}, {MaintenanceRootRotationRejected, 22}, {MaintenanceInternalFailure, 18}, {255, 18}}
	for _, c := range cases {
		if got := productionMaintenanceStatusV1(c.in); got != c.want {
			t.Fatalf("M1=%d P1=%d want=%d", c.in, got, c.want)
		}
	}
}
