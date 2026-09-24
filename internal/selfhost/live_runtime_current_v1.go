// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"sync"
	"time"
	"unsafe"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
)

// LiveRuntimeCurrentV1 owns one immutable same-pass current proof, not a
// protected-state registration. The later parent must invalidate it on current
// revision changes and retain its counted call until WithVerifiedV1 returns.
// The self identity is immutable after publication, including after Destroy.
type LiveRuntimeCurrentV1 struct {
	self                             *LiveRuntimeCurrentV1
	mu                               sync.Mutex
	verified                         profile.OfflineVerifiedArtifact
	admission                        profile.VerifiedActivationAdmission
	policy                           runtimepolicy.PolicyV2
	deadline, lastNow                time.Time
	limits                           LiveMaintenanceLimits
	bounds                           LiveMaintenanceBounds
	borrowActive, closing, destroyed bool
}

// One actual synchronous argument holder, with borrowed backing only. Its
// fixed storage is reserved in addition to the existing codec stage certificate.
type liveRuntimeCurrentBorrowV1 struct {
	verified profile.OfflineVerifiedArtifact
	state    lifecycle.VerifiedState
	policy   runtimepolicy.PolicyV2
	deadline time.Time
	use      func(profile.OfflineVerifiedArtifact, lifecycle.VerifiedState, runtimepolicy.PolicyV2, time.Time) error
}

func VerifyLiveRuntimeCurrentForRecipient(encoded []byte, now time.Time, current lifecycle.VerifiedState, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1, limits LiveMaintenanceLimits) (*LiveRuntimeCurrentV1, error) {
	return verifyLiveRuntimeCurrentForRecipientV1(encoded, now, current, request, private, limits, maintenanceVerifyCore)
}

func verifyLiveRuntimeCurrentForRecipientV1(encoded []byte, now time.Time, current lifecycle.VerifiedState, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1, limits LiveMaintenanceLimits, core liveCurrentCoreVerifierV1) (*LiveRuntimeCurrentV1, error) {
	if current.Status != lifecycle.Admitted || current.Generation == 0 {
		return nil, maintenanceFailure(LiveMaintenanceInvalidState)
	}
	t, err := verifyLiveCurrentCoreV1(encoded, now, current.Generation, request, private, limits, uint64(unsafe.Sizeof(LiveRuntimeCurrentV1{}))+uint64(unsafe.Sizeof(liveRuntimeCurrentBorrowV1{})), core)
	if err != nil {
		return nil, err
	}
	defer t.destroy()
	var diagnostic liveMaintenanceDiagnostic
	a, err := liveActivationRequestFromVerified(encoded, now, current, t.resolver, t.opener, liveResourceTypedFirstV1, &diagnostic, t.verified)
	defer diagnostic.destroyRequest()
	if err != nil {
		return nil, maintenanceFailure(diagnostic.reason)
	}
	resetLiveMaintenanceAdmissionDiagnostic(&diagnostic, t.opener)
	admission, err := profile.VerifyActivationAdmission(a)
	if err != nil {
		if diagnostic.rejection.Stage == profile.VerificationStageLifecycle {
			diagnostic.reason = LiveMaintenanceInvalidState
		}
		return nil, maintenanceFailure(diagnostic.reason)
	}
	defer admission.Destroy()
	if admission.CurrentState() != current {
		return nil, maintenanceFailure(LiveMaintenanceInvalidState)
	}
	deadline, policy, err := maintenanceAuthorityProjectionV1(t.verified.Profile, t.bundle, now)
	if err != nil {
		return nil, err
	}
	defer destroyMaintenancePolicy(&policy)
	v := &LiveRuntimeCurrentV1{verified: t.verified, admission: admission, policy: policy, deadline: deadline, lastNow: now, limits: limits}
	v.self = v
	// Move, never clone, the verified output, the actual activation proof and
	// the one policy decode. The private credential/bundle graph never escapes.
	t.verified = profile.OfflineVerifiedArtifact{}
	admission = profile.VerifiedActivationAdmission{}
	policy = runtimepolicy.PolicyV2{}
	v.bounds = LiveMaintenanceBounds{BudgetBytes: limits.OwnedBudgetBytes, RetainedBytes: v.retainedChargeV1(), PeakReservedBytes: t.workspace}
	retainedWithBorrow, ok := maintenanceAdd(v.bounds.RetainedBytes, uint64(unsafe.Sizeof(liveRuntimeCurrentBorrowV1{})))
	if !ok || retainedWithBorrow > t.workspace {
		v.Destroy()
		return nil, maintenanceFailure(LiveMaintenanceInternalFailure)
	}
	return v, nil
}

func (v *LiveRuntimeCurrentV1) BoundsV1() (LiveMaintenanceBounds, error) {
	if v == nil || v.self != v {
		return LiveMaintenanceBounds{}, maintenanceFailure(LiveMaintenanceInvalidState)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closing || v.destroyed {
		return LiveMaintenanceBounds{}, maintenanceFailure(LiveMaintenanceInvalidState)
	}
	return v.bounds, nil
}

// CheckAtV1 checks time only while the original admitted inputs are immutable.
// Changed-current invalidation belongs to the parent's revision fence, not this
// descriptive time check. A rejected time never renews or mutates the proof.
func (v *LiveRuntimeCurrentV1) CheckAtV1(now time.Time) error {
	if v == nil || v.self != v {
		return maintenanceFailure(LiveMaintenanceInvalidState)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closing || v.destroyed || v.borrowActive {
		return maintenanceFailure(LiveMaintenanceInvalidState)
	}
	if now.IsZero() || now.Unix() <= 0 || now.Before(v.lastNow) || !now.Before(v.deadline) {
		return maintenanceFailure(LiveMaintenanceExpired)
	}
	v.lastNow = now
	return nil
}

// WithVerifiedV1 is one synchronous borrow by trusted in-repository code. The
// callback must not mutate these aliasing slices or retain them beyond owner
// lifetime. Go does not make the view physically read-only. No parent can use
// Destroy as a joined barrier: the counted call remains live until this returns.
func (v *LiveRuntimeCurrentV1) WithVerifiedV1(use func(profile.OfflineVerifiedArtifact, lifecycle.VerifiedState, runtimepolicy.PolicyV2, time.Time) error) error {
	if v == nil || v.self != v || use == nil {
		return maintenanceFailure(LiveMaintenanceInvalidState)
	}
	v.mu.Lock()
	if v.closing || v.destroyed || v.borrowActive {
		v.mu.Unlock()
		return maintenanceFailure(LiveMaintenanceInvalidState)
	}
	borrow := liveRuntimeCurrentBorrowV1{v.verified, v.admission.CurrentState(), v.policy, v.deadline, use}
	v.borrowActive = true
	v.bounds.OperationReservedBytes = uint64(unsafe.Sizeof(borrow))
	v.mu.Unlock()
	defer func() {
		v.mu.Lock()
		defer v.mu.Unlock()
		borrow = liveRuntimeCurrentBorrowV1{}
		v.borrowActive = false
		v.bounds.OperationReservedBytes = 0
		if v.closing {
			v.destroyLockedV1()
		}
	}()
	return borrow.use(borrow.verified, borrow.state, borrow.policy, borrow.deadline)
}

// Destroy retires immediately but defers wiping an active borrowed graph until
// its callback unwinds (also on error/panic). It never waits for that callback,
// so reentrant retirement cannot self-join or clear active borrowed backing.
func (v *LiveRuntimeCurrentV1) Destroy() {
	if v == nil || v.self != v {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closing = true
	if !v.borrowActive {
		v.destroyLockedV1()
	}
}

func (v *LiveRuntimeCurrentV1) destroyLockedV1() {
	if v.destroyed {
		return
	}
	destroyLiveMaintenanceOffline(&v.verified)
	v.admission.Destroy()
	destroyMaintenancePolicy(&v.policy)
	v.deadline, v.lastNow = time.Time{}, time.Time{}
	v.limits, v.bounds = LiveMaintenanceLimits{}, LiveMaintenanceBounds{}
	v.destroyed = true
}

func (v *LiveRuntimeCurrentV1) retainedChargeV1() uint64 {
	p := v.verified.Profile
	// Embedded holders are in sizeof(root), not charged a second time.
	n := uint64(unsafe.Sizeof(*v)) + uint64(cap(v.verified.ExactArtifact)+cap(v.verified.ExactSignedObject))
	n += maintenanceProfileCharge(p) - uint64(unsafe.Sizeof(p))
	n += uint64(len(v.verified.Metadata.Class) + len(v.verified.Metadata.AudienceClass) + len(v.verified.Metadata.RecipientHint))
	n += maintenanceOpaqueCharge(len(v.verified.ExactArtifact), len(v.verified.ExactSignedObject), p) - uint64(unsafe.Sizeof(v.admission)) - uint64(unsafe.Sizeof(p))
	return n + maintenanceRuntimePolicyBackingV1(v.policy)
}

func maintenanceRuntimePolicyBackingV1(p runtimepolicy.PolicyV2) uint64 {
	n := uint64(cap(p.LiveProgram) + cap(p.TLSLeafDER) + cap(p.ClientIPv4) + cap(p.DNSIPv4) + cap(p.ClientIPv6) + cap(p.DNSIPv6) + cap(p.Fallback.EndpointIndexes))
	n += uint64(cap(p.Endpoints))*uint64(unsafe.Sizeof(runtimepolicy.EndpointV2{})) + uint64(cap(p.Routes))*uint64(unsafe.Sizeof(runtimepolicy.PrefixV2{}))
	n += uint64(cap(p.DNSServers))*uint64(unsafe.Sizeof([]byte(nil))) + uint64(cap(p.AllowedIPModes))*uint64(unsafe.Sizeof(runtimepolicy.IPModeV2(""))) + uint64(cap(p.AllowedProtocols))*uint64(unsafe.Sizeof(runtimepolicy.PayloadProtocolV2("")))
	for _, s := range []string{p.WireProtocol, p.CarrierFamily, p.ClientAuthKeyID, p.RelayAuthKeyID, p.TLSServerName} {
		n += uint64(len(s))
	}
	for _, e := range p.Endpoints {
		n += uint64(cap(e.Address))
	}
	for _, r := range p.Routes {
		n += uint64(cap(r.Address))
	}
	for _, s := range p.DNSServers {
		n += uint64(cap(s))
	}
	for _, s := range p.AllowedIPModes {
		n += uint64(len(s))
	}
	for _, s := range p.AllowedProtocols {
		n += uint64(len(s))
	}
	return n + maintenanceServicesCharge(p.Services)
}
