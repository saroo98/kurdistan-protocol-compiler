// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/x509"
	"math"
	"strings"
	"time"
	"unsafe"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
)

type LiveMaintenanceFailureV1 uint8

const (
	LiveMaintenanceNotAdmitted          LiveMaintenanceFailureV1 = 2
	LiveMaintenanceInvalidRequest       LiveMaintenanceFailureV1 = 3
	LiveMaintenanceInvalidState         LiveMaintenanceFailureV1 = 4
	LiveMaintenanceSizeLimit            LiveMaintenanceFailureV1 = 5
	LiveMaintenanceResourceLimit        LiveMaintenanceFailureV1 = 6
	LiveMaintenanceSignatureInvalid     LiveMaintenanceFailureV1 = 15
	LiveMaintenanceWrongRecipient       LiveMaintenanceFailureV1 = 16
	LiveMaintenanceProfileMismatch      LiveMaintenanceFailureV1 = 17
	LiveMaintenanceRollback             LiveMaintenanceFailureV1 = 18
	LiveMaintenanceExpired              LiveMaintenanceFailureV1 = 19
	LiveMaintenanceRevoked              LiveMaintenanceFailureV1 = 20
	LiveMaintenanceIncompatible         LiveMaintenanceFailureV1 = 21
	LiveMaintenanceRootRotationRejected LiveMaintenanceFailureV1 = 22
	LiveMaintenanceInternalFailure      LiveMaintenanceFailureV1 = 23
)

// LiveMaintenanceVerificationError contains no artifact or wrapped error data.
type LiveMaintenanceVerificationError struct{ reason LiveMaintenanceFailureV1 }

func (*LiveMaintenanceVerificationError) Error() string {
	return "selfhost: maintenance verification rejected"
}
func (e *LiveMaintenanceVerificationError) Reason() LiveMaintenanceFailureV1 {
	if e != nil {
		switch e.reason {
		case LiveMaintenanceNotAdmitted, LiveMaintenanceInvalidRequest, LiveMaintenanceInvalidState, LiveMaintenanceSizeLimit, LiveMaintenanceResourceLimit, LiveMaintenanceSignatureInvalid, LiveMaintenanceWrongRecipient, LiveMaintenanceProfileMismatch, LiveMaintenanceRollback, LiveMaintenanceExpired, LiveMaintenanceRevoked, LiveMaintenanceIncompatible, LiveMaintenanceRootRotationRejected:
			return e.reason
		}
	}
	return LiveMaintenanceInternalFailure
}

// This fact belongs to one synchronous call. It is diagnostic, never a proof.
type liveMaintenanceDiagnostic struct {
	expectedProfile *envelope.CanonicalProfileV1 // immutable owner context, operation-local
	requestBundle   *liveProfileBundleV2         // operation-owned request capture, never a callback
	reason          LiveMaintenanceFailureV1
	rejection       profile.VerificationRejection
}

func (d *liveMaintenanceDiagnostic) reset() {
	if d != nil {
		*d = liveMaintenanceDiagnostic{expectedProfile: d.expectedProfile, requestBundle: d.requestBundle}
	}
}
func (d *liveMaintenanceDiagnostic) destroyRequest() {
	if d != nil {
		destroyMaintenanceBundle(d.requestBundle)
		d.requestBundle = nil
	}
}
func (d *liveMaintenanceDiagnostic) fail(reason LiveMaintenanceFailureV1) {
	if d != nil && d.reason == 0 {
		d.reason = reason
	}
}
func (d *liveMaintenanceDiagnostic) sink(opener profile.OfflineRecipientOpener) profile.VerificationRejectionSink {
	if d == nil {
		return nil
	}
	return func(r profile.VerificationRejection) {
		if d.reason != 0 {
			return
		}
		d.rejection = r
		if r.Stage == profile.VerificationStageRecipient && r.Reason == profile.VerificationReasonRecipientRejected {
			if o, ok := opener.(*liveResourceRecipientOpener); ok && o.resourceError() != nil {
				d.resource(o.resourceError())
				return
			}
		}
		switch r.Reason {
		case profile.VerificationReasonMalformed:
			d.fail(LiveMaintenanceInvalidRequest)
		case profile.VerificationReasonSignatureInvalid:
			d.fail(LiveMaintenanceSignatureInvalid)
		case profile.VerificationReasonRecipientRejected:
			d.fail(LiveMaintenanceWrongRecipient)
		case profile.VerificationReasonBindingMismatch, profile.VerificationReasonScopeMismatch:
			d.fail(LiveMaintenanceProfileMismatch)
		case profile.VerificationReasonRootMismatch:
			d.fail(LiveMaintenanceRootRotationRejected)
		case profile.VerificationReasonFloorRejected, profile.VerificationReasonLifecycleMismatch:
			d.fail(LiveMaintenanceRollback)
		case profile.VerificationReasonTimeInvalid:
			d.fail(LiveMaintenanceExpired)
		case profile.VerificationReasonExplicitRevocation:
			d.fail(LiveMaintenanceRevoked)
		case profile.VerificationReasonIncompatible:
			d.fail(LiveMaintenanceIncompatible)
		default:
			d.fail(LiveMaintenanceInternalFailure)
		}
	}
}
func (d *liveMaintenanceDiagnostic) resource(err error) {
	if err == errLiveResourceSize {
		d.fail(LiveMaintenanceSizeLimit)
	} else {
		d.fail(LiveMaintenanceInvalidRequest)
	}
}

func resetLiveMaintenanceAdmissionDiagnostic(d *liveMaintenanceDiagnostic, opener *liveResourceRecipientOpener) {
	d.reset()
	if opener != nil {
		opener.failure = liveResourceFailureNone
	}
}

func destroyLiveMaintenanceOffline(v *profile.OfflineVerifiedArtifact) {
	if v == nil {
		return
	}
	clear(v.ExactArtifact)
	clear(v.ExactSignedObject)
	clear(v.Profile.Policy)
	*v = profile.OfflineVerifiedArtifact{}
}

// LiveMaintenanceAdmission is single-owner and synchronously serialized.
// The native parent must join its operation before Destroy. It does not assert
// a protected Android revision, run timers, mutate storage or start a tunnel.
type LiveMaintenanceAdmission struct {
	probe             *liveMaintenanceProbeState
	candidate         *LiveMaintenanceCandidate
	artifact          []byte
	admission         profile.VerifiedActivationAdmission
	value             envelope.CanonicalProfileV1
	bundle            liveProfileBundleV2
	request           enrollment.PublicRequestV1
	private           enrollment.PrivateBundleV1
	binding           profile.RecipientBinding
	services          *runtimepolicy.ServicesV1
	families          uint8
	deadline, lastNow time.Time
	limits            LiveMaintenanceLimits
	bounds            LiveMaintenanceBounds
}

func VerifyLiveMaintenanceCurrentForRecipient(encoded []byte, now time.Time, minimumGeneration uint64, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1, limits LiveMaintenanceLimits) (profile.OfflineVerifiedArtifact, LiveMaintenanceBounds, error) {
	t, err := verifyLiveCurrentCoreV1(encoded, now, minimumGeneration, request, private, limits, 0, maintenanceVerifyCore)
	if err != nil {
		return profile.OfflineVerifiedArtifact{}, LiveMaintenanceBounds{}, err
	}
	defer t.destroy()
	// Preserve the maintenance wrapper's early opener retirement. Only the
	// production continuation needs it alive for activation admission.
	t.opener.Destroy()
	t.opener = nil
	_, services, _, err := maintenanceAuthority(t.verified.Profile, t.bundle, now)
	destroyMaintenanceServices(services)
	if err != nil {
		return profile.OfflineVerifiedArtifact{}, LiveMaintenanceBounds{}, err
	}
	verified := t.verified
	t.verified = profile.OfflineVerifiedArtifact{}
	retained := uint64(unsafe.Sizeof(verified)) + uint64(cap(verified.ExactArtifact)+cap(verified.ExactSignedObject)) + maintenanceProfileCharge(verified.Profile)
	retained += uint64(len(verified.Metadata.Class) + len(verified.Metadata.AudienceClass) + len(verified.Metadata.RecipientHint))
	return verified, LiveMaintenanceBounds{BudgetBytes: limits.OwnedBudgetBytes, RetainedBytes: retained, PeakReservedBytes: t.workspace}, nil
}

// The private function parameter is a synchronous counting/failure seam for
// tests. Both exported producers always supply maintenanceVerifyCore itself.
type liveCurrentCoreVerifierV1 func([]byte, time.Time, uint64, enrollment.PublicRequestV1, enrollment.PrivateBundleV1, ...*envelope.CanonicalProfileV1) (liveProfileBundleV2, profile.OfflineVerifiedArtifact, *liveResourceRecipientOpener, profile.RecipientResolver, error)

type liveCurrentVerificationV1 struct {
	bundle    liveProfileBundleV2
	verified  profile.OfflineVerifiedArtifact
	opener    *liveResourceRecipientOpener
	resolver  profile.RecipientResolver
	workspace uint64
}

func (t *liveCurrentVerificationV1) destroy() {
	if t == nil {
		return
	}
	if t.opener != nil {
		t.opener.Destroy()
	}
	destroyLiveMaintenanceOffline(&t.verified)
	destroyMaintenanceBundle(&t.bundle)
	*t = liveCurrentVerificationV1{}
}

func verifyLiveCurrentCoreV1(encoded []byte, now time.Time, minimumGeneration uint64, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1, limits LiveMaintenanceLimits, extra uint64, core liveCurrentCoreVerifierV1) (*liveCurrentVerificationV1, error) {
	if err := maintenanceEntry(encoded, request, private, limits); err != nil {
		return nil, err
	}
	workspace, ok := maintenanceAdd(maintenanceVerificationWorkspace(limits), extra)
	if !ok || workspace > limits.OwnedBudgetBytes {
		return nil, maintenanceFailure(LiveMaintenanceResourceLimit)
	}
	t := &liveCurrentVerificationV1{workspace: workspace}
	var err error
	t.bundle, t.verified, t.opener, t.resolver, err = core(encoded, now, minimumGeneration, request, private)
	if err != nil {
		t.destroy()
		return nil, err
	}
	return t, nil
}

func maintenanceEntry(encoded []byte, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1, limits LiveMaintenanceLimits) error {
	if !validMaintenanceLimits(limits) {
		return maintenanceFailure(LiveMaintenanceInvalidRequest)
	}
	if len(encoded) == 0 || uint64(len(encoded)) > uint64(limits.MaxArtifactBytes) {
		return maintenanceFailure(LiveMaintenanceSizeLimit)
	}
	if !liveResourceRequestShape(request) || !liveResourcePrivateShape(private) {
		return maintenanceFailure(LiveMaintenanceInvalidRequest)
	}
	return nil
}

func maintenanceVerifyCore(encoded []byte, now time.Time, floor uint64, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1, expected ...*envelope.CanonicalProfileV1) (liveProfileBundleV2, profile.OfflineVerifiedArtifact, *liveResourceRecipientOpener, profile.RecipientResolver, error) {
	var diagnostic liveMaintenanceDiagnostic
	if len(expected) != 0 {
		diagnostic.expectedProfile = expected[0]
	}
	b, _, resolver, concrete, err := liveRecipientProvidersDiagnosticCore(encoded, now, floor, request, private, liveResourceTypedFirstV1, &diagnostic)
	if err != nil {
		return liveProfileBundleV2{}, profile.OfflineVerifiedArtifact{}, nil, nil, maintenanceFailure(diagnostic.reason)
	}
	opener := &liveResourceRecipientOpener{opener: concrete, mode: liveResourceTypedFirstV1}
	verified, err := verifyLiveAndroidArtifactCore(encoded, now, floor, resolver, opener, liveResourceTypedFirstV1, &diagnostic)
	if err != nil {
		opener.Destroy()
		destroyMaintenanceBundle(&b)
		return liveProfileBundleV2{}, profile.OfflineVerifiedArtifact{}, nil, nil, maintenanceFailure(diagnostic.reason)
	}
	return b, verified, opener, resolver, nil
}

// current must be the exact freshly recipient-verified protected runtime
// record. This internal reconstruction does not replace that parent gate.
func maintenanceInputWorkspaceV1(encoded []byte, limits LiveMaintenanceLimits) (uint64, error) {
	if !validMaintenanceLimits(limits) {
		return 0, maintenanceFailure(LiveMaintenanceInvalidRequest)
	}
	if len(encoded) == 0 || uint64(len(encoded)) > uint64(limits.MaxArtifactBytes) {
		return 0, maintenanceFailure(LiveMaintenanceSizeLimit)
	}
	// Local reservation input only. Neither the retained future-input limits
	// nor the formula's independent fixed terms are changed.
	sized := limits
	sized.MaxArtifactBytes = uint32(len(encoded))
	return maintenanceVerificationWorkspace(sized), nil
}

func NewLiveMaintenanceAdmissionForRecipient(encoded []byte, now time.Time, current lifecycle.VerifiedState, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1, limits LiveMaintenanceLimits) (*LiveMaintenanceAdmission, error) {
	if current.Status != lifecycle.Admitted || current.Generation == 0 {
		return nil, maintenanceFailure(LiveMaintenanceInvalidState)
	}
	if err := maintenanceEntry(encoded, request, private, limits); err != nil {
		return nil, err
	}
	inputWorkspace, err := maintenanceInputWorkspaceV1(encoded, limits)
	if err != nil {
		return nil, err
	}
	workspace, ok := maintenanceAdd(inputWorkspace, uint64(unsafe.Sizeof(LiveMaintenanceAdmission{})))
	if !ok || workspace > limits.OwnedBudgetBytes {
		return nil, maintenanceFailure(LiveMaintenanceResourceLimit)
	}
	b, verified, opener, resolver, err := maintenanceVerifyCore(encoded, now, current.Generation, request, private)
	if err != nil {
		return nil, err
	}
	defer opener.Destroy()
	defer destroyLiveMaintenanceOffline(&verified)
	keep := false
	defer func() {
		if !keep {
			destroyMaintenanceBundle(&b)
		}
	}()
	var diagnostic liveMaintenanceDiagnostic
	a, err := liveActivationRequestFromVerified(encoded, now, current, resolver, opener, liveResourceTypedFirstV1, &diagnostic, verified)
	defer diagnostic.destroyRequest()
	if err != nil {
		return nil, maintenanceFailure(diagnostic.reason)
	}
	resetLiveMaintenanceAdmissionDiagnostic(&diagnostic, opener)
	admission, err := profile.VerifyActivationAdmission(a)
	if err != nil {
		if diagnostic.rejection.Stage == profile.VerificationStageLifecycle {
			diagnostic.reason = LiveMaintenanceInvalidState
		}
		return nil, maintenanceFailure(diagnostic.reason)
	}
	if admission.CurrentState() != current {
		admission.Destroy()
		return nil, maintenanceFailure(LiveMaintenanceInvalidState)
	}
	deadline, services, families, err := maintenanceAuthority(verified.Profile, b, now)
	if err != nil {
		admission.Destroy()
		return nil, err
	}
	owner := &LiveMaintenanceAdmission{artifact: verified.ExactArtifact, admission: admission, value: verified.Profile, bundle: b, binding: resolver.(liveRecipientResolver).binding, services: services, families: families, deadline: deadline, lastNow: now, limits: limits}
	verified.ExactArtifact = nil
	verified.Profile = envelope.CanonicalProfileV1{}
	owner.request = request
	owner.request.RequestID = strings.Clone(request.RequestID)
	owner.request.RecipientKeyID = strings.Clone(request.RecipientKeyID)
	owner.request.ClientAuthKeyID = strings.Clone(request.ClientAuthKeyID)
	owner.request.RecipientPublic = bytes.Clone(request.RecipientPublic)
	owner.request.ClientAuthPublic = bytes.Clone(request.ClientAuthPublic)
	owner.request.Nonce = bytes.Clone(request.Nonce)
	owner.request.Signature = bytes.Clone(request.Signature)
	owner.private = enrollment.PrivateBundleV1{RecipientPrivate: bytes.Clone(private.RecipientPrivate), ClientAuthSeed: bytes.Clone(private.ClientAuthSeed)}
	owner.binding.Hint = owner.request.RequestID
	owner.binding.KeyID = owner.request.RecipientKeyID
	clear(owner.bundle.SealedProfile)
	owner.bundle.SealedProfile = nil
	owner.bounds = LiveMaintenanceBounds{BudgetBytes: limits.OwnedBudgetBytes, RetainedBytes: owner.retainedCharge(len(verified.ExactSignedObject)), PeakReservedBytes: workspace}
	if owner.bounds.RetainedBytes > workspace {
		owner.Destroy()
		return nil, maintenanceFailure(LiveMaintenanceInternalFailure)
	}
	keep = true
	return owner, nil
}

func maintenanceAuthority(value envelope.CanonicalProfileV1, b liveProfileBundleV2, now time.Time) (time.Time, *runtimepolicy.ServicesV1, uint8, error) {
	deadline, p, err := maintenanceAuthorityProjectionV1(value, b, now)
	if err != nil {
		return time.Time{}, nil, 0, err
	}
	defer destroyMaintenancePolicy(&p)
	families := uint8(0)
	if len(p.ClientIPv4) > 0 {
		families |= 1
	}
	if len(p.ClientIPv6) > 0 {
		families |= 2
	}
	services := p.Services
	p.Services = nil
	return deadline, services, families, nil
}

func maintenanceAuthorityProjectionV1(value envelope.CanonicalProfileV1, b liveProfileBundleV2, now time.Time) (time.Time, runtimepolicy.PolicyV2, error) {
	r := b.Revocations
	if r.IssuedAt <= 0 || r.MaxOfflineStalenessSecs > uint64(math.MaxInt64-r.IssuedAt-1) {
		return time.Time{}, runtimepolicy.PolicyV2{}, maintenanceFailure(LiveMaintenanceExpired)
	}
	end := min(value.ValidUntil, b.Root.ValidUntil, b.Delegation.ValidUntil, r.ExpiresAt, r.IssuedAt+int64(r.MaxOfflineStalenessSecs)+1)
	p, err := runtimepolicy.DecodeRuntimeAt(value.Policy, now)
	if err != nil {
		return time.Time{}, runtimepolicy.PolicyV2{}, maintenanceFailure(LiveMaintenanceIncompatible)
	}
	certificate, err := x509.ParseCertificate(p.TLSLeafDER)
	if err != nil {
		destroyMaintenancePolicy(&p)
		return time.Time{}, runtimepolicy.PolicyV2{}, maintenanceFailure(LiveMaintenanceIncompatible)
	}
	deadline := time.Unix(end, 0).UTC()
	if certificate.NotAfter.Before(deadline) {
		deadline = certificate.NotAfter
	}
	if now.IsZero() || now.Unix() <= 0 || !now.Before(deadline) {
		destroyMaintenancePolicy(&p)
		return time.Time{}, runtimepolicy.PolicyV2{}, maintenanceFailure(LiveMaintenanceExpired)
	}
	return deadline, p, nil
}

func (o *LiveMaintenanceAdmission) Bounds() LiveMaintenanceBounds {
	if o == nil {
		return LiveMaintenanceBounds{}
	}
	return o.bounds
}
func (o *LiveMaintenanceAdmission) AuthorityDeadline() time.Time {
	if o == nil || len(o.artifact) == 0 {
		return time.Time{}
	}
	return o.deadline
}
func (o *LiveMaintenanceAdmission) RevalidateAt(now time.Time) error {
	if o == nil || len(o.artifact) == 0 {
		return maintenanceFailure(LiveMaintenanceInvalidState)
	}
	if now.Before(o.lastNow) || !now.Before(o.deadline) {
		return maintenanceFailure(LiveMaintenanceExpired)
	}
	workspace, err := maintenanceInputWorkspaceV1(o.artifact, o.limits)
	if err != nil {
		return err
	}
	total, ok := maintenanceAdd(o.bounds.RetainedBytes, workspace)
	if !ok || total > o.limits.OwnedBudgetBytes {
		return maintenanceFailure(LiveMaintenanceResourceLimit)
	}
	o.bounds.OperationReservedBytes = workspace
	o.bounds.PeakReservedBytes = max(o.bounds.PeakReservedBytes, total)
	defer func() { o.bounds.OperationReservedBytes = 0 }()
	b, verified, opener, resolver, err := maintenanceVerifyCore(o.artifact, now, o.value.Generation, o.request, o.private)
	if err != nil {
		return err
	}
	defer opener.Destroy()
	defer destroyMaintenanceBundle(&b)
	defer destroyLiveMaintenanceOffline(&verified)
	var d liveMaintenanceDiagnostic
	a, err := liveActivationRequestFromVerified(o.artifact, now, o.admission.CurrentState(), resolver, opener, liveResourceTypedFirstV1, &d, verified)
	defer d.destroyRequest()
	if err != nil {
		return maintenanceFailure(d.reason)
	}
	resetLiveMaintenanceAdmissionDiagnostic(&d, opener)
	proof, err := profile.VerifyActivationAdmission(a)
	if err != nil {
		return maintenanceFailure(d.reason)
	}
	defer proof.Destroy()
	if proof.CurrentState() != o.admission.CurrentState() {
		return maintenanceFailure(LiveMaintenanceInvalidState)
	}
	o.lastNow = now
	return nil
}

func (o *LiveMaintenanceAdmission) Destroy() {
	if o == nil {
		return
	}
	if o.candidate != nil {
		o.candidate.Destroy()
	}
	if o.probe != nil {
		operation := LiveMaintenanceProbeOperationV1{state: o.probe}
		operation.Destroy()
	}
	clear(o.artifact)
	clear(o.value.Policy)
	o.admission.Destroy()
	destroyMaintenanceBundle(&o.bundle)
	clear(o.request.RecipientPublic)
	clear(o.request.ClientAuthPublic)
	clear(o.request.Nonce)
	clear(o.request.Signature)
	clear(o.private.RecipientPrivate)
	clear(o.private.ClientAuthSeed)
	destroyMaintenanceServices(o.services)
	*o = LiveMaintenanceAdmission{}
}

func destroyMaintenanceBundle(b *liveProfileBundleV2) {
	if b == nil {
		return
	}
	clear(b.RootPublicDER)
	clear(b.IssuerPublicDER)
	clear(b.DelegationPayload)
	clear(b.DelegationSignature)
	clear(b.RevocationPayload)
	clear(b.RevocationSignature)
	clear(b.SealedProfile)
	*b = liveProfileBundleV2{}
}

func destroyMaintenancePolicy(p *runtimepolicy.PolicyV2) {
	clear(p.LiveProgram)
	clear(p.TLSLeafDER)
	clear(p.ClientIPv4)
	clear(p.ClientIPv6)
	clear(p.DNSIPv4)
	clear(p.DNSIPv6)
	for i := range p.Endpoints {
		clear(p.Endpoints[i].Address)
	}
	for i := range p.Routes {
		clear(p.Routes[i].Address)
	}
	for _, v := range p.DNSServers {
		clear(v)
	}
	clear(p.Endpoints)
	clear(p.Routes)
	clear(p.DNSServers)
	clear(p.AllowedIPModes)
	clear(p.AllowedProtocols)
	clear(p.Fallback.EndpointIndexes)
	destroyMaintenanceServices(p.Services)
	*p = runtimepolicy.PolicyV2{}
}

func destroyMaintenanceServices(s *runtimepolicy.ServicesV1) {
	if s == nil {
		return
	}
	if p := s.Proxy; p != nil {
		clear(p.AddressKinds)
		for i := range p.DestinationCIDRs {
			clear(p.DestinationCIDRs[i].Address)
		}
		clear(p.DestinationPorts)
		*p = runtimepolicy.ProxyV1{}
	}
	if p := s.Probes; p != nil {
		for i := range p.Targets {
			clear(p.Targets[i].Address)
			clear(p.Targets[i].Methods)
			clear(p.Targets[i].Modes)
		}
		*p = runtimepolicy.ProbesV1{}
	}
	if s.Update != nil {
		*s.Update = runtimepolicy.UpdateV1{}
	}
	*s = runtimepolicy.ServicesV1{}
}
