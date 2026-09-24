// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
	runtimeengine "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
)

type productionCurrentEnvironmentV1 interface {
	VerifyProductionCurrentAt([]byte, envelope.ArtifactClass, lifecycle.VerifiedState, RecipientCredentials, time.Time, selfhost.LiveMaintenanceLimits) (*selfhost.LiveRuntimeCurrentV1, error)
}

// The trusted producer matches its owned snapshot before registering that same
// revision. Neither this expectation nor scalar receipt equality verifies it.
type ProductionPlatformOwnerV1 interface {
	RegisterProductionCurrentV1(uint64, *ProductionCurrentExpectationV1, func() ErrorCode) (MaintenanceRevisionRegistrationV1, ErrorCode)
}
type ProductionCurrentExpectationV1 struct {
	self             *ProductionCurrentExpectationV1
	parent           *productionParentV1
	epoch            uint64
	lengths          [4]int
	identities       [4][32]byte
	retired          bool
	settingsLength   int
	settingsIdentity [32]byte
}

func productionInputPartsV1(input MaintenanceCurrentInputV1) [4][]byte {
	return [4][]byte{input.VerifyRequest, input.ActivationRecord, input.RecipientRequest, input.RecipientPrivate}
}
func (e *ProductionCurrentExpectationV1) MatchesV1(input MaintenanceCurrentInputV1) bool {
	if e == nil || e.self != e || e.parent == nil || e.epoch == 0 {
		return false
	}
	limits := [4]int{MaxVerifyRequestBytes, MaxBridgeResultBytes, enrollment.MaxRequestBytes, enrollment.MaxPrivateBundleBytes}
	parts := productionInputPartsV1(input)
	e.parent.mu.Lock()
	defer e.parent.mu.Unlock()
	if e.retired || e.epoch != e.parent.ticket.epoch {
		return false
	}
	for i, p := range parts {
		if len(p) == 0 || len(p) > limits[i] || len(p) != e.lengths[i] || sha256.Sum256(p) != e.identities[i] {
			return false
		}
	}
	return true
}

type productionAdmissionV1 struct {
	self                                    *productionAdmissionV1
	parent                                  *productionParentV1
	epoch                                   uint64
	current                                 *selfhost.LiveRuntimeCurrentV1
	plan                                    sessionplan.PlanV2
	program                                 liveprogram.ProgramV1
	seed                                    [32]byte
	seedLive                                bool
	scope                                   [32]byte
	expected                                ProductionCurrentExpectationV1
	registration                            MaintenanceRevisionRegistrationV1
	failedLease                             MaintenancePublicationLeaseV1
	resources                               *productionResourcesV1
	now, monotonicNow                       func() time.Time
	timeMu                                  sync.Mutex
	lastNow, deadline, monotonicDeadline    time.Time
	probeScope                              runtimeengine.AuthenticatedProbeScopeV1
	probeRates                              *runtimeengine.ProbeRateRegistryV1
	opening                                 productionUseV1
	ownerTicket, currentTicket, planTicket  productionBudgetTicketV1
	inPlatform, published, initialLeaseUsed bool
	callbackActive, callbackSeen            bool
	callbackDone                            chan struct{}
	nativeOnce                              sync.Once
	nativeDone                              chan struct{}
	nativeStatus                            int32
	registrationClosing, registrationClosed bool
	registrationDone                        chan struct{}
	cleanupStatus                           int32
	attempt                                 *ProductionAttemptAdmissionV1
	nextBorrow                              uint64
	endpointCount                           uint8
}

type productionOpeningInputsV1 struct {
	artifact    []byte
	credentials RecipientCredentials
	record      profile.ActivationRecord
}

func (v *productionOpeningInputsV1) destroyV1() {
	clear(v.artifact)
	v.credentials.Destroy()
	destroyMaintenanceActivationRecordV1(&v.record)
	*v = productionOpeningInputsV1{}
}

// Actual borrowed argument holders, separate from the opaque current's owned
// graph. No callback value can be submitted as replacement authority.
type productionVerifiedArgumentsV1 struct {
	verified profile.OfflineVerifiedArtifact
	state    lifecycle.VerifiedState
	policy   runtimepolicy.PolicyV2
	deadline time.Time
	callback func(profile.OfflineVerifiedArtifact, lifecycle.VerifiedState, runtimepolicy.PolicyV2, time.Time) error
}

func newProductionAdmissionV1(parent *productionParentV1, opening productionUseV1, input MaintenanceCurrentInputV1, settings productionSettingsV1, environment productionCurrentEnvironmentV1, platform ProductionPlatformOwnerV1, now, monotonicNow func() time.Time, probeRates *runtimeengine.ProbeRateRegistryV1, limits selfhost.LiveMaintenanceLimits) (*productionAdmissionV1, int32) {
	return newProductionAdmissionComposedV1(parent, opening, input, settings, environment, platform, now, monotonicNow, probeRates, limits, nil)
}

func newProductionAdmissionComposedV1(parent *productionParentV1, opening productionUseV1, input MaintenanceCurrentInputV1, settings productionSettingsV1, environment productionCurrentEnvironmentV1, platform ProductionPlatformOwnerV1, now, monotonicNow func() time.Time, probeRates *runtimeengine.ProbeRateRegistryV1, limits selfhost.LiveMaintenanceLimits, prepared func(*productionAdmissionV1, *productionProjectionV1) int32) (*productionAdmissionV1, int32) {
	if parent == nil || opening.parent != parent || opening.index != productionUseOpeningV1 || environment == nil || platform == nil || now == nil || monotonicNow == nil {
		return nil, 2
	}
	if s := parent.useCurrentV1(opening); s != 0 {
		return nil, s
	}
	_, m := maintenanceBridgeReservation(input)
	if m != MaintenanceSuccess {
		return nil, productionMaintenanceStatusV1(m)
	}
	bridge, ok := maintenanceBridgeReservationLedger()
	if !ok {
		return nil, 5
	}
	rateBytes := uint64(0)
	if probeRates != nil {
		rateBytes = probeRates.OwnedBytesV1()
		if rateBytes == 0 {
			return nil, 3
		}
	}
	ownerBytes := uint64(unsafe.Sizeof(productionAdmissionV1{})) + productionRuntimeMetadataAllowanceV1 + rateBytes + 2*uint64(unsafe.Sizeof(productionVerifiedArgumentsV1{}))
	ownerTicket, s := parent.budget.reserveV1(productionBudgetChargeV1{owned: ownerBytes})
	if s != 0 {
		return nil, s
	}
	owner := &productionAdmissionV1{parent: parent, epoch: parent.ticket.epoch, opening: opening, now: now, monotonicNow: monotonicNow, probeRates: probeRates, ownerTicket: ownerTicket, callbackDone: make(chan struct{}), nativeDone: make(chan struct{}), registrationDone: make(chan struct{})}
	owner.self = owner
	owner.expected = ProductionCurrentExpectationV1{parent: parent, epoch: owner.epoch}
	owner.expected.self = &owner.expected
	if parent.session != nil {
		owner.expected.settingsLength = parent.session.settingsLength
		owner.expected.settingsIdentity = parent.session.settingsIdentity
	}
	// Capture the exact bounded input before decoding or invoking any producer.
	// A later buffer mutation cannot rebind old proof to a new current snapshot.
	for i, p := range productionInputPartsV1(input) {
		owner.expected.lengths[i] = len(p)
		owner.expected.identities[i] = sha256.Sum256(p)
	}
	parent.mu.Lock()
	if parent.admission != nil || parent.state != productionParentOpenV1 {
		parent.mu.Unlock()
		parent.budget.releaseV1(ownerTicket)
		return nil, 3
	}
	parent.admission = owner
	parent.mu.Unlock()
	fail := func(status int32) (*productionAdmissionV1, int32) {
		parent.mu.Lock()
		owner.published = false
		parent.mu.Unlock()
		parent.cancelV1(status)
		owner.destroyNativeV1()
		return nil, status
	}
	decodeBytes := maintenanceMaxV1(bridge.VerifyDecode, bridge.IngressFile, bridge.IngressURI, bridge.IngressQR, bridge.CredentialsRequest, bridge.CredentialsPrivate, bridge.CredentialsCheck, bridge.CredentialsClone, bridge.ActivationRecord) + uint64(unsafe.Sizeof(productionOpeningInputsV1{}))
	decodeTicket, s := parent.budget.reserveV1(productionBudgetChargeV1{owned: decodeBytes})
	if s != 0 {
		return fail(s)
	}
	var decoded productionOpeningInputsV1
	defer func() { decoded.destroyV1(); parent.budget.releaseV1(decodeTicket) }()
	decoded.artifact, decoded.credentials, m = decodeMaintenanceCurrentIngressV1(input, limits)
	if m != MaintenanceSuccess {
		return fail(productionMaintenanceStatusV1(m))
	}
	var err error
	decoded.record, err = DecodeActivationRecord(input.ActivationRecord)
	if err != nil {
		return fail(3)
	}
	// Decoder stages have returned. Only their actual owned output plus the one
	// credential clone overlaps the next verifier stage; maximum URI/QR scratch
	// is no longer live and must not be added to the verifier maximum.
	retainedInputs := uint64(unsafe.Sizeof(decoded)) + productionAdmissionBackingV1(reflect.ValueOf(decoded)) + uint64(unsafe.Sizeof(RecipientCredentials{}))
	for _, leaf := range [][]byte{decoded.credentials.Request.RecipientPublic, decoded.credentials.Request.ClientAuthPublic, decoded.credentials.Request.Nonce, decoded.credentials.Request.Signature, decoded.credentials.Private.RecipientPrivate, decoded.credentials.Private.ClientAuthSeed} {
		if len(leaf) != 0 {
			retainedInputs += 2*uint64(len(leaf)) + 8
		}
	}
	if s = parent.resizeAdmissionTicketV1(decodeTicket, retainedInputs); s != 0 {
		return fail(s)
	}
	captured := now()
	if captured.IsZero() || captured.Unix() <= 0 {
		return fail(21)
	}
	parent.budget.mu.Lock()
	residual := parent.budget.cap - parent.budget.owned
	parent.budget.mu.Unlock()
	if limits.OwnedBudgetBytes != 0 {
		residual = min(residual, limits.OwnedBudgetBytes)
	}
	owner.currentTicket, s = parent.budget.reserveV1(productionBudgetChargeV1{owned: residual})
	if s != 0 {
		return fail(s)
	}
	limits.OwnedBudgetBytes = residual
	// Only this immutable current proof is sized to its already-bounded input.
	// Original ingress/future-operation limits and all fixed workspace terms
	// remain unchanged; an oversized artifact is never clamped into admission.
	if limits.MaxArtifactBytes == 0 || len(decoded.artifact) == 0 || uint64(len(decoded.artifact)) > uint64(limits.MaxArtifactBytes) {
		return fail(4)
	}
	currentLimits := limits
	currentLimits.MaxArtifactBytes = uint32(len(decoded.artifact))
	owner.current, err = environment.VerifyProductionCurrentAt(decoded.artifact, envelope.ArtifactDeviceRecipient, decoded.record.State, decoded.credentials.Clone(), captured, currentLimits)
	if err != nil {
		return fail(productionMaintenanceStatusV1(maintenanceResultFromError(err)))
	}
	if owner.current == nil {
		return fail(18)
	}
	bounds, err := owner.current.BoundsV1()
	if err != nil || bounds.BudgetBytes != residual || bounds.RetainedBytes == 0 || bounds.RetainedBytes > bounds.PeakReservedBytes || bounds.PeakReservedBytes > residual {
		return fail(18)
	}
	// Keep the opaque owner's synchronous argument holder charged as well as its
	// retained proof. Bounds describe the proven owner's storage, not admission.
	if s = parent.resizeAdmissionTicketV1(owner.currentTicket, bounds.RetainedBytes+uint64(unsafe.Sizeof(productionVerifiedArgumentsV1{}))); s != 0 {
		return fail(s)
	}
	calculation, validCalculation := sessionplan.AdmittedCalculationBoundsV2(envelope.MaxPayloadBytes)
	if !validCalculation {
		return fail(5)
	}
	planStage := max(calculation.SuffixBytes, 2*calculation.PlanBytes+calculation.ProgramBytes+calculation.DecoderBytes+calculation.SelectionBytes) + 2*uint64(unsafe.Sizeof(productionProjectionV1{}))
	owner.planTicket, s = parent.budget.reserveV1(productionBudgetChargeV1{owned: planStage})
	if s != 0 {
		return fail(s)
	}
	var projection productionProjectionV1
	defer projection.Destroy()
	var semantic int32
	err = owner.current.WithVerifiedV1(func(v profile.OfflineVerifiedArtifact, state lifecycle.VerifiedState, policy runtimepolicy.PolicyV2, deadline time.Time) error {
		if semantic = validateProductionCurrentBindingV1(&decoded, v, state, policy); semantic != 0 {
			return errors.New("production current binding rejected")
		}
		owner.scope = maintenanceScopeIdentityV1(v)
		active := false
		if policy.Services != nil && policy.Services.Probes != nil {
			for _, target := range policy.Services.Probes.Targets {
				for _, mode := range target.Modes {
					active = active || mode == uint8(runtimeengine.ProbeActiveRelayV1)
				}
			}
		}
		if active {
			if probeRates == nil {
				semantic = 3
				return errors.New("production probe rate owner absent")
			}
			owner.probeScope, err = runtimeengine.NewAuthenticatedProbeScopeV1(v.Profile)
			if err != nil {
				return err
			}
		}
		var status productionStatusV1
		projection, status = projectProductionSettingsV1(settings, sessionplan.RequestV2{Profile: v.Profile, ActivationReceipt: state.Receipt, RuntimePolicy: policy}, captured)
		if status != 0 {
			semantic = int32(status)
			return errors.New("production settings rejected")
		}
		owner.plan = projection.plan.Clone()
		owner.endpointCount = projection.fallbackAttemptMax
		owner.program, err = liveprogram.DecodeV1(policy.LiveProgram)
		if err != nil {
			return err
		}
		if productionAdmissionBackingV1(reflect.ValueOf(owner.plan)) > calculation.PlanBytes || productionAdmissionBackingV1(reflect.ValueOf(projection.plan)) > calculation.PlanBytes || productionAdmissionBackingV1(reflect.ValueOf(owner.program)) > calculation.ProgramBytes {
			return errors.New("admission calculation holder exceeded")
		}
		if err = sessionplan.ValidateV2At(owner.plan, captured); err != nil {
			return err
		}
		copy(owner.seed[:], decoded.credentials.Private.ClientAuthSeed)
		owner.seedLive = true
		owner.deadline, owner.lastNow = deadline, captured
		return nil
	})
	if err != nil {
		if semantic == 0 {
			semantic = 18
		}
		return fail(semantic)
	}
	// WithVerifiedV1 has fully returned before any temporary ticket is reduced.
	decoded.destroyV1()
	if s = parent.resizeAdmissionTicketV1(decodeTicket, 0); s != 0 {
		return fail(s)
	}
	planBytes := productionAdmissionBackingV1(reflect.ValueOf(owner.plan)) + productionAdmissionBackingV1(reflect.ValueOf(owner.program)) + productionAdmissionBackingV1(reflect.ValueOf(projection)) + 2*uint64(unsafe.Sizeof(projection))
	if s = parent.resizeAdmissionTicketV1(owner.planTicket, planBytes); s != 0 {
		return fail(s)
	}
	if s = owner.enterPlatformV1(opening); s != 0 {
		return fail(s)
	}
	registration, code := platform.RegisterProductionCurrentV1(owner.epoch, &owner.expected, owner.invalidateV1)
	parent.mu.Lock()
	owner.registration = registration
	parent.mu.Unlock()
	s = owner.leavePlatformV1(opening)
	if s != 0 {
		return fail(s)
	}
	if code != CodeOK || registration == nil {
		return fail(3)
	}
	if s = owner.registrationCheckV1(parent.cancelContext, opening); s != 0 {
		return fail(s)
	}
	// All fallible resource construction precedes the single initial lease.
	if s = owner.acceptTimeV1(opening); s != 0 {
		return fail(s)
	}
	parent.budget.mu.Lock()
	available := runtimeengine.ProductionClientAvailableV1{AggregateBytes: parent.budget.cap - parent.budget.owned}
	parent.budget.mu.Unlock()
	if projection.effectiveMode != 1 {
		available.ProxyBytes = uint64(projection.effectiveProxyBufferBytes)
	}
	selected := projection
	selected.plan = owner.plan // borrowed immutable Plan, survives recipe consumption
	owner.resources, s = prepareProductionResourcesV1(&projection, parent.budget, available, owner.lastNow, opening.attempt)
	if s != 0 {
		return fail(s)
	}
	owner.resources.owner = owner
	owner.resources.generation = opening.attempt
	if prepared != nil {
		if s = prepared(owner, &selected); s != 0 {
			return fail(s)
		}
	}
	selected = productionProjectionV1{}
	if s = owner.acceptTimeV1(opening); s != 0 {
		return fail(s)
	}
	if s = owner.enterPlatformV1(opening); s != 0 {
		return fail(s)
	}
	parent.mu.Lock()
	owner.initialLeaseUsed = true
	parent.mu.Unlock()
	lease, result := registration.AcquirePublication(parent.cancelContext)
	s = owner.leavePlatformV1(opening)
	if lease != nil {
		// Returned leases remain owned even if terminal won before return. Every
		// platform method remains marked through its synchronous callback stack.
		parent.mu.Lock()
		owner.inPlatform = true
		parent.mu.Unlock()
		current := lease.IsCurrent()
		parent.mu.Lock()
		owner.inPlatform = false
		parent.mu.Unlock()
		if !current && s == 0 {
			s = 3
		}
		if s == 0 {
			s = owner.acceptTimeV1(opening)
		}
		if s == 0 {
			parent.mu.Lock()
			owner.published = parent.state == productionParentOpenV1
			parent.mu.Unlock()
		}
		parent.mu.Lock()
		owner.inPlatform = true
		parent.mu.Unlock()
		closeCode := lease.Close()
		parent.mu.Lock()
		owner.inPlatform = false
		parent.mu.Unlock()
		if currentStatus := parent.useCurrentV1(opening); currentStatus != 0 {
			s = currentStatus
		}
		if closeCode != CodeOK {
			parent.mu.Lock()
			owner.failedLease = lease
			owner.cleanupStatus = int32(productionInvalidStateV1)
			parent.mu.Unlock()
			if s == 0 {
				s = 3
			}
		}
	}
	if s != 0 {
		return fail(s)
	}
	if result != MaintenanceSuccess {
		return fail(productionMaintenanceStatusV1(result))
	}
	if lease == nil {
		return fail(18)
	}
	if s = owner.acceptTimeV1(opening); s != 0 {
		return fail(s)
	}
	parent.mu.Lock()
	published := owner.published && parent.state == productionParentOpenV1
	parent.mu.Unlock()
	if !published {
		return fail(7)
	}
	return owner, 0
}

func productionAdmissionBackingV1(v reflect.Value) uint64 {
	var n uint64
	switch v.Kind() {
	case reflect.String:
		n = uint64(v.Len())
	case reflect.Slice:
		n = uint64(v.Cap()) * uint64(v.Type().Elem().Size())
		for i := 0; i < v.Len(); i++ {
			n += productionAdmissionBackingV1(v.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			n += productionAdmissionBackingV1(v.Field(i))
		}
	}
	return n
}

func (o *productionAdmissionV1) enterPlatformV1(use productionUseV1) int32 {
	if o == nil || o.self != o {
		return 3
	}
	if s := o.parent.useCurrentV1(use); s != 0 {
		return s
	}
	o.parent.mu.Lock()
	defer o.parent.mu.Unlock()
	if o.inPlatform || o.parent.state != productionParentOpenV1 {
		return 3
	}
	o.inPlatform = true
	return 0
}
func (o *productionAdmissionV1) leavePlatformV1(use productionUseV1) int32 {
	o.parent.mu.Lock()
	o.inPlatform = false
	o.parent.mu.Unlock()
	return o.parent.useCurrentV1(use)
}
func (o *productionAdmissionV1) registrationCheckV1(ctx context.Context, use productionUseV1) int32 {
	if ctx == nil {
		return 2
	}
	if s := o.enterPlatformV1(use); s != 0 {
		return s
	}
	m := o.registration.Revalidate(ctx)
	if s := o.leavePlatformV1(use); s != 0 {
		return s
	}
	s := productionMaintenanceStatusV1(m)
	if s != 0 {
		o.parent.cancelV1(s)
	}
	return s
}
func (o *productionAdmissionV1) acceptTimeV1(use productionUseV1) int32 {
	if s := o.parent.useCurrentV1(use); s != 0 {
		return s
	}
	// Sample and publish trusted time in the same order across native callers.
	// Keep clock callbacks outside the lifecycle lock so cancellation can join.
	o.timeMu.Lock()
	defer o.timeMu.Unlock()
	now, mono := o.now(), o.monotonicNow()
	o.parent.mu.Lock()
	invalid := now.IsZero() || now.Unix() <= 0 || now.Before(o.lastNow) || !now.Before(o.deadline) || mono.IsZero() || !o.monotonicDeadline.IsZero() && !mono.Before(o.monotonicDeadline)
	if invalid {
		o.parent.mu.Unlock()
		o.parent.cancelV1(12)
		return 12
	}
	if err := o.current.CheckAtV1(now); err != nil {
		o.parent.mu.Unlock()
		return productionMaintenanceStatusV1(maintenanceResultFromError(err))
	}
	if err := o.planCheckV1(now); err != nil {
		o.parent.mu.Unlock()
		o.parent.cancelV1(22)
		return 22
	}
	if o.parent.state != productionParentOpenV1 {
		o.parent.mu.Unlock()
		return o.parent.useCurrentV1(use)
	}
	o.lastNow = now
	if o.monotonicDeadline.IsZero() {
		var ok bool
		o.monotonicDeadline, ok = maintenanceMonotonicDeadlineV1(now, o.deadline, mono)
		if !ok {
			o.parent.mu.Unlock()
			return 12
		}
	}
	o.parent.mu.Unlock()
	return 0
}
func (o *productionAdmissionV1) planCheckV1(now time.Time) error {
	return sessionplan.ValidateV2At(o.plan, now)
}

func (o *productionAdmissionV1) invalidateV1() ErrorCode {
	p := o.parent
	p.mu.Lock()
	// A protected revision change carries no authenticated revocation proof.
	cancel := p.fenceLockedV1(productionCancelledV1)
	// The registration contract has no invocation marker. Any platform overlap,
	// including an asynchronous callback, is conservatively cleanup-unproven.
	// The producer must block publication until external joined cleanup proves it.
	if o.inPlatform || o.callbackActive {
		p.mu.Unlock()
		if cancel {
			p.cancel()
			p.signalControlV1()
		}
		return CodeStateCorrupt
	}
	if o.callbackSeen {
		status := o.cleanupStatus
		p.mu.Unlock()
		if status != 0 {
			return CodeStateCorrupt
		}
		return CodeOK
	}
	o.callbackSeen, o.callbackActive = true, true
	p.mu.Unlock()
	defer func() { p.mu.Lock(); o.callbackActive = false; p.mu.Unlock(); close(o.callbackDone) }()
	if cancel {
		p.cancel()
		p.signalControlV1()
	}
	if p.joinV1(context.Background()) != 0 {
		return CodeStateCorrupt
	}
	if o.destroyNativeV1() != 0 {
		p.mu.Lock()
		o.cleanupStatus = int32(productionInvalidStateV1)
		p.mu.Unlock()
		return CodeStateCorrupt
	}
	p.mu.Lock()
	unproven := o.cleanupStatus != int32(productionSuccessV1)
	p.mu.Unlock()
	if unproven {
		return CodeStateCorrupt
	}
	return CodeOK
}

func (o *productionAdmissionV1) destroyNativeV1() int32 {
	o.nativeOnce.Do(func() {
		status := int32(0)
		if o.resources != nil {
			status = o.resources.destroyV1()
		}
		if status == 0 {
			clear(o.seed[:])
			o.seedLive = false
			o.plan.Destroy()
			clear(o.program.Frame.Compiled.DataTypeTag)
			clear(o.program.Frame.Compiled.PaddingTypeTag)
			clear(o.program.Messages)
			clear(o.program.Frame.HeaderOrder)
			clear(o.program.Security.ClientMandatoryCapabilities)
			clear(o.program.Security.RelayMandatoryCapabilities)
			clear(o.program.Security.SelectedCapabilities)
			o.program = liveprogram.ProgramV1{}
			if o.current != nil {
				o.current.Destroy()
				o.current = nil
			}
			for _, ticket := range []productionBudgetTicketV1{o.planTicket, o.currentTicket} {
				if ticket.ledger != nil && o.parent.budget.releaseV1(ticket) != 0 {
					status = 18
				}
			}
		}
		o.nativeStatus = status
		close(o.nativeDone)
	})
	<-o.nativeDone
	return o.nativeStatus
}

// External lifecycle close. Call only after releasing the caller's opening or
// transport attempt use. Registration.Close is never called on its callback.
func (o *productionAdmissionV1) closeV1(ctx context.Context) int32 {
	if o == nil || o.self != o || ctx == nil {
		return 3
	}
	o.parent.cancelV1(7)
	if s := o.parent.joinV1(ctx); s != 0 {
		return s
	}
	o.parent.mu.Lock()
	callback := o.callbackActive
	done := o.callbackDone
	o.parent.mu.Unlock()
	if callback {
		select {
		case <-done:
		case <-ctx.Done():
			return 8
		}
	}
	if s := o.destroyNativeV1(); s != 0 {
		return s
	}
	o.parent.mu.Lock()
	if o.registrationClosing {
		done := o.registrationDone
		o.parent.mu.Unlock()
		select {
		case <-done:
			return o.cleanupStatus
		case <-ctx.Done():
			return 8
		}
	}
	o.registrationClosing = true
	o.inPlatform = true
	registration := o.registration
	o.parent.mu.Unlock()
	code := CodeOK
	if registration != nil {
		code = registration.Close()
	}
	o.parent.mu.Lock()
	o.inPlatform = false
	if code != CodeOK {
		o.cleanupStatus = 3
	} else {
		o.registrationClosed = true
		o.expected.retired = true
		clear(o.expected.identities[:])
		clear(o.expected.lengths[:])
		o.registration = nil
	}
	status := o.cleanupStatus
	o.parent.mu.Unlock()
	if status == 0 && o.parent.budget.releaseV1(o.ownerTicket) != 0 {
		status = 18
		o.parent.mu.Lock()
		o.cleanupStatus = status
		o.parent.mu.Unlock()
	}
	close(o.registrationDone)
	return status
}

// MaintenanceResultP1V1 is the canonical ordinary-operation conversion. Update
// decisions keep their M1 body and must not use this transport conversion.
func MaintenanceResultP1V1(result MaintenanceResultV1) int32 {
	return productionMaintenanceStatusV1(result)
}

func productionMaintenanceStatusV1(result MaintenanceResultV1) int32 {
	switch normalizeMaintenancePlatformResult(result) {
	case MaintenanceSuccess:
		return 0
	case MaintenanceNotAdmitted:
		return 1
	case MaintenanceInvalidRequest:
		return 2
	case MaintenanceInvalidState:
		return 3
	case MaintenanceSizeLimit:
		return 4
	case MaintenanceResourceLimit:
		return 5
	case MaintenanceRateLimited:
		return 6
	case MaintenanceCancelled:
		return 7
	case MaintenanceTimeout:
		return 8
	case MaintenanceNetworkUnavailable:
		return 9
	case MaintenanceDestinationDenied:
		return 10
	case MaintenanceTLSTrustUnavailable:
		return 21
	case MaintenanceTLSRejected:
		return 14
	case MaintenanceSignatureInvalid, MaintenanceProfileMismatch, MaintenanceRootRotationRejected:
		return 22
	case MaintenanceWrongRecipient:
		return 23
	case MaintenanceRollback:
		return 24
	case MaintenanceExpired:
		return 12
	case MaintenanceRevoked:
		return 13
	case MaintenanceIncompatible:
		return 25
	default:
		return 18
	}
}
