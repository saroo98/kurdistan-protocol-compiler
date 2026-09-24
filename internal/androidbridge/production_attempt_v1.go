// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"errors"
	"math"
	"time"
	"unsafe"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
	runtimeengine "kurdistan/internal/runtime"
	"kurdistan/internal/transport/tlstcp"
)

type ProductionAttemptAdmissionV1 struct {
	self                *ProductionAttemptAdmissionV1
	owner               *productionAdmissionV1
	resources           *productionResourcesV1
	use                 productionUseV1
	generation          uint64
	endpoint            uint8
	borrow              *ProductionAttemptBorrowV1
	ticket              productionBudgetTicketV1
	transportTicket     productionBudgetTicketV1
	transportProxyBytes uint64
	transport           ProductionAttemptTransportV1
	preparing           bool
	released            bool
}

// These interfaces compose only trusted native implementations with the opaque
// admission. A numerical requirement is never accepted as a reservation receipt.
type ProductionAttemptReservationV1 struct{ OwnedBytes, ProxyAttributedBytes uint64 }
type ProductionAttemptFactoryV1 interface {
	ReservationV1(*ProductionAttemptBorrowV1) (ProductionAttemptReservationV1, int32)
	PrepareV1(*ProductionAttemptBorrowV1) (ProductionAttemptTransportV1, int32)
}
type ProductionAttemptTransportV1 interface {
	SocketFDV1() (int, int32)
	ConfirmProtectedV1(int) int32
	ConnectProtectedV1(context.Context) int32
	AuthenticateTLSV1(context.Context) int32
	AuthenticateKurdV1(context.Context) int32
	AttachInstalledV1(context.Context) int32
	CloseWakeV1()
	FinishV1() int32
	DoneV1() <-chan struct{}
}

func (a *ProductionAttemptAdmissionV1) PrepareV1(ctx context.Context, factory ProductionAttemptFactoryV1) (ProductionAttemptTransportV1, int32) {
	if a == nil || a.self != a || a.owner == nil {
		return nil, 3
	}
	if ctx == nil || factory == nil {
		return nil, 2
	}
	p := a.owner.parent
	p.mu.Lock()
	if a.preparing || a.borrow != nil || a.released {
		p.mu.Unlock()
		return nil, 3
	}
	a.preparing = true
	p.mu.Unlock()
	b, s := a.BorrowV1()
	if s != 0 {
		return nil, s
	}
	fail := func(status int32) (ProductionAttemptTransportV1, int32) {
		if a.transport != nil {
			a.transport.CloseWakeV1()
			a.transport.FinishV1()
			<-a.transport.DoneV1()
		} else {
			b.FinishOwnedV1()
		}
		return nil, b.StatusV1(status)
	}
	if _, s = b.RevalidateV1(ctx); s != 0 {
		return fail(s)
	}
	requirement, s := factory.ReservationV1(b)
	if s != 0 {
		return fail(s)
	}
	if requirement.OwnedBytes == 0 || requirement.ProxyAttributedBytes > requirement.OwnedBytes {
		return fail(2)
	}
	p.mu.Lock()
	proxyFits := productionProxyFitsV1(a.resources, productionAttemptHolderBytesV1(), requirement.ProxyAttributedBytes)
	p.mu.Unlock()
	if !proxyFits {
		return fail(int32(productionResourceLimitV1))
	}
	ticket, s := p.budget.reserveV1(productionBudgetChargeV1{owned: requirement.OwnedBytes, queued: requirement.ProxyAttributedBytes})
	if s != 0 {
		return fail(s)
	}
	p.mu.Lock()
	a.transportTicket = ticket
	a.transportProxyBytes = requirement.ProxyAttributedBytes
	p.mu.Unlock()
	if _, s = b.RevalidateV1(ctx); s != 0 {
		return fail(s)
	}
	transport, s := factory.PrepareV1(b)
	// Even a late failing factory result enters owned cleanup before any handle
	// can escape. The trusted factory joins its own partial nil-return state.
	p.mu.Lock()
	a.transport = transport
	p.mu.Unlock()
	if s != 0 || transport == nil {
		if s == 0 {
			s = 18
		}
		return fail(s)
	}
	if _, s = b.RevalidateV1(ctx); s != 0 {
		return fail(s)
	}
	return transport, 0
}

// LifetimeV1 exposes only the already owned parent cancellation and its bounded
// monotonic authority deadline, never mutable authority or platform inputs.
func (b *ProductionAttemptBorrowV1) LifetimeV1() (<-chan struct{}, time.Time, int32) {
	if !b.validV1() {
		return nil, time.Time{}, 3
	}
	o := b.admission.owner
	if s := b.completionStatusV1(); s != 0 {
		return nil, time.Time{}, s
	}
	return o.parent.cancelContext.Done(), o.monotonicDeadline, 0
}
func (b *ProductionAttemptBorrowV1) StatusV1(fallback int32) int32 {
	if !b.validV1() {
		return 3
	}
	if s := b.completionStatusV1(); s != 0 {
		return s
	}
	if !validProductionStatusV1(productionStatusV1(fallback)) {
		return 18
	}
	return fallback
}

// FinishOwnedV1 is the trusted coordinator's final step after its connector,
// actual raw close worker, serial calls and pump have joined. Installation close
// and ledger release precede closing the borrow, preserving the parent use fence.
func (b *ProductionAttemptBorrowV1) FinishOwnedV1() int32 {
	if !b.validV1() {
		return 3
	}
	a := b.admission
	i := a.resources.installation
	if err := i.Close(); err != nil {
		return productionResourceStatusV1(err)
	}
	<-i.Done()
	p := a.owner.parent
	p.mu.Lock()
	ticket := a.transportTicket
	a.transportTicket = productionBudgetTicketV1{}
	p.mu.Unlock()
	if ticket.ledger != nil {
		if s := p.budget.releaseV1(ticket); s != 0 {
			return s
		}
	}
	p.mu.Lock()
	a.transportProxyBytes = 0
	p.mu.Unlock()
	if b.Close() != nil {
		return 18
	}
	return 0
}

type ProductionAttemptBorrowV1 struct {
	self                                        *ProductionAttemptBorrowV1
	admission                                   *ProductionAttemptAdmissionV1
	serial                                      uint64
	closed, active, ready, attached, doneClosed bool
	accepted                                    time.Time
	done                                        chan struct{}
}
type productionBorrowArgumentsV1 struct {
	plan     sessionplan.PlanV2
	policy   runtimepolicy.PolicyV2
	program  liveprogram.ProgramV1
	seed     []byte
	endpoint uint8
	now      time.Time
	callback func(sessionplan.PlanV2, runtimepolicy.PolicyV2, liveprogram.ProgramV1, []byte, uint8, time.Time) error
}

// Caller holds the existing parent ownership guard; zero means no proxy domain.
func productionProxyFitsV1(r *productionResourcesV1, charges ...uint64) bool {
	if r.proxyCeilingBytes == 0 {
		return true
	}
	if r.proxyRetainedBytes > r.proxyCeilingBytes {
		return false
	}
	residual := r.proxyCeilingBytes - r.proxyRetainedBytes
	for _, charge := range charges {
		if charge > residual {
			return false
		}
		residual -= charge
	}
	return true
}

func productionAttemptHolderBytesV1() uint64 {
	return uint64(unsafe.Sizeof(ProductionAttemptAdmissionV1{})) + uint64(unsafe.Sizeof(ProductionAttemptBorrowV1{})) + uint64(unsafe.Sizeof(productionBorrowArgumentsV1{})) + productionRuntimeMetadataAllowanceV1
}

func newProductionAttemptAdmissionV1(owner *productionAdmissionV1, resources *productionResourcesV1, endpoint uint8, use productionUseV1) (*ProductionAttemptAdmissionV1, int32) {
	if owner == nil || owner.self != owner || resources == nil || resources.self != resources || use.parent != owner.parent || use.index != productionUseAttemptV1 {
		return nil, 3
	}
	p := owner.parent
	if s := p.useCurrentV1(use); s != 0 {
		return nil, s
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !owner.published || owner.attempt != nil || resources.owner != owner || resources.generation != use.attempt || use.attempt == 0 || owner.epoch != p.ticket.epoch || !owner.seedLive || int(endpoint) >= len(owner.plan.Endpoints) || endpoint >= owner.endpointCount || p.state != productionParentOpenV1 {
		return nil, 3
	}
	// Plan endpoints are the actual builder-selected fallback sequence, never a
	// caller URL. The selected ordinal is bounded to that immutable sequence.
	resources.mu.Lock()
	retired := resources.destroyed
	resources.mu.Unlock()
	if retired {
		return nil, 3
	}
	charge := productionAttemptHolderBytesV1()
	if !productionProxyFitsV1(resources, charge) {
		return nil, int32(productionResourceLimitV1)
	}
	ticket, s := p.budget.reserveV1(productionBudgetChargeV1{owned: charge})
	if s != 0 {
		return nil, s
	}
	a := &ProductionAttemptAdmissionV1{owner: owner, resources: resources, use: use, generation: use.attempt, endpoint: endpoint, ticket: ticket}
	a.self = a
	owner.attempt = a
	return a, 0
}
func (a *ProductionAttemptAdmissionV1) BorrowV1() (*ProductionAttemptBorrowV1, int32) {
	if a == nil || a.self != a || a.owner == nil || a.owner.self != a.owner {
		return nil, 3
	}
	p := a.owner.parent
	if s := p.useCurrentV1(a.use); s != 0 {
		return nil, s
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if a.released || a.borrow != nil || a.owner.attempt != a || a.generation != p.attempt || a.resources.owner != a.owner || a.owner.nextBorrow == math.MaxUint64 || p.state != productionParentOpenV1 {
		return nil, 3
	}
	a.owner.nextBorrow++
	b := &ProductionAttemptBorrowV1{admission: a, serial: a.owner.nextBorrow, done: make(chan struct{})}
	b.self = b
	a.borrow = b
	return b, 0
}
func (b *ProductionAttemptBorrowV1) validV1() bool {
	return b != nil && b.self == b && b.admission != nil && b.admission.self == b.admission && b.admission.owner != nil && b.admission.owner.self == b.admission.owner
}
func (b *ProductionAttemptBorrowV1) beginV1(requireReady, attach bool) int32 {
	if !b.validV1() {
		return 3
	}
	a := b.admission
	p := a.owner.parent
	if s := p.useCurrentV1(a.use); s != 0 {
		return s
	}
	p.mu.Lock()
	if b.closed || b.active || a.released || a.borrow != b || a.owner.attempt != a || a.generation != p.attempt || b.serial == 0 || b.serial != a.owner.nextBorrow || p.state != productionParentOpenV1 || requireReady && !b.ready || attach && b.attached {
		p.mu.Unlock()
		return 3
	}
	b.active = true
	if requireReady {
		b.ready = false
	}
	if attach {
		b.attached = true
	}
	p.mu.Unlock()
	if _, err := b.acceptNativeTimeV1(time.Time{}, false); err != nil {
		b.endV1()
		if errors.Is(err, runtimeengine.ServiceAuthorityExpiredV1) {
			return int32(productionAuthorityExpiredV1)
		}
		return int32(productionAuthorityRevokedV1)
	}
	return 0
}
func (b *ProductionAttemptBorrowV1) endV1() {
	p := b.admission.owner.parent
	p.mu.Lock()
	b.active = false
	if b.closed && !b.doneClosed {
		close(b.done)
		b.doneClosed = true
	}
	p.mu.Unlock()
}
func (b *ProductionAttemptBorrowV1) RevalidateV1(ctx context.Context) (time.Time, int32) {
	if ctx == nil {
		return time.Time{}, 2
	}
	if s := b.beginV1(false, false); s != 0 {
		return time.Time{}, s
	}
	defer b.endV1()
	o := b.admission.owner
	o.parent.mu.Lock()
	b.ready = false
	o.parent.mu.Unlock()
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return time.Time{}, int32(productionTimeoutV1)
		}
		return time.Time{}, int32(productionCancelledV1)
	}
	if s := o.registrationCheckV1(ctx, b.admission.use); s != 0 {
		return time.Time{}, s
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return time.Time{}, int32(productionTimeoutV1)
		}
		return time.Time{}, int32(productionCancelledV1)
	}
	if s := o.acceptTimeV1(b.admission.use); s != 0 {
		if terminal := b.completionStatusV1(); terminal != int32(productionSuccessV1) {
			return time.Time{}, terminal
		}
		return time.Time{}, s
	}
	o.parent.mu.Lock()
	defer o.parent.mu.Unlock()
	if o.parent.state != productionParentOpenV1 && (o.parent.terminal == productionAuthorityExpiredV1 || o.parent.terminal == productionAuthorityRevokedV1) {
		return time.Time{}, int32(o.parent.terminal)
	}
	if b.closed || o.parent.state != productionParentOpenV1 {
		return time.Time{}, 3
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return time.Time{}, int32(productionTimeoutV1)
		}
		return time.Time{}, int32(productionCancelledV1)
	}
	b.accepted = o.lastNow
	b.ready = true
	return b.accepted, 0
}
func (b *ProductionAttemptBorrowV1) WithInputsV1(use func(sessionplan.PlanV2, runtimepolicy.PolicyV2, liveprogram.ProgramV1, []byte, uint8, time.Time) error) error {
	if use == nil {
		return runtimeengine.ServiceInvalidRequestV1
	}
	if s := b.beginV1(true, false); s != 0 {
		return productionBorrowErrorV1(s)
	}
	defer b.endV1()
	a := b.admission
	o := a.owner
	err := o.current.WithVerifiedV1(func(_ profile.OfflineVerifiedArtifact, _ lifecycle.VerifiedState, policy runtimepolicy.PolicyV2, _ time.Time) error {
		args := productionBorrowArgumentsV1{o.plan, policy, o.program, o.seed[:], a.endpoint, b.accepted, use}
		defer func() { args = productionBorrowArgumentsV1{} }()
		return args.callback(args.plan, args.policy, args.program, args.seed, args.endpoint, args.now)
	})
	// The trusted callback may span the exclusive deadline. Its return is still
	// part of this counted stage, and cannot publish late authority success.
	_, authorityErr := b.acceptNativeTimeV1(time.Time{}, false)
	if status := b.completionStatusV1(); status != int32(productionSuccessV1) {
		return productionBorrowErrorV1(status)
	}
	if authorityErr != nil {
		return authorityErr
	}
	return err
}

// Preserve the selected authority cause at the new completion boundary without
// changing the legacy parent operation mapping of expiry to cancellation.
func (b *ProductionAttemptBorrowV1) completionStatusV1() int32 {
	a := b.admission
	p := a.owner.parent
	status := p.useCurrentV1(a.use)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != productionParentOpenV1 {
		if p.terminal == productionAuthorityExpiredV1 || p.terminal == productionAuthorityRevokedV1 {
			return int32(p.terminal)
		}
		return p.terminalOperationStatusLockedV1()
	}
	return status
}

// Close joins an active trusted callback but cannot retire the containing
// transport. Trusted callbacks must not invoke Close on their own active borrow.
func (b *ProductionAttemptBorrowV1) Close() error {
	if !b.validV1() {
		return runtimeengine.ServiceInvalidRequestV1
	}
	p := b.admission.owner.parent
	p.mu.Lock()
	b.closed = true
	b.ready = false
	if !b.active && !b.doneClosed {
		close(b.done)
		b.doneClosed = true
	}
	done := b.done
	p.mu.Unlock()
	<-done
	return nil
}

func (b *ProductionAttemptBorrowV1) nativeAuthorityV1(now time.Time) error {
	_, err := b.acceptNativeTimeV1(now, true)
	return err
}

func (b *ProductionAttemptBorrowV1) acceptNativeTimeV1(sample time.Time, checkSample bool) (time.Time, error) {
	if !b.validV1() {
		return time.Time{}, runtimeengine.ServiceNotAdmittedV1
	}
	a := b.admission
	o := a.owner
	p := o.parent
	// The caller's sample may precede another operation's accepted sample.
	// Now accepts fresh clock observations; CheckAuthority validates an already
	// accepted sample without mistaking overlap for rollback or resampling it.
	o.timeMu.Lock()
	defer o.timeMu.Unlock()
	current := sample
	if !checkSample {
		current = o.now()
	}
	mono := o.monotonicNow()
	p.mu.Lock()
	live := !a.released && o.attempt == a && a.generation == p.attempt && p.state == productionParentOpenV1 && !o.registrationClosed && o.registration != nil
	expired := current.IsZero() || current.Unix() <= 0 || !checkSample && current.Before(o.lastNow) || checkSample && current.After(o.lastNow) || !current.Before(o.deadline) || mono.IsZero() || !mono.Before(o.monotonicDeadline)
	if live && !expired && !checkSample {
		o.lastNow = current
	}
	p.mu.Unlock()
	if !live {
		return current, runtimeengine.ServiceAuthorityRevokedV1
	}
	if expired {
		p.cancelV1(12)
		return current, runtimeengine.ServiceAuthorityExpiredV1
	}
	return current, nil
}
func (b *ProductionAttemptBorrowV1) runtimeAuthorityV1(raw bool) runtimeengine.ProductionClientAuthorityV1 {
	o := b.admission.owner
	authority := runtimeengine.ProductionClientAuthorityV1{AuthorityDeadline: o.deadline, Now: func() time.Time {
		now, err := b.acceptNativeTimeV1(time.Time{}, false)
		if err != nil {
			return time.Time{}
		}
		return now
	}, CheckAuthority: b.nativeAuthorityV1}
	if !raw && o.probeScope != (runtimeengine.AuthenticatedProbeScopeV1{}) {
		authority.ProbeScope = o.probeScope
		authority.ProbeRates = o.probeRates
	}
	return authority
}

// The existing exclusive borrow owns one temporary aggregate ticket. Its proxy
// subtotal is separate from the deliberately conservative transport queue charge.
func (b *ProductionAttemptBorrowV1) reserveAttachmentPreparationV1() (runtimeengine.ProductionClientAttachmentPreparationV1, productionBudgetTicketV1, error) {
	var empty runtimeengine.ProductionClientAttachmentPreparationV1
	var noTicket productionBudgetTicketV1
	if !b.validV1() {
		return empty, noTicket, runtimeengine.ServiceInvalidRequestV1
	}
	a, o := b.admission, b.admission.owner
	r, p := a.resources, o.parent
	p.mu.Lock()
	defer p.mu.Unlock()
	if !b.active || b.closed || a.released || a.borrow != b || o.attempt != a || a.generation != p.attempt || p.state != productionParentOpenV1 {
		return empty, noTicket, runtimeengine.ServiceCancelledV1
	}
	r.mu.Lock()
	retired := r.destroyed
	r.mu.Unlock()
	if retired || r.attachmentScratchBytes != 0 {
		return empty, noTicket, runtimeengine.ServiceInvalidRequestV1
	}
	proxy := r.proxyCeilingBytes != 0
	minimum, err := runtimeengine.ServicePreparationBoundsForPlanV1(o.plan, proxy)
	if err != nil {
		return empty, noTicket, err
	}
	if !productionProxyFitsV1(r, a.transportProxyBytes, productionAttemptHolderBytesV1(), minimum.ProxyAttributedBytes) {
		return empty, noTicket, runtimeengine.ServiceResourceLimitV1
	}
	ticket, status := p.budget.reserveV1(productionBudgetChargeV1{owned: minimum.OwnedBytes})
	if status != 0 {
		return empty, noTicket, productionBorrowErrorV1(status)
	}
	r.attachmentScratchBytes, r.attachmentScratchSerial = minimum.OwnedBytes, ticket.serial
	return runtimeengine.ProductionClientAttachmentPreparationV1{OwnedBytes: minimum.OwnedBytes, ProxyAttributedBytes: minimum.ProxyAttributedBytes}, ticket, nil
}

func (b *ProductionAttemptBorrowV1) releaseAttachmentPreparationV1(ticket productionBudgetTicketV1) error {
	a, p := b.admission, b.admission.owner.parent
	p.mu.Lock()
	defer p.mu.Unlock()
	r := a.resources
	if ticket.ledger != p.budget || ticket.serial == 0 || r.attachmentScratchSerial != ticket.serial || r.attachmentScratchBytes == 0 {
		return runtimeengine.ServiceInvalidRequestV1
	}
	if s := p.budget.releaseV1(ticket); s != 0 {
		return productionBorrowErrorV1(s)
	}
	r.attachmentScratchBytes, r.attachmentScratchSerial = 0, 0
	return nil
}

// A concrete pointer constraint keeps nil checks typed: a nil service pump must
// never become a non-nil interface whose Done method dereferences that pointer.
// Callers defer this after endV1 so retirement and scratch release finish first.
func finishProductionAttachmentV1[P interface {
	*runtimeengine.ServicePumpV1 | *runtimeengine.RawPacketPumpV2
	Close() error
	Done() <-chan struct{}
}](b *ProductionAttemptBorrowV1, ticket productionBudgetTicketV1, pump *P, err *error) {
	retire := func() {
		if *pump != nil {
			(*pump).Close()
			<-(*pump).Done()
			*pump = nil
		}
	}
	if *err != nil {
		retire()
	}
	if releaseErr := b.releaseAttachmentPreparationV1(ticket); releaseErr != nil && *err == nil {
		retire()
		*err = releaseErr
	}
}

func (b *ProductionAttemptBorrowV1) AttachServiceV1(ctx context.Context, result *auth.ProcessHandshakeResultV1, carrier *tlstcp.Conn) (pump *runtimeengine.ServicePumpV1, err error) {
	defer func() {
		if err != nil && carrier != nil {
			carrier.Close()
		}
	}()
	if ctx == nil {
		return nil, runtimeengine.ServiceInvalidRequestV1
	}
	if s := b.beginV1(true, true); s != 0 {
		return nil, productionBorrowErrorV1(s)
	}
	defer b.endV1()
	preparation, scratchTicket, reserveErr := b.reserveAttachmentPreparationV1()
	if reserveErr != nil {
		return nil, reserveErr
	}
	defer finishProductionAttachmentV1(b, scratchTicket, &pump, &err)
	o := b.admission.owner
	err = o.current.WithVerifiedV1(func(_ profile.OfflineVerifiedArtifact, _ lifecycle.VerifiedState, policy runtimepolicy.PolicyV2, _ time.Time) error {
		if policy.SchemaVersion != runtimepolicy.SchemaVersionV3 || policy.Services == nil {
			return runtimeengine.ServiceNotAdmittedV1
		}
		var e error
		pump, e = runtimeengine.NewProductionClientServicePumpV1(ctx, result, b.admission.resources.installation, carrier, b.runtimeAuthorityV1(false), preparation)
		return e
	})
	if terminal := b.completionStatusV1(); terminal != int32(productionSuccessV1) {
		err = productionBorrowErrorV1(terminal)
		if pump != nil {
			pump.Close()
			<-pump.Done()
			pump = nil
		}
	}
	return pump, err
}
func (b *ProductionAttemptBorrowV1) AttachRawV2(ctx context.Context, result *auth.ProcessHandshakeResultV1, carrier *tlstcp.Conn) (pump *runtimeengine.RawPacketPumpV2, err error) {
	defer func() {
		if err != nil && carrier != nil {
			carrier.Close()
		}
	}()
	if ctx == nil {
		return nil, runtimeengine.ServiceInvalidRequestV1
	}
	if s := b.beginV1(true, true); s != 0 {
		return nil, productionBorrowErrorV1(s)
	}
	defer b.endV1()
	preparation, scratchTicket, reserveErr := b.reserveAttachmentPreparationV1()
	if reserveErr != nil {
		return nil, reserveErr
	}
	defer finishProductionAttachmentV1(b, scratchTicket, &pump, &err)
	o := b.admission.owner
	err = o.current.WithVerifiedV1(func(_ profile.OfflineVerifiedArtifact, _ lifecycle.VerifiedState, policy runtimepolicy.PolicyV2, _ time.Time) error {
		if policy.SchemaVersion != runtimepolicy.SchemaVersionV2 || policy.Services != nil {
			return runtimeengine.ServiceNotAdmittedV1
		}
		var e error
		pump, e = runtimeengine.NewProductionClientRawPacketPumpV2(ctx, result, b.admission.resources.installation, carrier, b.runtimeAuthorityV1(true), preparation)
		return e
	})
	if terminal := b.completionStatusV1(); terminal != int32(productionSuccessV1) {
		err = productionBorrowErrorV1(terminal)
		if pump != nil {
			pump.Close()
			<-pump.Done()
			pump = nil
		}
	}
	return pump, err
}
func productionBorrowErrorV1(status int32) error {
	switch productionStatusV1(status) {
	case productionSuccessV1:
		return nil
	case productionAuthorityRevokedV1:
		return runtimeengine.ServiceAuthorityRevokedV1
	case productionAuthorityExpiredV1:
		return runtimeengine.ServiceAuthorityExpiredV1
	case productionCancelledV1:
		return runtimeengine.ServiceCancelledV1
	case productionResourceLimitV1:
		return runtimeengine.ServiceResourceLimitV1
	case productionNotAdmittedV1:
		return runtimeengine.ServiceNotAdmittedV1
	default:
		return errors.New("production attempt rejected")
	}
}
