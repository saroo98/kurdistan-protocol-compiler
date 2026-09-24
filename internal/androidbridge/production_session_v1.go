// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	runtimeengine "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
)

// Fixed process ownership, never reset by closing or reopening a parent.
var productionOpaqueIDsV1 atomic.Uint64

func nextProductionOpaqueIDV1(counter *atomic.Uint64) (uint64, int32) {
	for {
		old := counter.Load()
		if old == math.MaxUint64 {
			return 0, 5
		}
		if counter.CompareAndSwap(old, old+1) {
			return old + 1, 0
		}
	}
}

// Only trusted native composition supplies these dependencies. None is decoded
// from KPO1 or provided by an app-facing configuration setter.
type ProductionSessionConfigV1 struct {
	Environment       productionCurrentEnvironmentV1
	Platform          ProductionSessionPlatformV1
	Factory           ProductionAttemptFactoryV1
	ProbeRates        *runtimeengine.ProbeRateRegistryV1
	Now, MonotonicNow func() time.Time
	Limits            selfhost.LiveMaintenanceLimits
	// External C/adapter/Java backing only. Native values added for scoped
	// integration are measured separately by unsafe.Sizeof in native charges.
	OutputMetadataBytes uint64
}

type ProductionSessionPlatformV1 interface {
	ProductionPlatformOwnerV1
	RegisterProductionSocketV1(context.Context, *ProductionSocketExpectationV1) (ProductionSocketRegistrationV1, int32)
}
type ProductionSocketRegistrationV1 interface {
	BindingRequiredV1() bool
	ConfirmV1(uint8, uint8, uint64) int32
	DoneV1() <-chan struct{}
	CloseV1() int32
}
type ProductionAttemptRunnerV1 interface {
	RunV1(context.Context, func(*runtimeengine.ServiceRunPublicationV1) int32) int32
	ServicePumpV1() (*runtimeengine.ServicePumpV1, int32)
}

// A producer verifies these immutable requested values against its own current
// framework selection. Returning the values is not an assertion of OS proof.
type ProductionSocketExpectationV1 struct {
	self                  *ProductionSocketExpectationV1
	parent                *productionParentV1
	epoch, attempt, token uint64
	fd                    int
	hasNetwork            uint8
	network               uint64
	selectionExplicit     bool
}

func (e *ProductionSocketExpectationV1) IdentityV1() (uint64, uint64, uint64, int, bool) {
	if e == nil || e.self != e || e.parent == nil {
		return 0, 0, 0, -1, false
	}
	e.parent.mu.Lock()
	defer e.parent.mu.Unlock()
	if e.parent.state != productionParentOpenV1 || e.parent.attempt != e.attempt || e.parent.ticket.epoch != e.epoch || e.parent.session == nil || e.parent.session.expected != e {
		return 0, 0, 0, -1, false
	}
	return e.epoch, e.attempt, e.token, e.fd, true
}
func (e *ProductionSocketExpectationV1) SelectionV1() (bool, uint8, uint64) {
	if e == nil || e.self != e {
		return false, 0, 0
	}
	return e.selectionExplicit, e.hasNetwork, e.network
}
func (e *ProductionCurrentExpectationV1) MatchesSettingsV1(settings []byte) bool {
	if e == nil || e.self != e || e.parent == nil || len(settings) == 0 || len(settings) > productionSettingsMaxBytesV1 {
		return false
	}
	e.parent.mu.Lock()
	defer e.parent.mu.Unlock()
	return !e.retired && e.epoch == e.parent.ticket.epoch && len(settings) == e.settingsLength && sha256.Sum256(settings) == e.settingsIdentity
}

type productionDeliveryV1 struct {
	invoking                   bool
	token, underlying, attempt uint64
	length                     int
	deadline                   time.Time
	use                        productionUseV1
}
type productionStreamV1 struct {
	child, attempt            uint64
	wire                      uint32
	opening, closed, localFIN bool
	delivery                  productionDeliveryV1
}
type productionCommandV1 struct {
	kind, reason, protectedOK, hasNetwork uint8
	network, token                        uint64
	use                                   productionUseV1
}
type productionSessionV1 struct {
	parent                      *productionParentV1
	handle                      Handle
	config                      ProductionSessionConfigV1
	ticket                      productionBudgetTicketV1
	settingsLength              int
	settingsIdentity            [32]byte
	projection                  productionProjectionV1 // original scalar narrowing, no Plan/settings aliases
	snapshot                    [productionSnapshotMaxBytesV1]byte
	eventSnapshot               [productionSnapshotMaxBytesV1]byte
	snapshotLength              int
	port                        *runtimeengine.PacketPortV1
	pump                        *runtimeengine.ServicePumpV1
	transport                   ProductionAttemptTransportV1
	socket                      ProductionSocketRegistrationV1
	socketClosed                bool
	expected                    *ProductionSocketExpectationV1
	selectionExplicit           bool
	selectedHasNetwork          uint8
	selectedNetwork             uint64
	coordinator                 productionUseV1
	wake, done                  chan struct{}
	runDone                     chan int32
	attemptContext              context.Context
	attemptCancel               context.CancelFunc
	ready, published, quiescing bool
	waitingPath                 bool
	command                     productionCommandV1
	nextToken, nextChild        uint64
	nextSocket                  uint64
	socketToken                 uint64
	socketDeadline              time.Time
	packet                      productionDeliveryV1
	streams                     [64]productionStreamV1
	fallbackUsed, automaticUsed uint8
	endpoint                    uint8
	cleanupOnce                 sync.Once
	cleanupDone                 chan struct{}
	cleanupResult               int32
}

func OpenProductionV1(registry *HandleRegistry, request, output []byte, config ProductionSessionConfigV1) (Handle, int, int32) {
	return OpenProductionV1Scoped(registry, request, output, config, ProductionOutputInvocationV1{})
}

func OpenProductionV1Scoped(registry *HandleRegistry, request, output []byte, config ProductionSessionConfigV1, inv ProductionOutputInvocationV1) (Handle, int, int32) {
	if len(output) < productionSnapshotMaxBytesV1 {
		return 0, 0, 4
	}
	view, code := decodeProductionOpenV1(request)
	if code != 0 {
		return 0, 0, int32(code)
	}
	if view.purpose != 1 {
		return 0, 0, 2
	}
	settings, code := decodeProductionSettingsV1(view.settings)
	if code != 0 {
		return 0, 0, int32(code)
	}
	if registry == nil || config.Environment == nil || config.Platform == nil || config.Factory == nil || config.ProbeRates == nil || config.Now == nil || config.MonotonicNow == nil {
		return 0, 0, 2
	}
	capacity := uint64(settings.memoryMiB) << 20
	if capacity == 0 {
		capacity = 80 << 20
	}
	capacity = min(capacity, 128<<20)
	if s := productionOutputOpeningV1(registry, inv, config.OutputMetadataBytes, capacity); s != 0 {
		return 0, 0, s
	}
	ticket, s := reserveProductionSlotV1(registry)
	if s != 0 {
		return 0, 0, s
	}
	p, s := newProductionParentV1(ticket, capacity, time.Time{})
	if s != 0 {
		return 0, 0, s
	}
	p.mu.Lock()
	if !inv.legacyV1() {
		p.output, p.outputOwner = inv.observer, inv.owner
		s = productionOutputStatusV1(p.output.BindParentV1(inv.call, ticket.epoch))
		if s == 0 {
			inv.epoch = ticket.epoch // local copy only
			s = productionOutputStatusV1(p.output.BindLaneV1(inv.call, inv.epoch, 0, p.attempt))
		}
	}
	p.mu.Unlock()
	if s != 0 {
		p.cancelV1(s)
		p.retireV1()
		return 0, 0, s
	}
	opening, s := p.beginUseV1(0, productionBudgetChargeV1{})
	if s != 0 {
		p.cancelV1(s)
		p.retireV1()
		return 0, 0, s
	}
	// Includes snapshot encoder scratch and bounded by-value selection holders.
	charge := uint64(unsafe.Sizeof(productionSessionV1{})) + uint64(unsafe.Sizeof(productionOpaqueIDsV1)) + uint64(unsafe.Sizeof(ProductionSocketExpectationV1{})) + 3*uint64(unsafe.Sizeof(productionProjectionV1{})) + 2*uint64(unsafe.Sizeof(productionSnapshotV1{})) + 2*productionSnapshotMaxBytesV1 + 8192
	// This charge cannot release the producer's independently retained outer
	// reservation. Count native invocation value backing, not ART estimates.
	charge, ok := maintenanceAddV1(charge, config.OutputMetadataBytes, uint64(unsafe.Sizeof(inv)), 65*uint64(unsafe.Sizeof(productionRetiredDeliveryV1{})))
	if !ok {
		p.finishUseV1(opening)
		p.cancelV1(5)
		p.retireV1()
		return 0, 0, 5
	}
	owned, s := p.budget.reserveV1(productionBudgetChargeV1{owned: charge})
	if s != 0 {
		p.finishUseV1(opening)
		p.cancelV1(s)
		p.retireV1()
		return 0, 0, s
	}
	v := &productionSessionV1{parent: p, config: config, ticket: owned, settingsLength: len(view.settings), settingsIdentity: sha256.Sum256(view.settings), wake: make(chan struct{}, 1), done: make(chan struct{}), cleanupDone: make(chan struct{})}
	p.session = v
	registry.mu.Lock()
	slot := &registry.slots[ticket.index]
	slot.productionGeneration++
	v.handle = encodeHandle(ticket.index, slot.productionGeneration, HandleProductionSession)
	registry.mu.Unlock()
	p.mu.Lock()
	p.outputHandle = v.handle
	if p.output != nil {
		s = productionOutputStatusV1(p.output.BindHandleV1(inv.call, inv.epoch, v.handle))
	}
	p.mu.Unlock()
	if s != 0 {
		v.abortOpeningV1(opening, s)
		return 0, 0, s
	}
	limits := config.Limits
	if limits.MaxArtifactBytes == 0 {
		limits.MaxArtifactBytes = envelope.MaxTotalInputBytes
	}
	if limits.MaxPublicationBytes == 0 {
		limits.MaxPublicationBytes = 8 << 20
	}
	_, s = newProductionAdmissionComposedV1(p, opening, MaintenanceCurrentInputV1{view.verify, view.activation, view.recipientRequest, view.recipientPrivate}, settings, config.Environment, config.Platform, config.Now, config.MonotonicNow, config.ProbeRates, limits, v.prepareSnapshotV1)
	if s != 0 {
		v.abortOpeningV1(opening, s)
		return 0, 0, s
	}
	v.coordinator, s = p.beginUseV1(productionUseCoordinatorV1, productionBudgetChargeV1{})
	if s != 0 {
		v.abortOpeningV1(opening, s)
		return 0, 0, s
	}
	// No registry lock under this fence. The reserved slot already points at p;
	// its public identity becomes usable only when published is true here.
	p.mu.Lock()
	if p.state != productionParentOpenV1 || !time.Now().Before(p.admission.monotonicDeadline) {
		p.mu.Unlock()
		v.abortOpeningV1(opening, 7)
		return 0, 0, 7
	}
	p.deadline = p.admission.monotonicDeadline
	if p.output != nil {
		s = productionOutputStatusV1(p.output.PrepareV1(inv.call, inv.epoch, p.attempt, 0, 0, p.deadline, false))
		if s != 0 {
			p.mu.Unlock()
			v.abortOpeningV1(opening, s)
			return 0, 0, s
		}
	}
	v.published = true
	copy(output, v.snapshot[:v.snapshotLength])
	p.mu.Unlock()
	go v.coordinateV1()
	p.finishUseV1(opening)
	return v.handle, v.snapshotLength, 0
}

func (v *productionSessionV1) abortOpeningV1(opening productionUseV1, status int32) {
	p := v.parent
	p.cancelV1(status)
	if v.coordinator.parent != nil {
		p.finishUseV1(v.coordinator)
	}
	p.finishUseV1(opening)
	if p.admission != nil {
		if cleanup := p.admission.closeV1(context.Background()); cleanup != 0 {
			v.retainCleanupV1(cleanup)
			return
		}
	}
	if cleanup := p.budget.releaseV1(v.ticket); cleanup != 0 {
		v.retainCleanupV1(cleanup)
		return
	}
	p.retireV1()
}

func (v *productionSessionV1) prepareSnapshotV1(o *productionAdmissionV1, x *productionProjectionV1) int32 {
	v.projection = *x
	v.projection.plan = sessionplan.PlanV2{}
	v.projection.request = productionSettingsV1{}
	reservation, err := o.resources.installation.ReservationV1()
	if err != nil {
		return productionResourceStatusV1(err)
	}
	v.port, err = o.resources.installation.PacketPortV1()
	if err != nil {
		return productionResourceStatusV1(err)
	}
	s := productionSnapshotV1{
		profileGeneration: x.plan.ProfileGeneration, planDigest: x.plan.Digest,
		effectiveMode: x.effectiveMode, effectiveDNSMode: x.effectiveDNSMode, effectiveMTU: x.effectiveMTU, metered: x.request.metered, perAppMode: x.request.routingMode, effectivePackageCount: x.request.packageCount,
		signedCapabilityMask: x.signedCapabilityMask, nativeCapabilityMask: x.nativeCapabilityMask, effectiveCapabilityMask: x.effectiveCapabilityMask,
		packetMax: x.packetMax, queuePackets: x.queuePackets, incompleteOps: x.incompleteOps, payloadProtocolMask: x.payloadProtocolMask,
		signedReconnectMax: x.signedReconnectMax, nativeReconnectMax: x.nativeReconnectMax, effectiveAutomaticReconnectMax: x.effectiveAutomaticReconnectMax, fallbackAttemptMax: x.fallbackAttemptMax, dialTimeoutMillis: x.dialTimeoutMillis, idleTimeoutMillis: x.effectiveSessionIdleMillis,
		signedStreamMax: x.signedStreamMax, nativeStreamMax: x.nativeStreamMax, effectiveStreamMax: x.effectiveStreamMax, nativeClientMax: x.nativeClientMax, effectiveClientMax: x.effectiveClientMax,
		signedBufferBytes: x.signedProxyBufferBytes, effectiveTotalBufferBytes: x.effectiveProxyBufferBytes, effectiveProxyIdleSeconds: x.effectiveProxyIdleSeconds, signedConnectMillis: x.signedConnectMillis, perDirectionQueueBytes: x.perDirectionQueueBytes, streamChunkMax: x.streamChunkMax,
		probeMaxConcurrent: x.probeMaxConcurrent, probeMaxSamples: x.probeMaxSamples, probeMinAttemptIntervalMillis: x.probeMinAttemptIntervalMillis, probeAttemptsPerMinute: x.probeAttemptsPerMinute, probeMaxTotalMillis: x.probeMaxTotalMillis,
		updateMaxArtifactBytes: x.updateMaxArtifactBytes, updateMaxTimeoutMillis: x.updateMaxTimeoutMillis, updateMinCheckIntervalSeconds: x.updateMinCheckIntervalSeconds,
		rawFlowStatus: x.rawFlowStatus, effectiveTCPFlowMax: x.effectiveTCPFlowMax, effectiveUDPFlowMax: x.effectiveUDPFlowMax, effectiveFlowIdleMillis: x.effectiveFlowIdleMillis, nativeAggregateBufferMax: productionNativeAggregateV1, effectiveAggregateBufferMax: x.effectiveAggregateBufferBytes, flowTableReservedBytes: uint32(reservation.FlowOwnedBytes),
	}
	if x.rawFlowStatus == 1 {
		s.nativeTCPFlowMax, s.nativeUDPFlowMax = 4096, 2048
	}
	s.effectiveIP = 4
	if x.plan.IPMode == runtimepolicy.IPModeIPv4Only {
		s.effectiveIP = 2
	}
	if x.plan.IPMode == runtimepolicy.IPModeIPv6Only {
		s.effectiveIP = 3
	}
	if x.effectiveMode != 3 {
		if s.effectiveIP != 3 {
			s.clientV4.family = 4
			copy(s.clientV4.value[:], x.plan.ClientIPv4[:])
			s.dns[s.dnsCount].family = 4
			copy(s.dns[s.dnsCount].value[:], x.plan.DNSIPv4[:])
			s.dnsCount++
		}
		if s.effectiveIP != 2 {
			s.clientV6.family = 6
			s.clientV6.value = x.plan.ClientIPv6
			s.dns[s.dnsCount] = productionAddressV1{6, x.plan.DNSIPv6}
			s.dnsCount++
		}
		for _, route := range x.plan.Routes {
			i := s.routeCount
			if i >= 256 {
				return 4
			}
			s.routes[i].address.family = uint8(len(route.Address)/4*2 + 2)
			if len(route.Address) == 16 {
				s.routes[i].address.family = 6
			}
			copy(s.routes[i].address.value[:], route.Address)
			s.routes[i].bits = route.PrefixLen
			s.routeCount++
		}
	}
	err = o.current.WithVerifiedV1(func(verified profile.OfflineVerifiedArtifact, _ lifecycle.VerifiedState, _ runtimepolicy.PolicyV2, _ time.Time) error {
		content := sha256.Sum256([]byte(profile.InspectRedacted(verified).ContentSHA256))
		copy(s.profileFingerprint[:], content[:16])
		return nil
	})
	if err != nil {
		return 18
	}
	strategy := sha256.Sum256([]byte(x.plan.StrategyID))
	relay := sha256.Sum256([]byte(x.plan.RelayKeyID))
	copy(s.strategyFingerprint[:], strategy[:16])
	copy(s.relayFingerprint[:], relay[:16])
	n, status := encodeProductionSnapshotV1(s, v.snapshot[:])
	v.snapshotLength = n
	return int32(status)
}

func productionSessionLookupV1(r *HandleRegistry, h Handle) (*productionSessionV1, int32) {
	if r == nil || h == 0 || HandleType(uint64(h)>>56) != HandleProductionSession || uint64(h)&0x00ff000000000000 != 0 {
		return nil, 3
	}
	i := uint16(h)
	g := uint32(uint64(h) >> 16)
	if i == 0 || int(i) > MaxBridgeHandles || g == 0 {
		return nil, 3
	}
	r.mu.Lock()
	slot := &r.slots[i-1]
	p := slot.productionParent
	valid := slot.privatelyReserved && slot.productionGeneration == g && p != nil
	r.mu.Unlock()
	if !valid {
		return nil, 3
	}
	p.mu.Lock()
	v := p.session
	valid = v != nil && v.handle == h && v.published && p.state != productionParentClosedV1
	p.mu.Unlock()
	if !valid {
		return nil, 3
	}
	return v, 0
}
func productionRetiredResultV1(r *HandleRegistry, h Handle) int32 {
	if r == nil || h == 0 {
		return 3
	}
	i := uint16(h)
	if i == 0 || int(i) > MaxBridgeHandles {
		return 3
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	slot := &r.slots[i-1]
	if slot.retiredParent.valid && slot.retiredParent.kind == HandleProductionSession && slot.retiredParent.handle == h {
		return slot.retiredParent.nativeResult
	}
	return 3
}
func NextProductionControlV1(r *HandleRegistry, h Handle, out []byte) (int, int32) {
	return NextProductionControlV1Scoped(r, h, out, ProductionOutputInvocationV1{})
}
func NextProductionControlV1Scoped(r *HandleRegistry, h Handle, out []byte, inv ProductionOutputInvocationV1) (int, int32) {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return 0, s
	}
	return v.parent.nextControlScopedV1(context.Background(), out, inv)
}
func (v *productionSessionV1) signalV1() {
	select {
	case v.wake <- struct{}{}:
	default:
	}
}
func (v *productionSessionV1) terminalV1(reason int32) {
	if !validProductionTerminalStatusV1(productionStatusV1(reason)) {
		reason = 18
	}
	if reason == 13 {
		v.parent.enqueueControlFixedV1(productionControlRevokedV1, nil)
		return
	}
	if reason == 7 {
		v.parent.enqueueControlFixedV1(productionControlStoppedV1, nil)
		return
	}
	var body [2]byte
	binary.BigEndian.PutUint16(body[:], uint16(reason))
	v.parent.enqueueControlFixedV1(productionControlFailedV1, body[:])
}
func (v *productionSessionV1) retainCleanupV1(status int32) {
	if status == 0 {
		return
	}
	v.parent.mu.Lock()
	if v.parent.cleanupResult == 0 {
		v.parent.cleanupResult = status
	}
	v.parent.mu.Unlock()
}
func CancelProductionV1(r *HandleRegistry, h Handle) int32 {
	return CancelProductionV1Scoped(r, h, ProductionOutputInvocationV1{})
}
func CancelProductionV1Scoped(r *HandleRegistry, h Handle, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		if !inv.legacyV1() {
			return productionRetiredOutputV1(r, h, inv)
		}
		return productionRetiredResultV1(r, h)
	}
	v.terminalV1(7)
	<-v.done
	v.parent.mu.Lock()
	s = v.parent.cleanupResult
	v.parent.mu.Unlock()
	return s
}
func CloseProductionV1(r *HandleRegistry, h Handle) int32 {
	return CloseProductionV1Scoped(r, h, ProductionOutputInvocationV1{})
}
func CloseProductionV1Scoped(r *HandleRegistry, h Handle, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		if !inv.legacyV1() {
			return productionRetiredOutputV1(r, h, inv)
		}
		return productionRetiredResultV1(r, h)
	}
	return v.closeOutputParentV1()
}
func (v *productionSessionV1) closeOutputParentV1() int32 {
	v.cleanupOnce.Do(func() {
		v.terminalV1(7)
		<-v.done
		v.parent.mu.Lock()
		pending := v.parent.activeUses != 0 || v.socket != nil || v.transport != nil
		first := v.parent.cleanupResult
		v.parent.mu.Unlock()
		if pending && first != 0 {
			v.cleanupResult = first
			close(v.cleanupDone)
			return
		}
		v.cleanupResult = v.parent.admission.closeV1(context.Background())
		if v.cleanupResult == 0 {
			clear(v.snapshot[:])
			clear(v.eventSnapshot[:])
			v.retainCleanupV1(v.parent.budget.releaseV1(v.ticket))
			v.cleanupResult = v.parent.retireV1()
		}
		close(v.cleanupDone)
	})
	<-v.cleanupDone
	return v.cleanupResult
}

func productionOperationStatusV1(err error) int32 {
	if err == nil {
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 7
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return 8
	}
	if errors.Is(err, io.ErrShortBuffer) {
		return 4
	}
	if errors.Is(err, io.ErrClosedPipe) {
		return 9
	}
	if err == runtimeengine.ErrPacketPortBusy {
		return 5
	}
	// Refusing one packet does not invalidate the authenticated session.
	if err == runtimeengine.ErrPacketInvalid || err == runtimeengine.ErrPacketFamily ||
		err == runtimeengine.ErrPacketProtocol || err == runtimeengine.ErrPacketSource ||
		err == runtimeengine.ErrPacketDestination || err == runtimeengine.ErrPacketFragmented {
		return 10
	}
	if err == runtimeengine.ErrPacketPortPacket {
		return 2
	}
	if err == runtimeengine.ErrPacketPortToken || err == runtimeengine.ErrPacketPortDelivery || err == runtimeengine.ErrAuthenticatedFrameState {
		return 3
	}
	if err == runtimeengine.ServiceUnreachableV1 {
		return 11
	}
	if errors.Is(err, runtimeengine.ServiceAuthorityRevokedV1) {
		return 7
	}
	return productionMaintenanceStatusV1(maintenanceProbeResultV1(err))
}

// Commands reserve a single counted slot. Their success is admission only;
// protection verification and all network stages execute on the coordinator.
func (v *productionSessionV1) admitCommandV1(c productionCommandV1) int32 {
	return v.admitCommandOutputV1(c, ProductionOutputInvocationV1{})
}
func (v *productionSessionV1) admitCommandOutputV1(c productionCommandV1, inv ProductionOutputInvocationV1) int32 {
	p := v.parent
	use, s := p.beginUseOutputV1(4, productionBudgetChargeV1{}, inv, false)
	if s != 0 {
		return s
	}
	p.mu.Lock()
	if p.state != productionParentOpenV1 || v.command.kind != 0 {
		p.mu.Unlock()
		p.finishUseV1(use)
		return 5
	}
	if c.kind == 1 && (c.token == 0 || c.token != v.socketToken || !time.Now().Before(v.socketDeadline)) {
		p.mu.Unlock()
		p.finishUseV1(use)
		v.terminalV1(3)
		return 3
	}
	if c.kind != 1 && !v.ready && !v.waitingPath {
		p.mu.Unlock()
		p.finishUseV1(use)
		return 3
	}
	if c.reason == 2 && v.automaticUsed >= v.projection.effectiveAutomaticReconnectMax {
		p.mu.Unlock()
		p.finishUseV1(use)
		return 1
	}
	deadline := p.admission.monotonicDeadline
	if c.kind == 1 {
		deadline = productionOutputDeadlineV1(deadline, v.socketDeadline)
	}
	if s = p.outputPrepareLockedV1(inv, use.attempt, 0, 0, deadline, false); s != 0 {
		p.mu.Unlock()
		p.finishUseV1(use)
		return s
	}
	if c.reason == 2 {
		v.automaticUsed++
	}
	c.use = use
	v.command = c
	p.mu.Unlock()
	v.signalV1()
	return 0
}
func ConfirmProductionSocketV1(r *HandleRegistry, h Handle, token uint64, ok, has uint8, network uint64) int32 {
	return ConfirmProductionSocketV1Scoped(r, h, token, ok, has, network, ProductionOutputInvocationV1{})
}
func ConfirmProductionSocketV1Scoped(r *HandleRegistry, h Handle, token uint64, ok, has uint8, network uint64, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return s
	}
	if ok > 1 || has > 1 || (has == 0) != (network == 0) {
		return 2
	}
	return v.admitCommandOutputV1(productionCommandV1{kind: 1, token: token, protectedOK: ok, hasNetwork: has, network: network}, inv)
}
func ReconnectProductionV1(r *HandleRegistry, h Handle, reason uint8) int32 {
	return ReconnectProductionV1Scoped(r, h, reason, ProductionOutputInvocationV1{})
}
func ReconnectProductionV1Scoped(r *HandleRegistry, h Handle, reason uint8, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return s
	}
	if reason < 1 || reason > 3 {
		return 2
	}
	return v.admitCommandOutputV1(productionCommandV1{kind: 2, reason: reason}, inv)
}
func HandoverProductionV1(r *HandleRegistry, h Handle, has uint8, network uint64) int32 {
	return HandoverProductionV1Scoped(r, h, has, network, ProductionOutputInvocationV1{})
}
func HandoverProductionV1Scoped(r *HandleRegistry, h Handle, has uint8, network uint64, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return s
	}
	if has > 1 || (has == 0) != (network == 0) {
		return 2
	}
	return v.admitCommandOutputV1(productionCommandV1{kind: 3, reason: 4, hasNetwork: has, network: network}, inv)
}

func (v *productionSessionV1) freshTokenLockedV1() (uint64, int32) {
	if v.nextToken == math.MaxUint64 {
		return 0, 5
	}
	token, s := nextProductionOpaqueIDV1(&productionOpaqueIDsV1)
	if s == 0 {
		v.nextToken = token
	}
	return token, s
}

func (v *productionSessionV1) coordinateV1() {
	p := v.parent
	retired := false
	defer func() {
		v.retireAttemptV1()
		p.mu.Lock()
		terminal := int32(p.terminal)
		p.mu.Unlock()
		v.terminalV1(terminal)
		p.finishUseV1(v.coordinator)
		close(v.done)
	}()
	for {
		if p.cancelContext.Err() != nil {
			return
		}
		if v.selectionExplicit && v.selectedHasNetwork == 0 {
			p.mu.Lock()
			v.waitingPath = true
			p.mu.Unlock()
			p.enqueueControlFixedV1(productionControlDegradedV1, []byte{2})
			if !v.waitCommandV1(nil) {
				return
			}
			continue
		}
		if v.fallbackUsed >= v.projection.fallbackAttemptMax {
			v.terminalV1(9)
			return
		}
		if retired {
			if _, s := p.nextAttemptV1(); s != 0 {
				v.terminalV1(s)
				return
			}
			v.endpoint = v.fallbackUsed
			if s := v.prepareNextResourcesV1(); s != 0 {
				v.terminalV1(s)
				return
			}
			retired = false
		}
		v.fallbackUsed++
		if v.fallbackUsed > 1 {
			if p.enqueueControlFixedV1(productionControlFallbackStartedV1, []byte{v.fallbackUsed, v.projection.fallbackAttemptMax}) != 0 {
				return
			}
		}
		status := v.startAttemptV1()
		if status == 0 {
			if !v.waitCommandV1(v.runDone) {
				return
			}
		} else {
			if p.cancelContext.Err() != nil {
				return
			}
			if status != 9 && status != 11 && status != 8 {
				v.terminalV1(status)
				return
			}
		}
		v.retireAttemptV1()
		p.mu.Lock()
		failed := p.cleanupResult != 0
		p.mu.Unlock()
		if failed {
			v.terminalV1(18)
			return
		}
		retired = true
	}
}

func (v *productionSessionV1) startAttemptV1() int32 {
	p := v.parent
	o := p.admission
	if s := o.registrationCheckV1(p.cancelContext, v.coordinator); s != 0 {
		return s
	}
	if s := o.acceptTimeV1(v.coordinator); s != 0 {
		return s
	}
	use, s := p.beginUseV1(productionUseAttemptV1, productionBudgetChargeV1{})
	if s != 0 {
		return s
	}
	a, s := newProductionAttemptAdmissionV1(o, o.resources, v.endpoint, use)
	if s != 0 {
		p.finishUseV1(use)
		return s
	}
	v.attemptContext, v.attemptCancel = context.WithCancel(p.cancelContext)
	transport, s := a.PrepareV1(v.attemptContext, v.config.Factory)
	if s != 0 {
		v.transport = a.transport
		return s
	}
	v.transport = transport
	fd, s := transport.SocketFDV1()
	if s != 0 {
		return s
	}
	p.mu.Lock()
	var token uint64
	if v.nextSocket == math.MaxUint64 {
		s = 5
	} else {
		token, s = nextProductionOpaqueIDV1(&productionOpaqueIDsV1)
		if s == 0 {
			v.nextSocket = token
		}
	}
	v.socketToken = token
	v.socketDeadline = time.Now().Add(time.Duration(v.projection.dialTimeoutMillis) * time.Millisecond)
	if o.monotonicDeadline.Before(v.socketDeadline) {
		v.socketDeadline = o.monotonicDeadline
	}
	selected, has, network := v.selectionExplicit, v.selectedHasNetwork, v.selectedNetwork
	v.expected = &ProductionSocketExpectationV1{parent: p, epoch: p.ticket.epoch, attempt: p.attempt, token: token, fd: fd, selectionExplicit: selected, hasNetwork: has, network: network}
	v.expected.self = v.expected
	p.mu.Unlock()
	if s != 0 {
		return s
	}
	if s = o.enterPlatformV1(v.coordinator); s != 0 {
		return s
	}
	v.socket, s = v.config.Platform.RegisterProductionSocketV1(v.attemptContext, v.expected)
	v.socketClosed = false
	if current := o.leavePlatformV1(v.coordinator); current != 0 {
		return current
	}
	if s != 0 {
		return s
	}
	if v.socket == nil || v.socket.DoneV1() == nil {
		return 3
	}
	var body [14]byte
	binary.BigEndian.PutUint64(body[:8], token)
	binary.BigEndian.PutUint32(body[8:12], uint32(fd))
	body[12] = 1
	body[13] = boolByteProductionV1(v.socket.BindingRequiredV1())
	if s = p.enqueueControlFixedV1(productionControlSocketProtectionRequiredV1, body[:]); s != 0 {
		return s
	}
	timer := time.NewTimer(time.Until(v.socketDeadline))
	defer timer.Stop()
	var command productionCommandV1
	for command.kind == 0 {
		select {
		case <-p.cancelContext.Done():
			return 7
		case <-v.socket.DoneV1():
			return 9
		case <-timer.C:
			return 8
		case <-v.wake:
		}
		p.mu.Lock()
		command = v.command
		if command.kind == 1 {
			v.command = productionCommandV1{}
			v.socketToken = 0
		}
		p.mu.Unlock()
		if command.kind != 0 && command.kind != 1 {
			return 3
		}
	}
	if s = o.enterPlatformV1(command.use); s == 0 {
		s = v.socket.ConfirmV1(command.protectedOK, command.hasNetwork, command.network)
		if current := o.leavePlatformV1(command.use); current != 0 {
			s = current
		}
	}
	p.finishUseV1(command.use)
	if s != 0 {
		return s
	}
	if command.protectedOK == 0 {
		return 16
	}
	if s = transport.ConfirmProtectedV1(fd); s != 0 {
		return s
	}
	if s = p.enqueueControlFixedV1(productionControlTransportConnectingV1, nil); s != 0 {
		return s
	}
	for _, stage := range []func(context.Context) int32{transport.ConnectProtectedV1, transport.AuthenticateTLSV1, transport.AuthenticateKurdV1, transport.AttachInstalledV1} {
		if s = stage(v.attemptContext); s != 0 {
			return s
		}
	}
	runner, ok := transport.(ProductionAttemptRunnerV1)
	if !ok {
		return 25
	}
	v.pump, s = runner.ServicePumpV1()
	if s != 0 && s != 1 {
		return s
	}
	// Opening bytes describe the pre-attempt state. Stage the current event
	// before Run's one-shot publication commitment, within reserved ownership.
	eventSnapshot, snapshotStatus := decodeProductionSnapshotV1(v.snapshot[:v.snapshotLength])
	if snapshotStatus != productionSuccessV1 {
		return int32(snapshotStatus)
	}
	eventSnapshot.fallbackAttemptsUsed = v.fallbackUsed
	eventLength, snapshotStatus := encodeProductionSnapshotV1(eventSnapshot, v.eventSnapshot[:])
	if snapshotStatus != productionSuccessV1 {
		return int32(snapshotStatus)
	}
	v.runDone = make(chan int32, 1)
	started := make(chan int32, 1)
	go func() {
		called := false
		result := runner.RunV1(v.attemptContext, func(publication *runtimeengine.ServiceRunPublicationV1) int32 {
			called = true
			result := v.publishReadyV1(a.generation, publication, v.eventSnapshot[:eventLength])
			started <- result
			return result
		})
		if !called {
			started <- result
		}
		v.runDone <- result
	}()
	return <-started
}

func (v *productionSessionV1) publishReadyV1(generation uint64, publication *runtimeengine.ServiceRunPublicationV1, snapshot []byte) int32 {
	kind := productionControlRoutePlanReadyV1
	if generation > 1 {
		kind = productionControlPathChangedV1
	}
	if s := validateProductionControlBodyV1(kind, snapshot); s != 0 {
		return s
	}
	p := v.parent
	p.mu.Lock()
	if p.state != productionParentOpenV1 || p.attempt != generation {
		s := p.terminalOperationStatusLockedV1()
		p.mu.Unlock()
		return s
	}
	if !time.Now().Before(p.admission.monotonicDeadline) {
		p.mu.Unlock()
		return 12
	}
	if int(p.controlCount)+2 > productionControlOrdinaryDescriptorsV1 || uint64(p.controlBytes)+2*productionControlHeaderBytesV1+uint64(len(snapshot)) > productionControlOrdinaryBytesV1 {
		p.mu.Unlock()
		return 5
	}
	if err := publication.CommitV1(); err != nil {
		p.mu.Unlock()
		return productionOperationStatusV1(err)
	}
	// Commit is the linearization point. No fallible work or callback follows
	// before the native fence releases, including both ordinary control writes.
	v.ready, v.quiescing = true, false
	p.appendOrdinaryControlLockedV1(productionControlTransportReadyV1, nil)
	p.appendOrdinaryControlLockedV1(kind, snapshot)
	p.mu.Unlock()
	p.signalControlV1()
	return 0
}

func (v *productionSessionV1) waitCommandV1(run <-chan int32) bool {
	p := v.parent
	deadline := time.NewTimer(time.Until(p.admission.monotonicDeadline))
	defer deadline.Stop()
	for {
		var network <-chan struct{}
		if v.socket != nil {
			network = v.socket.DoneV1()
		}
		select {
		case <-deadline.C:
			v.terminalV1(12)
			return false
		case <-p.cancelContext.Done():
			return false
		case <-network:
			v.terminalV1(9)
			return false
		case result := <-run:
			// Put back the sole joined Run result for retirement.
			v.runDone <- result
			p.mu.Lock()
			allowed := (result == 9 || result == 11 || result == 8) && v.automaticUsed < v.projection.effectiveAutomaticReconnectMax
			if allowed {
				v.automaticUsed++
			}
			p.mu.Unlock()
			if !allowed {
				v.terminalV1(result)
				return false
			}
			if s := p.enqueueControlFixedV1(productionControlReconnectStartedV1, []byte{2, v.automaticUsed, v.projection.signedReconnectMax}); s != 0 {
				return false
			}
			return true
		case <-v.wake:
			p.mu.Lock()
			command := v.command
			if command.kind != 2 && command.kind != 3 {
				p.mu.Unlock()
				continue
			}
			v.command = productionCommandV1{}
			v.ready = false
			v.quiescing = true
			if p.output != nil {
				p.output.AttemptTerminalV1(p.ticket.epoch, p.attempt, 7)
			}
			v.waitingPath = false
			if command.kind == 3 {
				v.selectionExplicit = true
				v.selectedHasNetwork = command.hasNetwork
				v.selectedNetwork = command.network
			}
			p.mu.Unlock()
			p.finishUseV1(command.use)
			if s := p.enqueueControlFixedV1(productionControlReconnectStartedV1, []byte{command.reason, 1, v.projection.signedReconnectMax}); s != 0 {
				return false
			}
			return true
		}
	}
}

func (v *productionSessionV1) prepareNextResourcesV1() int32 {
	p := v.parent
	o := p.admission
	if s := o.registrationCheckV1(p.cancelContext, v.coordinator); s != 0 {
		return s
	}
	if s := o.acceptTimeV1(v.coordinator); s != 0 {
		return s
	}
	x := v.projection
	x.plan = o.plan.Clone()
	p.budget.mu.Lock()
	available := runtimeengine.ProductionClientAvailableV1{AggregateBytes: p.budget.cap - p.budget.owned}
	p.budget.mu.Unlock()
	if x.effectiveMode != 1 {
		available.ProxyBytes = uint64(x.effectiveProxyBufferBytes)
	}
	resources, s := prepareProductionResourcesV1(&x, p.budget, available, o.lastNow, p.attempt)
	if s != 0 {
		x.Destroy()
		return s
	}
	resources.owner = o
	resources.generation = p.attempt
	o.resources = resources
	var err error
	v.port, err = resources.installation.PacketPortV1()
	if err != nil {
		return productionResourceStatusV1(err)
	}
	return 0
}

func (v *productionSessionV1) retireAttemptV1() {
	p := v.parent
	var retired [65]productionRetiredDeliveryV1
	p.mu.Lock()
	v.ready = false
	v.quiescing = true
	if p.output != nil {
		p.output.AttemptTerminalV1(p.ticket.epoch, p.attempt, 7)
	}
	v.waitingPath = false
	v.socketToken = 0
	command := v.command
	v.command = productionCommandV1{}
	p.mu.Unlock()
	// A queued command owns a counted use but has no running caller to release
	// it. Drain it after closing admission and before waiting for attempt uses.
	if command.use.parent != nil {
		p.finishUseV1(command.use)
	}
	if v.attemptCancel != nil {
		v.attemptCancel()
	}
	if v.transport != nil {
		v.transport.CloseWakeV1()
	}
	if v.port != nil {
		v.port.Close()
	}
	if v.runDone != nil {
		<-v.runDone
		v.runDone = nil
	}
	// Handed-out deliveries remain counted after their receive call returns.
	// Teardown owns rejection and releases those exact counts after waking IO.
	for {
		v.retireDeliveriesOutputV1(&retired)
		p.mu.Lock()
		busy := false
		for i := range p.uses {
			if i != productionUseAttemptV1 && i != productionUseCoordinatorV1 && i != productionUseControlPollV1 && i != productionUseOpeningV1 && p.uses[i].live {
				busy = true
				break
			}
		}
		p.mu.Unlock()
		if !busy {
			break
		}
		<-v.wake
	}
	a := p.admission.attempt
	if v.transport != nil {
		v.retainCleanupV1(v.transport.FinishV1())
		select {
		case <-v.transport.DoneV1():
		default:
			v.retainCleanupV1(18)
			return
		}
	} else if a != nil && a.borrow != nil {
		v.retainCleanupV1(a.borrow.FinishOwnedV1())
	}
	if a != nil {
		if a.borrow == nil {
			v.retainCleanupV1(a.resources.destroyV1())
		}
		v.retainCleanupV1(p.finishUseV1(a.use))
	}
	if p.admission.resources != nil {
		v.retainCleanupV1(p.admission.resources.destroyV1())
	}
	if v.socket != nil {
		if v.socketClosed {
			return
		}
		v.socketClosed = true
		status := v.socket.CloseV1()
		v.retainCleanupV1(status)
		if status != 0 {
			return
		}
		v.socket = nil
	}
	v.transport = nil
	v.pump = nil
	v.port = nil
	v.attemptCancel = nil
	p.mu.Lock()
	if p.output != nil {
		for _, d := range retired {
			if d.delivery == 0 {
				continue
			}
			kind := ProductionOutputPacketDeliveryV1
			if d.child != 0 {
				kind = ProductionOutputStreamDeliveryV1
			}
			actual := d.actual
			if actual == 0 {
				actual = p.cleanupResult
			}
			p.output.ResourceRetiredV1(p.ticket.epoch, kind, p.outputHandle, d.attempt, d.child, d.delivery, actual)
		}
		for _, row := range v.streams {
			if row.child != 0 && row.wire != 0 {
				p.output.ResourceRetiredV1(p.ticket.epoch, ProductionOutputStreamV1, p.outputHandle, row.attempt, row.child, 0, p.cleanupResult)
			}
		}
	}
	clear(v.streams[:])
	p.mu.Unlock()
}

func (v *productionSessionV1) retireDeliveriesV1() {
	v.retireDeliveriesOutputV1(nil)
}
func (v *productionSessionV1) retireDeliveriesOutputV1(retired *[65]productionRetiredDeliveryV1) {
	p := v.parent
	var uses [65]productionUseV1
	p.mu.Lock()
	if !v.packet.invoking {
		if retired != nil && v.packet.token != 0 {
			retired[0] = productionRetiredDeliveryV1{attempt: v.packet.attempt, delivery: v.packet.token}
		}
		uses[0] = v.packet.use
		v.packet = productionDeliveryV1{}
	}
	for i := range v.streams {
		if !v.streams[i].delivery.invoking {
			if retired != nil && v.streams[i].delivery.token != 0 {
				retired[i+1] = productionRetiredDeliveryV1{attempt: v.streams[i].delivery.attempt, child: v.streams[i].child, delivery: v.streams[i].delivery.token}
			}
			uses[i+1] = v.streams[i].delivery.use
			v.streams[i].delivery = productionDeliveryV1{}
		}
	}
	p.mu.Unlock()
	for i, use := range uses {
		if use.parent != nil {
			actual := p.finishUseV1(use)
			if retired != nil {
				retired[i].actual = actual
			}
			v.retainCleanupV1(actual)
		}
	}
}
