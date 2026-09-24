// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"context"
	"errors"
	"io"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"time"
	"unsafe"
)

type ServiceTCPConnV1 interface {
	net.Conn
	CloseWrite() error
}
type RelayServiceNetworkV1 interface {
	ResolveProxy(context.Context, []byte, *[16]netip.Addr) (int, error)
	DialTCP(context.Context, netip.AddrPort) (ServiceTCPConnV1, error)
}
type ServicePumpConfigV1 struct {
	PacketIO, Carrier                                                             io.ReadWriteCloser
	ExternalPacketIngress                                                         bool
	StreamLimit, ProbeLimit                                                       uint8
	StreamQueueBytes                                                              uint32
	BufferBudget                                                                  uint64
	MaxRecordBytes                                                                uint32
	Generation                                                                    uint64
	AuthorityDeadline                                                             time.Time
	Now                                                                           func() time.Time
	CheckAuthority                                                                func(time.Time) error
	ProbeScope                                                                    AuthenticatedProbeScopeV1
	ProbeRates                                                                    *ProbeRateRegistryV1
	RelayNetwork                                                                  RelayServiceNetworkV1
	PacketOwnedBytes, PacketQueuedBytes, NetworkOperationBytes, CarrierOwnedBytes uint64
}

// ServicePumpBoundsV1 reports reserved native capacity, not kernel/TLS/GC RSS.
type ServicePumpBoundsV1 struct {
	OwnedBytes, QueuedBytes                uint64
	PacketsProcessed, ServicesProcessed    uint64
	ActiveStreams, ActiveProbes, QueueUsed uint32
}
type serviceQueueSlotV1 struct {
	flow     productionFlowRefV1
	data     []byte
	cached   []byte
	size     int
	id       uint32
	opcode   ServiceOpcodeV1
	state    uint8
	serial   uint64
	deadline time.Time
	stream   int
	probe    int
}
type serviceStreamSlotV1 struct {
	responseQueue                                                     int
	responseSerial                                                    uint64
	id                                                                uint32
	state                                                             uint8
	conn                                                              ServiceTCPConnV1
	cancel                                                            context.CancelFunc
	deadline, idle, tombstone                                         time.Time
	localFIN, remoteFIN, writing, receiving, worker, resultSeen, sent bool
	readEOF                                                           bool
	outBytes, discarded                                               uint32
	request                                                           ProxyRequestV1
	result                                                            error
	scratch                                                           []byte
}
type serviceProbeSlotV1 struct {
	responseQueue                                          int
	responseSerial                                         uint64
	handle                                                 uint64
	id                                                     uint32
	state                                                  uint8
	admission                                              ProbeAdmissionV1
	deadline, sentAt, sentMono, attemptDeadline, tombstone time.Time
	cancel                                                 context.CancelFunc
	worker, awaiting, consumed, resultSeen, hasResult      bool
	result                                                 ServiceResultV1
	failure                                                error
	samples                                                [10]ProbeSampleV1
	sampleCount                                            int
	aggregate                                              ProbeAggregateV1
}
type serviceDeliveryV1 struct {
	id                  uint32
	token               uint64
	length              int
	received, confirmed bool
	deadline            time.Time
}

// ServicePumpV1 is an exclusive, non-copyable owner constructed by one of the
// combined factories. The containing authenticated owner must await Done before
// starting a successor generation or releasing adapter resources.
type ServicePumpV1 struct {
	mu, clockMu                                                                       sync.Mutex
	changed, closed, done                                                             chan struct{}
	cfg                                                                               ServicePumpConfigV1
	endpoint                                                                          ProcessDuplexEndpointV3
	admission                                                                         *ServiceAdmissionV1
	kind                                                                              packetPumpKindV1
	client, terminal, wakeDone, finalized, binding, bindUsed, ready, running, ingress bool
	reason                                                                            error
	users                                                                             int
	ctx                                                                               context.Context
	cancel                                                                            context.CancelFunc
	deadline, lastNow, activity, ioDeadline                                           time.Time
	dialTimeout, idleTimeout                                                          time.Duration
	client4, dns4                                                                     [4]byte
	client6, dns6                                                                     [16]byte
	protocols                                                                         [4]runtimepolicy.PayloadProtocolV2
	protocolCount                                                                     int
	mtu, chunk, slotBytes                                                             int
	codec                                                                             ServiceRecordCodecV1
	rx, packetScratch                                                                 []byte
	queue                                                                             []serviceQueueSlotV1
	head, tail, used                                                                  int
	serial                                                                            uint64
	streams                                                                           []serviceStreamSlotV1
	probes                                                                            []serviceProbeSlotV1
	delivery                                                                          serviceDeliveryV1
	nextID                                                                            uint32
	nextHandle                                                                        uint64
	outer                                                                             uint32
	bounds                                                                            ServicePumpBoundsV1
	postCommit                                                                        func() error
	production                                                                        *productionPacketAdmissionV1
	proxyIdle                                                                         time.Duration
}

const serviceWorkerReserveV1 uint64 = 8192

func NewClientServicePumpV1(r *auth.ProcessHandshakeResultV1, p sessionplan.PlanV2, c ServicePumpConfigV1) (*ServicePumpV1, error) {
	return newServicePumpV1(r, p, c, true)
}
func NewRelayServicePumpV1(r *auth.ProcessHandshakeResultV1, p sessionplan.PlanV2, c ServicePumpConfigV1) (*ServicePumpV1, error) {
	return newServicePumpV1(r, p, c, false)
}
func newServicePumpV1(result *auth.ProcessHandshakeResultV1, plan sessionplan.PlanV2, c ServicePumpConfigV1, client bool) (*ServicePumpV1, error) {
	return newServicePumpPreparedV1(result, plan, c, client, nil, nil)
}

func newServicePumpPreparedV1(result *auth.ProcessHandshakeResultV1, plan sessionplan.PlanV2, c ServicePumpConfigV1, client bool, installed *ProductionClientInstallationV1, prepared *productionDuplexPreparedV1) (*ServicePumpV1, error) {
	return newPacketPumpPreparedV1(result, plan, c, client, installed, prepared, mixedPacketPumpV1)
}

func newPacketPumpPreparedV1(result *auth.ProcessHandshakeResultV1, plan sessionplan.PlanV2, c ServicePumpConfigV1, client bool, installed *ProductionClientInstallationV1, prepared *productionDuplexPreparedV1, kind packetPumpKindV1) (*ServicePumpV1, error) {
	if kind != mixedPacketPumpV1 && kind != rawPacketPumpV2 {
		return nil, ServiceInvalidRequestV1
	}
	if kind == rawPacketPumpV2 && (!client || c.ExternalPacketIngress || c.StreamLimit != 0 || c.ProbeLimit != 0 || c.StreamQueueBytes != 0 || !nilServiceOwnerV1(c.RelayNetwork) || c.NetworkOperationBytes != 0 || c.ProbeScope != (AuthenticatedProbeScopeV1{}) || c.ProbeRates != nil) {
		return nil, ServiceInvalidRequestV1
	}
	if installed != nil && installed.recipe.kind != kind {
		return nil, ServiceNotAdmittedV1
	}
	if c.Now == nil || c.CheckAuthority == nil || c.Generation == 0 || nilServiceOwnerV1(c.PacketIO) || nilServiceOwnerV1(c.Carrier) || c.BufferBudget == 0 || c.BufferBudget > 128<<20 || c.CarrierOwnedBytes == 0 || c.CarrierOwnedBytes > c.BufferBudget {
		return nil, ServiceInvalidRequestV1
	}
	if _, old := c.Carrier.(*ProcessTLSTCPDuplexCarrierV1); old {
		return nil, ServiceInvalidRequestV1
	}
	now := c.Now()
	if now.IsZero() || !c.AuthorityDeadline.After(now) {
		return nil, ServiceAuthorityExpiredV1
	}
	if e := c.CheckAuthority(now); e != nil {
		return nil, serviceTerminalV1(e)
	}
	facts, validFacts := plan.ConstructionFactsV2()
	proxyActive := facts.ProxyBufferBytes != 0 && (installed == nil || installed.recipe.limits.Mode != ProductionTUNV1)
	preparation, prepErr := ServicePreparationBoundsForPlanV1(plan, proxyActive)
	if !validFacts || prepErr != nil {
		return nil, ServiceResourceLimitV1
	}
	if installed == nil {
		if c.BufferBudget <= preparation.OwnedBytes || proxyActive && c.BufferBudget > uint64(facts.ProxyBufferBytes) {
			return nil, ServiceResourceLimitV1
		}
		c.BufferBudget -= preparation.OwnedBytes
		packet, admission, wrapper := c.PacketOwnedBytes, preparation.RetainedAdmissionBytes, uint64(0)
		if client {
			packet = 2*1280 + uint64(unsafe.Sizeof(PacketPortV1{})) + serviceWorkerReserveV1
		}
		if kind == rawPacketPumpV2 {
			admission = 0
			wrapper = uint64(unsafe.Sizeof(RawPacketPumpV2{}))
		}
		known, ok := serviceAddBytesV1(packet, c.CarrierOwnedBytes, admission, wrapper, uint64(unsafe.Sizeof(ServicePumpV1{})))
		if !ok || known >= c.BufferBudget {
			return nil, ServiceResourceLimitV1
		}
	}
	if sessionplan.ValidateV2At(plan, now) != nil {
		return nil, ServiceNotAdmittedV1
	}
	policy, e := plan.RuntimePolicyAt(now)
	defer policy.Destroy()
	if e != nil || !kind.admitsV1(policy) {
		return nil, ServiceNotAdmittedV1
	}
	var a *ServiceAdmissionV1
	transferredAdmission := false
	defer func() {
		if !transferredAdmission {
			a.Destroy()
		}
	}()
	if kind == mixedPacketPumpV1 {
		a, e = NewServiceAdmissionV1(policy, now)
		if e != nil {
			return nil, e
		}
	}
	program, e := liveprogram.DecodeV1(policy.LiveProgram)
	defer destroyProductionRecipeProgramV1(&program)
	if e != nil {
		return nil, ServiceNotAdmittedV1
	}
	var proxy *runtimepolicy.ProxyV1
	if policy.Services != nil {
		proxy = policy.Services.Proxy
	}
	proxyEnabled := proxy != nil && (installed == nil || installed.recipe.limits.Mode != ProductionTUNV1)
	if !proxyEnabled {
		if c.StreamLimit != 0 || c.StreamQueueBytes != 0 {
			return nil, ServiceInvalidRequestV1
		}
	} else {
		if c.StreamLimit == 0 || c.StreamLimit > proxy.MaxConcurrentStreams || c.StreamLimit > 64 || c.StreamQueueBytes == 0 || c.StreamQueueBytes > proxy.MaxQueuedBytesPerDirection {
			return nil, ServiceResourceLimitV1
		}
	}
	active := false
	if policy.Services != nil && policy.Services.Probes != nil {
		for _, t := range policy.Services.Probes.Targets {
			for _, m := range t.Modes {
				active = active || m == uint8(ProbeActiveRelayV1)
			}
		}
	}
	if active {
		if c.ProbeLimit == 0 || c.ProbeLimit > 4 || c.ProbeLimit > policy.Services.Probes.MaxConcurrentOperations || !c.ProbeScope.valid || c.ProbeRates == nil {
			return nil, ServiceInvalidRequestV1
		}
	} else if c.ProbeLimit != 0 {
		return nil, ServiceInvalidRequestV1
	}
	needsNetwork := !client && (proxy != nil || active)
	if (!nilServiceOwnerV1(c.RelayNetwork)) != needsNetwork || client && c.ExternalPacketIngress || c.RelayNetwork == nil && c.NetworkOperationBytes != 0 || needsNetwork && (c.NetworkOperationBytes < 1 || c.NetworkOperationBytes > 1<<20) {
		return nil, ServiceInvalidRequestV1
	}
	packetOwned, packetQueued := c.PacketOwnedBytes, c.PacketQueuedBytes
	if client {
		port, ok := c.PacketIO.(*PacketPortV1)
		if !ok || packetOwned != 0 || packetQueued != 0 {
			return nil, ServiceInvalidRequestV1
		}
		port.mu.Lock()
		valid := !port.closed && port.maximum == int(plan.MTU) && len(port.outbound) == port.maximum && len(port.inbound) == port.maximum
		if installed != nil {
			valid = valid && port == installed.port && port.production == installed.admission
		} else {
			valid = valid && port.production == nil
		}
		packetQueued = uint64(cap(port.inbound) + cap(port.outbound))
		packetOwned = packetQueued + uint64(unsafe.Sizeof(*port)) + serviceWorkerReserveV1
		port.mu.Unlock()
		if !valid {
			return nil, ServiceInvalidRequestV1
		}
	} else if packetOwned == 0 || packetOwned > c.BufferBudget || packetQueued > packetOwned || packetQueued > 16<<20 {
		return nil, ServiceInvalidRequestV1
	}
	extra, flowBytes := uint64(0), uint64(0)
	if kind == rawPacketPumpV2 {
		extra = uint64(unsafe.Sizeof(RawPacketPumpV2{}))
	}
	raw := !c.ExternalPacketIngress
	if installed != nil {
		extra = installed.recipe.extraBytes
		flowBytes = installed.recipe.reservation.FlowOwnedBytes
		raw = installed.admission.raw
	}
	graph, e := sizeServicePumpV1(plan, program, c, packetOwned, packetQueued, extra, flowBytes, a.retainedBytesV1(), proxyEnabled, raw)
	if e != nil {
		return nil, e
	}
	fixed, queued, chunk, slotBytes := graph.fixed, graph.queued, graph.chunk, graph.slotBytes
	k, s, h := uint64(plan.MaxQueuePackets), uint64(c.StreamLimit), uint64(c.ProbeLimit)
	if fixed >= c.BufferBudget {
		return nil, ServiceResourceLimitV1
	}
	var state *processDuplexStateV1
	if installed == nil {
		state, e = newDuplexStateMinimumV3(result, plan.Digest, program, c.MaxRecordBytes, c.BufferBudget-fixed, client, max(272, uint32(plan.MTU)))
	} else {
		r := installed.recipe
		if !client || prepared == nil || graph != r.graph || prepared.size != r.endpoint || prepared.size.bounds.OwnedBytes > c.BufferBudget-fixed {
			return nil, ServiceResourceLimitV1
		}
		if proxyEnabled && (graph.proxyFixed > r.reservation.ProxyAttributedBytes || prepared.size.bounds.OwnedBytes > r.reservation.ProxyAttributedBytes-graph.proxyFixed) {
			return nil, ServiceResourceLimitV1
		}
		state, e = constructDuplexV3(result, plan.Digest, prepared.snapshot, prepared.context, prepared.config, prepared.codec, prepared.size, true)
	}
	if e != nil {
		return nil, e
	}
	var endpoint ProcessDuplexEndpointV3
	if kind == rawPacketPumpV2 {
		endpoint = &processClientRawEndpointV2{ProcessClientDuplexEndpointV3{state: state}}
	} else if client {
		endpoint = &ProcessClientDuplexEndpointV3{state: state}
	} else {
		endpoint = &ProcessRelayDuplexEndpointV3{state: state}
	}
	bounds := endpoint.BoundsV3()
	actual := int(bounds.MaxPayloadBytes)
	// Pre-reserved conservative maxima dominate actual endpoint reconciliation.
	ctx, cancel := context.WithCancel(context.Background())
	pump := &ServicePumpV1{cfg: c, endpoint: endpoint, admission: a, client: client, changed: make(chan struct{}), closed: make(chan struct{}), done: make(chan struct{}), ctx: ctx, cancel: cancel, deadline: minServiceTimeV1(c.AuthorityDeadline, now.Add(time.Duration(program.Limits.MaxSessionMillis)*time.Millisecond)), lastNow: now, activity: now, dialTimeout: plan.DialTimeout, idleTimeout: plan.IdleTimeout, client4: plan.ClientIPv4, dns4: plan.DNSIPv4, client6: plan.ClientIPv6, dns6: plan.DNSIPv6, mtu: int(plan.MTU), chunk: min(chunk, actual-8), slotBytes: slotBytes, rx: make([]byte, actual), queue: make([]serviceQueueSlotV1, k), streams: make([]serviceStreamSlotV1, s), probes: make([]serviceProbeSlotV1, h), outer: 1, bounds: ServicePumpBoundsV1{OwnedBytes: fixed + bounds.OwnedBytes, QueuedBytes: queued}}
	pump.kind = kind
	if kind == mixedPacketPumpV1 {
		pump.codec, _ = NewServiceRecordCodecV1(program.Messages[0].MinPayloadBytes, actual)
	}
	pump.protocolCount = copy(pump.protocols[:], plan.PayloadProtocols)
	if installed != nil {
		pump.production = installed.admission
		pump.idleTimeout = installed.recipe.limits.SessionIdle
		pump.proxyIdle = installed.recipe.limits.ProxyIdle
	}
	if raw {
		pump.packetScratch = make([]byte, plan.MTU)
	}
	transferredAdmission = true
	return pump, nil
}

func nilServiceOwnerV1(owner any) bool {
	if owner == nil {
		return true
	}
	v := reflect.ValueOf(owner)
	switch v.Kind() {
	case reflect.Pointer, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
func minServiceTimeV1(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}
func serviceTerminalV1(e error) error {
	if r, ok := e.(ServiceResultV1); ok && r > ServiceSuccessV1 && r <= ServiceInternalFailureV1 {
		return r
	}
	if errors.Is(e, context.Canceled) {
		return ServiceCancelledV1
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return ServiceTimeoutV1
	}
	for _, known := range []error{ErrServiceRecordV1, ErrAuthenticatedFrameState, ErrSecureChannel, ErrSessionMessageLimit, ErrLinkClosed, ErrProbeClockRegressionV1, ErrPacketPumpIO} {
		if e == known {
			return e
		}
	}
	return ServiceInternalFailureV1
}
func (p *ServicePumpV1) notifyLockedV1() { close(p.changed); p.changed = make(chan struct{}) }
func (p *ServicePumpV1) endUseV1() {
	p.mu.Lock()
	p.users--
	finish := p.terminal && p.wakeDone && p.users == 0 && !p.finalized
	if finish {
		p.finalized = true
	}
	p.mu.Unlock()
	if finish {
		p.finalizeV1()
	}
}
func (p *ServicePumpV1) finalizeV1() {
	p.endpoint.Abort()
	p.mu.Lock()
	clear(p.rx)
	clear(p.packetScratch)
	p.rx = nil
	p.packetScratch = nil
	for i := range p.queue {
		if p.production != nil {
			p.production.releaseV1(p.queue[i].flow)
		}
		clear(p.queue[i].data)
		clear(p.queue[i].cached)
		p.queue[i] = serviceQueueSlotV1{}
	}
	for i := range p.streams {
		clear(p.streams[i].scratch)
		clear(p.streams[i].request.Address)
		p.streams[i] = serviceStreamSlotV1{}
	}
	clear(p.probes)
	p.admission.Destroy()
	p.admission = nil
	p.delivery = serviceDeliveryV1{}
	p.bounds.OwnedBytes = 0
	p.bounds.QueuedBytes = 0
	p.used = 0
	p.cfg = ServicePumpConfigV1{}
	p.endpoint = nil
	p.queue = nil
	p.streams = nil
	p.probes = nil
	p.ctx = nil
	p.cancel = nil
	p.mu.Unlock()
	close(p.done)
}

// CancelWithReason is the trusted owner's terminal entry, not a wire revocation verifier.
// First publication wins; no later evidence can rewrite a retired generation.
func (p *ServicePumpV1) CancelWithReason(reason error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.terminal {
		p.mu.Unlock()
		return
	}
	p.terminal = true
	if p.production != nil {
		p.production.mu.Lock()
		p.production.closed = true
		p.production.active = false
		p.production.mu.Unlock()
	}
	p.reason = serviceTerminalV1(reason)
	close(p.closed)
	p.notifyLockedV1()
	carrier, packet := p.cfg.Carrier, p.cfg.PacketIO
	var connections [64]ServiceTCPConnV1
	var cancels [68]context.CancelFunc
	for i := range p.streams {
		connections[i] = p.streams[i].conn
		cancels[i] = p.streams[i].cancel
		p.streams[i].conn = nil
	}
	for i := range p.probes {
		cancels[64+i] = p.probes[i].cancel
	}
	p.mu.Unlock()
	p.cancel()
	for _, c := range cancels {
		if c != nil {
			c()
		}
	}
	if carrier != nil {
		carrier.Close()
	}
	if packet != nil {
		packet.Close()
	}
	for _, c := range connections {
		if c != nil {
			c.Close()
		}
	}
	p.mu.Lock()
	p.wakeDone = true
	finish := p.users == 0 && !p.finalized
	if finish {
		p.finalized = true
	}
	p.mu.Unlock()
	if finish {
		p.finalizeV1()
	}
}
func (p *ServicePumpV1) authorityV1() (time.Time, error) {
	p.clockMu.Lock()
	defer p.clockMu.Unlock()
	now := p.cfg.Now()
	if e := p.cfg.CheckAuthority(now); e != nil {
		return now, serviceTerminalV1(e)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.terminal {
		return now, p.reason
	}
	if now.Before(p.lastNow) {
		return now, ErrProbeClockRegressionV1
	}
	p.lastNow = now
	if p.production != nil {
		p.production.mu.Lock()
		if now.After(p.production.now) {
			p.production.now = now
		}
		p.production.mu.Unlock()
	}
	if !now.Before(p.deadline) {
		return now, ServiceAuthorityExpiredV1
	}
	return now, nil
}
func (p *ServicePumpV1) beginUseV1(requireReady bool) error {
	p.mu.Lock()
	if p.terminal {
		e := p.reason
		p.mu.Unlock()
		return e
	}
	if requireReady && (!p.ready || !p.running) {
		p.mu.Unlock()
		return ErrAuthenticatedFrameState
	}
	if e := p.reserveUsesLockedV1(1); e != nil {
		p.mu.Unlock()
		return e
	}
	p.mu.Unlock()
	if _, e := p.authorityV1(); e != nil {
		p.CancelWithReason(e)
		p.endUseV1()
		return e
	}
	return nil
}

// Every public use, pending worker and Run launch shares this hard ceiling.
// A worker keeps its reservation through deferred closes/cancellation and its
// final endUseV1, even if the logical service slot becomes reusable first.
func (p *ServicePumpV1) reserveUsesLockedV1(n int) error {
	if p.terminal {
		return p.reason
	}
	if n < 1 || p.users > 8+3*len(p.streams)+3*len(p.probes)-n {
		return ServiceResourceLimitV1
	}
	p.users += n
	return nil
}
func (p *ServicePumpV1) BindV1(ctx context.Context, exporter [32]byte) error {
	if e := p.beginUseV1(false); e != nil {
		return e
	}
	defer p.endUseV1()
	p.mu.Lock()
	if p.production != nil {
		p.production.mu.Lock()
		expected := p.production.exporter
		p.production.mu.Unlock()
		if expected != ([32]byte{}) && exporter != expected {
			p.mu.Unlock()
			return ErrProfileIncompatible
		}
	}
	if p.bindUsed || p.running || exporter == ([32]byte{}) {
		p.mu.Unlock()
		return ErrAuthenticatedFrameState
	}
	p.bindUsed = true
	p.binding = true
	p.mu.Unlock()
	now, e := p.authorityV1()
	if e != nil {
		p.CancelWithReason(e)
		return e
	}
	deadline := minServiceTimeV1(p.deadline, now.Add(p.dialTimeout))
	bindCtx, cancel := context.WithTimeout(ctx, deadline.Sub(now))
	defer cancel()
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(bindCtx, func() { p.CancelWithReason(bindCtx.Err()); close(callbackDone) })
	defer func() {
		if !stop() {
			<-callbackDone
		}
		p.mu.Lock()
		p.binding = false
		p.mu.Unlock()
	}()
	if e = bindCtx.Err(); e != nil {
		p.CancelWithReason(e)
		return serviceTerminalV1(e)
	}
	if p.client {
		endpoint := p.endpoint.(interface {
			ProfileBind([32]byte) ([]byte, error)
			AcceptEngineReady([]byte) error
		})
		var record []byte
		record, e = endpoint.ProfileBind(exporter)
		if e == nil {
			e = writeBoundedRecordV1(p.cfg.Carrier, record)
		}
		if e == nil {
			record, e = p.readRecordV1()
		}
		if e == nil {
			e = endpoint.AcceptEngineReady(record)
		}
	} else {
		var record []byte
		record, e = p.readRecordV1()
		if e == nil {
			record, e = p.endpoint.(*ProcessRelayDuplexEndpointV3).AcceptProfileBind(record, exporter)
		}
		if e == nil {
			e = writeBoundedRecordV1(p.cfg.Carrier, record)
		}
	}
	if e != nil {
		p.CancelWithReason(e)
		return serviceTerminalV1(e)
	}
	p.mu.Lock()
	if p.terminal {
		e = p.reason
	} else {
		p.ready = true
		p.activity = p.lastNow
	}
	p.mu.Unlock()
	return e
}
func (p *ServicePumpV1) Run(ctx context.Context) error {
	return p.runV1(ctx, nil)
}

// ServiceRunPublicationV1 is an opaque, one-shot commitment from an actual Run.
// The native owner performs all fallible preparation first, holds its own fence,
// commits, then performs only bounded infallible publication before unlocking.
type ServiceRunPublicationV1 struct {
	mu                                 sync.Mutex
	self                               *ServiceRunPublicationV1
	pump                               *ServicePumpV1
	active, called, committed, misused bool
}

func (v *ServiceRunPublicationV1) CommitV1() error {
	if v == nil || v.self != v {
		return ErrAuthenticatedFrameState
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.active || v.called {
		v.misused = true
		return ErrAuthenticatedFrameState
	}
	v.called = true
	v.pump.mu.Lock()
	defer v.pump.mu.Unlock()
	if v.pump.terminal {
		return v.pump.reason
	}
	v.committed = true
	return nil
}

func (v *ServiceRunPublicationV1) finishV1(result error) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.active = false
	v.pump = nil
	if result == nil && (!v.committed || v.misused) {
		return ErrAuthenticatedFrameState
	}
	return result
}

// RunWithPublicationV1 invokes trusted native preparation outside runtime locks.
// CommitV1 orders its final publication against actual runtime terminal selection.
func (p *ServicePumpV1) RunWithPublicationV1(ctx context.Context, ready func(*ServiceRunPublicationV1) error) error {
	if ready == nil {
		return ServiceInvalidRequestV1
	}
	return p.runV1(ctx, ready)
}

func (p *ServicePumpV1) runV1(ctx context.Context, ready func(*ServiceRunPublicationV1) error) error {
	if p == nil || ctx == nil {
		return ServiceInvalidRequestV1
	}
	p.mu.Lock()
	if p.terminal {
		e := p.reason
		p.mu.Unlock()
		return e
	}
	if p.running || p.binding || !p.ready {
		p.mu.Unlock()
		return ErrAuthenticatedFrameState
	}
	// The run coordinator and every worker register before the terminal fence.
	uses := 4
	if p.packetSourceEnabledV1() {
		uses++
	}
	if e := p.reserveUsesLockedV1(uses); e != nil {
		p.mu.Unlock()
		return e
	}
	p.running = true
	if p.production != nil {
		p.production.mu.Lock()
		if !p.production.closed {
			p.production.active = true
		}
		p.production.mu.Unlock()
	}
	p.mu.Unlock()
	if p.production != nil {
		port := p.cfg.PacketIO.(*PacketPortV1)
		port.mu.Lock()
		port.notifyV1()
		port.mu.Unlock()
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { p.CancelWithReason(ctx.Err()); close(callbackDone) })
	go p.workerV1(p.txV1)
	go p.workerV1(p.rxV1)
	go p.workerV1(p.superviseV1)
	if p.packetSourceEnabledV1() {
		go p.workerV1(p.packetSourceV1)
	}
	if ready != nil {
		if err := ctx.Err(); err != nil {
			p.CancelWithReason(err)
		} else if _, err := p.authorityV1(); err != nil {
			p.CancelWithReason(err)
		} else {
			publication := &ServiceRunPublicationV1{pump: p, active: true}
			publication.self = publication
			if err := publication.finishV1(ready(publication)); err != nil {
				p.CancelWithReason(err)
			}
		}
		ready = nil
	}
	<-p.closed
	if !stop() {
		<-callbackDone
	}
	p.endUseV1()
	<-p.done
	p.mu.Lock()
	e := p.reason
	p.mu.Unlock()
	return e
}
func (p *ServicePumpV1) packetSourceEnabledV1() bool {
	return !p.cfg.ExternalPacketIngress && (p.production == nil || p.production.raw)
}
func (p *ServicePumpV1) workerV1(f func() error) {
	defer p.endUseV1()
	if e := f(); e != nil {
		p.CancelWithReason(e)
	}
}
func (p *ServicePumpV1) superviseV1() error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.closed:
			return nil
		case <-ticker.C:
		}
		now, e := p.authorityV1()
		if e != nil {
			return e
		}
		p.mu.Lock()
		expired := !now.Before(p.activity.Add(p.idleTimeout)) || !p.ioDeadline.IsZero() && !now.Before(p.ioDeadline) || !p.delivery.deadline.IsZero() && !now.Before(p.delivery.deadline)
		var retired [64]ServiceTCPConnV1
		for i := range p.streams {
			s := &p.streams[i]
			proxyIdle := p.proxyIdle
			if p.production == nil && p.admission.policy.Services.Proxy != nil {
				proxyIdle = time.Duration(p.admission.policy.Services.Proxy.IdleTimeoutSeconds) * time.Second
			}
			if s.state == 2 && p.admission.policy.Services.Proxy != nil && !now.Before(s.idle.Add(proxyIdle)) {
				expired = true
			}
			retired[i] = p.retireRelayStreamLockedV1(i)
			if s.state == 3 && !s.worker && !s.writing && !s.receiving && !now.Before(s.tombstone) && !p.queuedIDLockedV1(s.id) {
				clear(s.scratch)
				clear(s.request.Address)
				*s = serviceStreamSlotV1{}
			}
		}
		for i := range p.probes {
			g := &p.probes[i]
			if !g.worker && !g.awaiting && (g.state == 2 && g.consumed || g.state == 3 && !now.Before(g.tombstone) && (g.handle == 0 || g.consumed)) {
				*g = serviceProbeSlotV1{}
			}
		}
		p.notifyLockedV1()
		p.mu.Unlock()
		for _, c := range retired {
			if c != nil {
				c.Close()
			}
		}
		if expired {
			return ServiceTimeoutV1
		}
	}
}
func (p *ServicePumpV1) Close() error          { p.CancelWithReason(ServiceCancelledV1); return nil }
func (p *ServicePumpV1) Done() <-chan struct{} { return p.done }
func (p *ServicePumpV1) BoundsV1() ServicePumpBoundsV1 {
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.bounds
	b.QueueUsed = uint32(p.used)
	for i := range p.streams {
		if p.streams[i].state != 0 {
			b.ActiveStreams++
		}
	}
	for i := range p.probes {
		if p.probes[i].state != 0 {
			b.ActiveProbes++
		}
	}
	return b
}
