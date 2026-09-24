// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"context"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/transport/tlstcp"
	"reflect"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type ProductionClientModeV1 uint8

const (
	ProductionTUNV1       ProductionClientModeV1 = 1
	ProductionTUNProxyV1  ProductionClientModeV1 = 2
	ProductionProxyOnlyV1 ProductionClientModeV1 = 3
)

type ProductionClientNarrowingV1 struct {
	Mode                                     ProductionClientModeV1
	SessionIdle, FlowIdle, ProxyIdle         time.Duration
	TCPFlows, UDPFlows                       uint16
	StreamLimit, ProbeLimit                  uint8
	StreamQueueBytes                         uint32
	AggregateCeilingBytes, ProxyCeilingBytes uint64
}
type ProductionClientAvailableV1 struct{ AggregateBytes, ProxyBytes uint64 }
type ProductionClientAuthorityV1 struct {
	AuthorityDeadline time.Time
	Now               func() time.Time
	CheckAuthority    func(time.Time) error
	ProbeScope        AuthenticatedProbeScopeV1
	ProbeRates        *ProbeRateRegistryV1
}
type ProductionClientReservationV1 struct {
	OwnedBytes, ProxyAttributedBytes, QueuedBytes     uint64
	DormantOwnedBytes, FlowOwnedBytes                 uint64
	MaxRecordBytes, MaxPayloadBytes, StreamChunkBytes uint32
}

// A recipe is an opaque single-use calculation/ownership object, not a profile
// trust receipt. Public numerical views are never accepted back as authority.
type ProductionClientRecipeV1 struct {
	mu                      sync.Mutex
	self                    *ProductionClientRecipeV1
	state                   uint8 // 1 prepared, 2 transferred, 3 closed
	kind                    packetPumpKindV1
	plan                    sessionplan.PlanV2
	program                 liveprogram.ProgramV1
	limits                  ProductionClientNarrowingV1
	reservation             ProductionClientReservationV1
	generation              uint64
	preparedAt              time.Time
	config                  StrictSessionConfigV1
	cryptoBytes, extraBytes uint64
	endpoint                duplexSizeV3
	graph                   servicePumpSizeV1
}
type ProductionClientInstallationV1 struct {
	mu                sync.Mutex
	self              *ProductionClientInstallationV1
	recipe            *ProductionClientRecipeV1
	port              *PacketPortV1
	admission         *productionPacketAdmissionV1
	pump              *ServicePumpV1
	closing, attached bool
	done, attachDone  chan struct{}
}

type servicePumpSizeV1 struct {
	fixed, proxyFixed, queued uint64
	maximum, chunk, slotBytes int
	scratch                   uint64
}

type productionDuplexPreparedV1 struct {
	snapshot auth.AuthenticatedContextSnapshotV1
	context  security.EnvelopeContextV1
	config   StrictSessionConfigV1
	codec    *framing.LiveDataCodecV3
	size     duplexSizeV3
}

// Attachment owns carrier cleanup from entry. Until TakeChannelSecretV1 the
// caller still owns result; every refusal makes the installation single-use.
func NewProductionClientServicePumpV1(ctx context.Context, result *auth.ProcessHandshakeResultV1, i *ProductionClientInstallationV1, carrier *tlstcp.Conn, authority ProductionClientAuthorityV1, preparation ProductionClientAttachmentPreparationV1) (pump *ServicePumpV1, err error) {
	return newProductionClientPumpV1(ctx, result, i, carrier, authority, preparation, mixedPacketPumpV1)
}

func newProductionClientPumpV1(ctx context.Context, result *auth.ProcessHandshakeResultV1, i *ProductionClientInstallationV1, carrier *tlstcp.Conn, authority ProductionClientAuthorityV1, preparation ProductionClientAttachmentPreparationV1, kind packetPumpKindV1) (pump *ServicePumpV1, err error) {
	entered := false
	defer func() {
		if err != nil && carrier != nil {
			carrier.Close()
		}
		if entered {
			close(i.attachDone)
			if err != nil {
				i.Close()
			}
		}
	}()
	if i == nil || i.self != i {
		return nil, ServiceInvalidRequestV1
	}
	i.mu.Lock()
	if i.closing || i.attached {
		i.mu.Unlock()
		return nil, ServiceInvalidRequestV1
	}
	i.attached = true
	i.attachDone = make(chan struct{})
	entered = true
	r := i.recipe
	i.mu.Unlock()
	if r.kind != kind {
		return nil, ServiceNotAdmittedV1
	}
	if kind == rawPacketPumpV2 && (authority.ProbeScope != (AuthenticatedProbeScopeV1{}) || authority.ProbeRates != nil) {
		return nil, ServiceInvalidRequestV1
	}
	if ctx == nil || carrier == nil || authority.Now == nil || authority.CheckAuthority == nil {
		return nil, ServiceInvalidRequestV1
	}
	if e := ctx.Err(); e != nil {
		return nil, serviceTerminalV1(e)
	}
	now := authority.Now()
	if now.IsZero() || !authority.AuthorityDeadline.After(now) {
		return nil, ServiceAuthorityExpiredV1
	}
	if e := authority.CheckAuthority(now); e != nil {
		return nil, serviceTerminalV1(e)
	}
	minimum, prepErr := ServicePreparationBoundsForPlanV1(r.plan, r.limits.Mode != ProductionTUNV1)
	if prepErr != nil || preparation.OwnedBytes < minimum.OwnedBytes || preparation.ProxyAttributedBytes < minimum.ProxyAttributedBytes {
		return nil, ServiceResourceLimitV1
	}
	if sessionplan.ValidateV2At(r.plan, now) != nil {
		return nil, ServiceNotAdmittedV1
	}
	if carrier.ValidatePlanDigestV1(r.plan.Digest) != nil {
		return nil, ErrProfileIncompatible
	}
	if r.limits.ProbeLimit != 0 && (!authority.ProbeScope.valid || authority.ProbeRates == nil) {
		return nil, ServiceInvalidRequestV1
	}
	snapshot, e := result.ProjectedContextSnapshotV3(r.program, "tls13-tcp", auth.ProjectedContextValidationBytesV3)
	defer func() { snapshot = auth.AuthenticatedContextSnapshotV1{} }()
	if e != nil {
		return nil, ErrProfileIncompatible
	}
	envelope, config, e := prepareProcessRecordContextV1(snapshot, true)
	defer func() { envelope = security.EnvelopeContextV1{}; config = StrictSessionConfigV1{} }()
	if e != nil {
		return nil, e
	}
	if config != r.config {
		return nil, ErrProfileIncompatible
	}
	cryptoBytes, e := security.EnvelopeOwnedBytesV3(envelope)
	if e != nil {
		return nil, e
	}
	if cryptoBytes != r.cryptoBytes {
		return nil, ServiceResourceLimitV1
	}
	codec, e := framing.NewLiveDataCodecV3(r.program)
	defer func() { codec = nil }()
	if e != nil {
		return nil, ErrProfileIncompatible
	}
	size, e := sizeDuplexV3(r.program, codec, envelope.MaxEnvelopeBytes, cryptoBytes, r.reservation.MaxRecordBytes, max(272, uint32(r.plan.MTU)), r.endpoint.bounds.OwnedBytes)
	if e != nil {
		return nil, e
	}
	if size != r.endpoint {
		return nil, ServiceResourceLimitV1
	}
	stream, e := carrier.SelectRecordStreamV3(ctx, r.limits.SessionIdle)
	if e != nil {
		return nil, ServiceInvalidRequestV1
	}
	bounds := stream.BoundsV3()
	if bounds.MaxRecordBytes != r.reservation.MaxRecordBytes || bounds.OwnedBytes != tlstcp.RecordStreamOwnedBytesV3() || bounds.QueuedPayloadBytes != 0 {
		return nil, ServiceResourceLimitV1
	}
	exporter, e := carrier.CarrierBinding()
	if e != nil {
		return nil, ErrProfileIncompatible
	}
	i.mu.Lock()
	closing := i.closing
	i.mu.Unlock()
	if closing {
		return nil, ServiceCancelledV1
	}
	if e = ctx.Err(); e != nil {
		return nil, serviceTerminalV1(e)
	}
	i.admission.mu.Lock()
	i.admission.exporter = exporter
	i.admission.mu.Unlock()
	c := ServicePumpConfigV1{PacketIO: i.port, Carrier: stream, StreamLimit: r.limits.StreamLimit, ProbeLimit: r.limits.ProbeLimit, StreamQueueBytes: r.limits.StreamQueueBytes, BufferBudget: r.reservation.OwnedBytes, MaxRecordBytes: r.reservation.MaxRecordBytes, Generation: r.generation, AuthorityDeadline: authority.AuthorityDeadline, Now: authority.Now, CheckAuthority: authority.CheckAuthority, ProbeScope: authority.ProbeScope, ProbeRates: authority.ProbeRates, CarrierOwnedBytes: bounds.OwnedBytes}
	prepared := productionDuplexPreparedV1{snapshot: snapshot, context: envelope, config: config, codec: codec, size: size}
	defer func() { prepared = productionDuplexPreparedV1{} }()
	p, e := newPacketPumpPreparedV1(result, r.plan, c, true, i, &prepared, kind)
	if e != nil {
		return nil, e
	}
	i.mu.Lock()
	if i.closing || ctx.Err() != nil {
		i.mu.Unlock()
		p.Close()
		<-p.Done()
		return nil, ServiceCancelledV1
	}
	if p.bounds.OwnedBytes != r.reservation.OwnedBytes || p.bounds.QueuedBytes != r.reservation.QueuedBytes || len(p.streams) != int(r.limits.StreamLimit) || len(p.probes) != int(r.limits.ProbeLimit) || p.chunk != int(r.reservation.StreamChunkBytes) {
		i.mu.Unlock()
		p.Close()
		<-p.Done()
		return nil, ServiceResourceLimitV1
	}
	i.pump = p
	i.mu.Unlock()
	return p, nil
}

// This is the constructor's one capacity graph, with separate attribution of
// shared resources to the subordinate proxy ceiling, never a second allowance.
func sizeServicePumpV1(plan sessionplan.PlanV2, program liveprogram.ProgramV1, c ServicePumpConfigV1, packetOwned, packetQueued, extra, flowBytes, retainedAdmission uint64, proxy, raw bool) (servicePumpSizeV1, error) {
	if len(program.Messages) == 0 {
		return servicePumpSizeV1{}, ServiceNotAdmittedV1
	}
	p := min(65535, program.Messages[0].MaxPayloadBytes, program.Limits.MaxPayloadBytes)
	chunk := 0
	if proxy {
		chunk = min(16384, p-8, int(c.StreamQueueBytes))
	}
	if p < 272 || chunk < 0 {
		return servicePumpSizeV1{}, ServiceResourceLimitV1
	}
	slot := max(int(plan.MTU), 272, chunk+8)
	k, s, h := uint64(plan.MaxQueuePackets), uint64(c.StreamLimit), uint64(c.ProbeLimit)
	rawScratch := uint64(0)
	if raw {
		rawScratch = uint64(plan.MTU)
	}
	scratch := rawScratch + s*uint64(chunk+8)
	queued := 2*uint64(p) + packetQueued + scratch + k*uint64(slot)
	fixed := retainedAdmission + uint64(unsafe.Sizeof(ServicePumpV1{})) + k*uint64(unsafe.Sizeof(serviceQueueSlotV1{})) + s*uint64(unsafe.Sizeof(serviceStreamSlotV1{})) + h*uint64(unsafe.Sizeof(serviceProbeSlotV1{})) + (8+3*s+3*h)*serviceWorkerReserveV1 + uint64(p) + packetOwned + scratch + k*uint64(slot)
	for _, n := range []uint64{c.CarrierOwnedBytes, (s + h) * c.NetworkOperationBytes, extra} {
		if n > ^uint64(0)-fixed {
			return servicePumpSizeV1{}, ServiceResourceLimitV1
		}
		fixed += n
	}
	if queued > 16<<20 {
		return servicePumpSizeV1{}, ServiceResourceLimitV1
	}
	proxyFixed := uint64(0)
	if proxy {
		disjoint := packetOwned + rawScratch + flowBytes + h*(uint64(unsafe.Sizeof(serviceProbeSlotV1{}))+3*serviceWorkerReserveV1+c.NetworkOperationBytes)
		if disjoint > fixed {
			return servicePumpSizeV1{}, ServiceResourceLimitV1
		}
		proxyFixed = fixed - disjoint
	}
	return servicePumpSizeV1{fixed: fixed, proxyFixed: proxyFixed, queued: queued, maximum: p, chunk: chunk, slotBytes: slot, scratch: scratch}, nil
}

func validateProductionNarrowingV1(plan sessionplan.PlanV2, policy runtimepolicy.PolicyV2, n ProductionClientNarrowingV1, a ProductionClientAvailableV1) error {
	return validateProductionPacketNarrowingV1(plan, policy, n, a, mixedPacketPumpV1)
}

func validateProductionPacketNarrowingV1(plan sessionplan.PlanV2, policy runtimepolicy.PolicyV2, n ProductionClientNarrowingV1, a ProductionClientAvailableV1, kind packetPumpKindV1) error {
	if n.Mode < ProductionTUNV1 || n.Mode > ProductionProxyOnlyV1 || n.SessionIdle <= 0 || n.SessionIdle > plan.IdleTimeout || n.SessionIdle > time.Hour || n.AggregateCeilingBytes == 0 || n.AggregateCeilingBytes > 128<<20 || a.AggregateBytes == 0 || a.AggregateBytes > n.AggregateCeilingBytes {
		return ServiceInvalidRequestV1
	}
	if n.Mode == ProductionProxyOnlyV1 {
		if n.TCPFlows != 0 || n.UDPFlows != 0 || n.FlowIdle != 0 {
			return ServiceInvalidRequestV1
		}
	} else if n.TCPFlows < 16 || n.TCPFlows > 4096 || n.UDPFlows > 2048 || n.FlowIdle <= 0 || n.FlowIdle > n.SessionIdle {
		return ServiceInvalidRequestV1
	}
	if !kind.admitsV1(policy) {
		return ServiceNotAdmittedV1
	}
	if kind == rawPacketPumpV2 {
		if n.Mode != ProductionTUNV1 || n.StreamLimit != 0 || n.ProbeLimit != 0 || n.StreamQueueBytes != 0 || n.ProxyIdle != 0 || n.ProxyCeilingBytes != 0 || a.ProxyBytes != 0 {
			return ServiceInvalidRequestV1
		}
		return nil
	}
	if n.Mode == ProductionTUNV1 {
		if n.StreamLimit != 0 || n.StreamQueueBytes != 0 || n.ProxyIdle != 0 || n.ProxyCeilingBytes != 0 || a.ProxyBytes != 0 {
			return ServiceInvalidRequestV1
		}
	} else {
		p := policy.Services.Proxy
		if p == nil {
			return ServiceNotAdmittedV1
		}
		if n.StreamLimit == 0 || n.StreamLimit > 64 || n.StreamLimit > p.MaxConcurrentStreams || n.StreamQueueBytes == 0 || n.StreamQueueBytes > 65536 || n.StreamQueueBytes > p.MaxQueuedBytesPerDirection || n.ProxyIdle <= 0 || n.ProxyIdle > time.Duration(p.IdleTimeoutSeconds)*time.Second || n.ProxyIdle > time.Hour {
			return ServiceInvalidRequestV1
		}
		if n.ProxyCeilingBytes < 16<<20 || n.ProxyCeilingBytes > uint64(p.MaxBufferBytes) || n.ProxyCeilingBytes > n.AggregateCeilingBytes || a.ProxyBytes == 0 || a.ProxyBytes > n.ProxyCeilingBytes {
			return ServiceResourceLimitV1
		}
	}
	h := uint8(0)
	if p := policy.Services.Probes; p != nil {
		for _, t := range p.Targets {
			for _, m := range t.Modes {
				if m == uint8(ProbeActiveRelayV1) {
					h = min(4, p.MaxConcurrentOperations)
				}
			}
		}
	}
	if n.ProbeLimit != h {
		return ServiceInvalidRequestV1
	}
	return nil
}

// Count actual detached dynamic backing, not occupancy. Struct/array storage
// belongs to its containing holder and is counted there. Types are fixed local
// Plan/program/config values, never arbitrary caller object graphs.
func productionBackingBytesV1(v reflect.Value) uint64 {
	var n uint64
	switch v.Kind() {
	case reflect.String:
		n = uint64(v.Len())
	case reflect.Pointer:
		if !v.IsNil() {
			n = uint64(v.Type().Elem().Size()) + productionBackingBytesV1(v.Elem())
		}
	case reflect.Slice:
		n = uint64(v.Cap()) * uint64(v.Type().Elem().Size())
		for i := 0; i < v.Len(); i++ {
			n += productionBackingBytesV1(v.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			n += productionBackingBytesV1(v.Field(i))
		}
	}
	return n
}

func PrepareProductionClientServiceV1(plan sessionplan.PlanV2, n ProductionClientNarrowingV1, a ProductionClientAvailableV1, now time.Time, generation uint64) (*ProductionClientRecipeV1, error) {
	return prepareProductionClientV1(plan, n, a, now, generation, mixedPacketPumpV1)
}

func prepareProductionClientV1(plan sessionplan.PlanV2, n ProductionClientNarrowingV1, a ProductionClientAvailableV1, now time.Time, generation uint64, kind packetPumpKindV1) (*ProductionClientRecipeV1, error) {
	if generation == 0 || now.IsZero() {
		return nil, ServiceInvalidRequestV1
	}
	// Reserve before the first Plan validation/clone. The containing ledger has
	// already charged its own borrowed projection separately from this residual.
	facts, ok := plan.ConstructionFactsV2()
	if !ok {
		return nil, ServiceResourceLimitV1
	}
	calculation, ok := sessionplan.AdmittedCalculationBoundsV2(facts.ProfileBytes)
	if !ok {
		return nil, ServiceResourceLimitV1
	}
	workspace := max(calculation.SuffixBytes, calculation.DecoderBytes+calculation.PolicyBytes+calculation.ProgramBytes+calculation.PlanBytes+calculation.SelectionBytes)
	if kind == mixedPacketPumpV1 {
		workspace, ok = serviceAddBytesV1(workspace, serviceAdmissionMaximumBytesV1())
	}
	if !ok || a.AggregateBytes < workspace || n.Mode != ProductionTUNV1 && (workspace > a.ProxyBytes || workspace > n.ProxyCeilingBytes || workspace > uint64(facts.ProxyBufferBytes)) {
		return nil, ServiceResourceLimitV1
	}
	if sessionplan.ValidateV2At(plan, now) != nil {
		return nil, ServiceNotAdmittedV1
	}
	policy, e := plan.RuntimePolicyAt(now)
	defer policy.Destroy()
	if e != nil || !kind.admitsV1(policy) {
		return nil, ServiceNotAdmittedV1
	}
	if e = validateProductionPacketNarrowingV1(plan, policy, n, a, kind); e != nil {
		return nil, e
	}
	program, e := liveprogram.DecodeV1(policy.LiveProgram)
	transferredProgram := false
	defer func() {
		if !transferredProgram {
			destroyProductionRecipeProgramV1(&program)
		}
	}()
	if e != nil {
		return nil, ServiceNotAdmittedV1
	}
	if productionBackingBytesV1(reflect.ValueOf(policy)) > calculation.PolicyBytes || productionBackingBytesV1(reflect.ValueOf(program)) > calculation.ProgramBytes {
		return nil, ServiceResourceLimitV1
	}
	retainedAdmission := uint64(0)
	if kind == mixedPacketPumpV1 {
		admission, err := NewServiceAdmissionV1(policy, now)
		if err != nil {
			return nil, err
		}
		retainedAdmission = admission.retainedBytesV1()
		admission.Destroy()
	}
	policy.Destroy()
	resources, e := auth.ProjectProcessResourcesV3(program, "tls13-tcp", auth.ProjectedContextValidationBytesV3)
	if e != nil {
		return nil, ErrProfileIncompatible
	}
	config, e := strictConfigFromSourcesV1(resources.Policy, resources.ConfigSource, resources.Limits)
	if e != nil {
		return nil, e
	}
	if _, e = strictTrafficSuiteV1(config.SelectedSuite); e != nil {
		return nil, e
	}
	cryptoBytes, e := security.EnvelopeStorageOwnedBytesV3(resources.Policy)
	if e != nil {
		return nil, e
	}
	codec, e := framing.NewLiveDataCodecV3(program)
	if e != nil {
		return nil, ErrProfileIncompatible
	}
	recordCap := uint32(program.Limits.MaxFrameBytes)
	endpoint, e := sizeDuplexV3(program, codec, config.MaxEnvelopeBytes, cryptoBytes, recordCap, max(272, uint32(plan.MTU)), 128<<20)
	if e != nil {
		return nil, e
	}
	codec = nil // no retained second framing codec across post-auth attachment
	flowBytes := uint64(0)
	if n.Mode != ProductionProxyOnlyV1 {
		flowBytes, _, e = productionFlowStorageV1(n.TCPFlows, n.UDPFlows)
		if e != nil {
			return nil, e
		}
	}
	ownedPlan := plan.Clone()
	transferredPlan := false
	defer func() {
		if !transferredPlan {
			ownedPlan.Destroy()
		}
	}()
	// Clone detaches mutable backing; detach the fixed public text fields too.
	v := reflect.ValueOf(&ownedPlan).Elem()
	for j := 0; j < v.NumField(); j++ {
		f := v.Field(j)
		if f.Kind() == reflect.String && f.CanSet() {
			f.SetString(strings.Clone(f.String()))
		}
	}
	if productionBackingBytesV1(reflect.ValueOf(ownedPlan)) > calculation.PlanBytes {
		return nil, ServiceResourceLimitV1
	}
	extra := uint64(unsafe.Sizeof(ProductionClientRecipeV1{})) + uint64(unsafe.Sizeof(ProductionClientInstallationV1{})) + uint64(unsafe.Sizeof(productionPacketAdmissionV1{})) + uint64(unsafe.Sizeof(productionFlowRefV1{})) + uint64(unsafe.Sizeof(productionReturnReceiptV1{})) + 2*serviceWorkerReserveV1 + flowBytes + productionBackingBytesV1(reflect.ValueOf(ownedPlan)) + productionBackingBytesV1(reflect.ValueOf(program)) + productionBackingBytesV1(reflect.ValueOf(config))
	packetQueued := 2 * uint64(plan.MTU)
	if kind == rawPacketPumpV2 {
		extra += uint64(unsafe.Sizeof(RawPacketPumpV2{}))
	}
	packetOwned := packetQueued + uint64(unsafe.Sizeof(PacketPortV1{})) + serviceWorkerReserveV1
	c := ServicePumpConfigV1{StreamLimit: n.StreamLimit, ProbeLimit: n.ProbeLimit, StreamQueueBytes: n.StreamQueueBytes, CarrierOwnedBytes: tlstcp.RecordStreamOwnedBytesV3()}
	graph, e := sizeServicePumpV1(plan, program, c, packetOwned, packetQueued, extra, flowBytes, retainedAdmission, n.Mode != ProductionTUNV1, n.Mode != ProductionProxyOnlyV1)
	if e != nil {
		ownedPlan.Destroy()
		return nil, e
	}
	owned := graph.fixed + endpoint.bounds.OwnedBytes
	proxy := uint64(0)
	if n.Mode != ProductionTUNV1 {
		proxy = graph.proxyFixed + endpoint.bounds.OwnedBytes
	}
	if owned > a.AggregateBytes || proxy > a.ProxyBytes {
		ownedPlan.Destroy()
		return nil, ServiceResourceLimitV1
	}
	r := &ProductionClientRecipeV1{state: 1, plan: ownedPlan, program: program, limits: n, generation: generation, preparedAt: now, config: config, cryptoBytes: cryptoBytes, extraBytes: extra, endpoint: endpoint, graph: graph, reservation: ProductionClientReservationV1{OwnedBytes: owned, ProxyAttributedBytes: proxy, QueuedBytes: graph.queued, DormantOwnedBytes: packetOwned + flowBytes + uint64(unsafe.Sizeof(productionPacketAdmissionV1{})), FlowOwnedBytes: flowBytes, MaxRecordBytes: recordCap, MaxPayloadBytes: endpoint.bounds.MaxPayloadBytes, StreamChunkBytes: uint32(min(graph.chunk, int(endpoint.bounds.MaxPayloadBytes)-8))}}
	r.self = r
	r.kind = kind
	transferredProgram = true
	transferredPlan = true
	return r, nil
}

func destroyProductionRecipeProgramV1(program *liveprogram.ProgramV1) {
	clear(program.Messages)
	clear(program.Frame.HeaderOrder)
	clear(program.Frame.Compiled.DataTypeTag)
	clear(program.Frame.Compiled.PaddingTypeTag)
	clear(program.Security.ClientMandatoryCapabilities)
	clear(program.Security.RelayMandatoryCapabilities)
	clear(program.Security.SelectedCapabilities)
	*program = liveprogram.ProgramV1{}
}

func (r *ProductionClientRecipeV1) ReservationV1() (ProductionClientReservationV1, error) {
	if r == nil || r.self != r {
		return ProductionClientReservationV1{}, ServiceInvalidRequestV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != 1 {
		return ProductionClientReservationV1{}, ServiceInvalidRequestV1
	}
	return r.reservation, nil
}
func (r *ProductionClientRecipeV1) InstallV1() (*ProductionClientInstallationV1, error) {
	if r == nil || r.self != r {
		return nil, ServiceInvalidRequestV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != 1 {
		return nil, ServiceInvalidRequestV1
	}
	r.state = 3
	port, e := NewPacketPortV1(int(r.plan.MTU))
	if e != nil {
		r.plan.Destroy()
		destroyProductionRecipeProgramV1(&r.program)
		return nil, e
	}
	n := r.limits
	a := &productionPacketAdmissionV1{generation: r.generation, raw: n.Mode != ProductionProxyOnlyV1, now: r.preparedAt, mtu: int(r.plan.MTU), client4: r.plan.ClientIPv4, dns4: r.plan.DNSIPv4, client6: r.plan.ClientIPv6, dns6: r.plan.DNSIPv6}
	a.protocolCount = copy(a.protocols[:], r.plan.PayloadProtocols)
	if a.raw {
		a.flow, e = newProductionFlowTableV1(n.TCPFlows, n.UDPFlows, n.FlowIdle)
		if e != nil {
			port.Close()
			r.plan.Destroy()
			destroyProductionRecipeProgramV1(&r.program)
			return nil, e
		}
	}
	port.production = a
	i := &ProductionClientInstallationV1{recipe: r, port: port, admission: a, done: make(chan struct{})}
	i.self = i
	r.state = 2
	return i, nil
}
func (r *ProductionClientRecipeV1) Close() error {
	if r == nil || r.self != r {
		return ServiceInvalidRequestV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == 1 {
		r.state = 3
		r.plan.Destroy()
		destroyProductionRecipeProgramV1(&r.program)
		r.config = StrictSessionConfigV1{}
	}
	return nil
}
func (i *ProductionClientInstallationV1) ReservationV1() (ProductionClientReservationV1, error) {
	if i == nil || i.self != i {
		return ProductionClientReservationV1{}, ServiceInvalidRequestV1
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closing {
		return ProductionClientReservationV1{}, ServiceInvalidRequestV1
	}
	return i.recipe.reservation, nil
}
func (i *ProductionClientInstallationV1) InstalledLimitsV1() (ProductionClientNarrowingV1, error) {
	if i == nil || i.self != i {
		return ProductionClientNarrowingV1{}, ServiceInvalidRequestV1
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closing {
		return ProductionClientNarrowingV1{}, ServiceInvalidRequestV1
	}
	n := i.recipe.limits
	a := i.admission
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.generation != i.recipe.generation || a.raw != (n.Mode != ProductionProxyOnlyV1) || a.mtu != int(i.recipe.plan.MTU) {
		return ProductionClientNarrowingV1{}, ServiceInvalidRequestV1
	}
	if a.raw {
		if a.flow == nil {
			return ProductionClientNarrowingV1{}, ServiceInvalidRequestV1
		}
		a.flow.mu.Lock()
		valid := !a.flow.destroyed && a.flow.tcpCapacity == n.TCPFlows && len(a.flow.entries) == int(n.TCPFlows)+int(n.UDPFlows) && a.flow.idle == n.FlowIdle
		a.flow.mu.Unlock()
		if !valid {
			return ProductionClientNarrowingV1{}, ServiceInvalidRequestV1
		}
	} else if a.flow != nil {
		return ProductionClientNarrowingV1{}, ServiceInvalidRequestV1
	}
	return n, nil
}
func (i *ProductionClientInstallationV1) PacketPortV1() (*PacketPortV1, error) {
	if i == nil || i.self != i {
		return nil, ServiceInvalidRequestV1
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closing {
		return nil, ServiceInvalidRequestV1
	}
	return i.port, nil
}
func (i *ProductionClientInstallationV1) Done() <-chan struct{} {
	if i == nil || i.self != i {
		return nil
	}
	return i.done
}
func (i *ProductionClientInstallationV1) Close() error {
	if i == nil || i.self != i {
		return ServiceInvalidRequestV1
	}
	i.mu.Lock()
	if i.closing {
		done := i.done
		i.mu.Unlock()
		<-done
		return nil
	}
	i.closing = true
	a, port, attach := i.admission, i.port, i.attachDone
	a.mu.Lock()
	a.closed = true
	a.active = false
	a.mu.Unlock()
	i.mu.Unlock()
	port.Close()
	if attach != nil {
		<-attach
	}
	i.mu.Lock()
	pump := i.pump
	i.mu.Unlock()
	if pump != nil {
		pump.Close()
		<-pump.Done()
	}
	port.joinV1()
	if a.flow != nil {
		a.flow.destroyV1()
	}
	a.mu.Lock()
	a.flow = nil
	a.client4 = [4]byte{}
	a.dns4 = [4]byte{}
	a.client6 = [16]byte{}
	a.dns6 = [16]byte{}
	a.protocols = [4]runtimepolicy.PayloadProtocolV2{}
	a.protocolCount = 0
	a.now = time.Time{}
	a.exporter = [32]byte{}
	a.mu.Unlock()
	i.mu.Lock()
	i.recipe.mu.Lock()
	i.recipe.plan.Destroy()
	destroyProductionRecipeProgramV1(&i.recipe.program)
	i.recipe.config = StrictSessionConfigV1{}
	i.recipe.state = 3
	i.recipe.mu.Unlock()
	i.pump = nil
	i.port = nil
	i.admission = nil
	i.mu.Unlock()
	close(i.done)
	return nil
}
