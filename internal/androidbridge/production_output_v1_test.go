// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
	runtimeengine "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"kurdistan/internal/transport/tlstcp"
	"math"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// Test-only, fixed backing. No observer method waits, reenters Go, or invokes a
// test hook. Tests move barriers to caller/platform seams outside owner locks.
type productionOutputTestV1 struct {
	mu              sync.Mutex
	registry        *HandleRegistry
	ended           [512]bool
	epoch           uint64
	handle          Handle
	lanes           [268]uint64
	laneEpochs      [268]uint64
	strictAttempt   bool
	bindAttempts    [268]uint16
	oneLane         bool
	events          [512]uint8
	count           int
	refuse          int32
	prepareRefuse   int32
	prepareCalls    int
	terminal        bool
	retiredAttempt  uint64
	expectedReceipt ProductionOutputReceiptKindV1
	receipts        [512]productionOutputReceiptTestV1
}
type productionOutputReceiptTestV1 struct {
	epoch                                uint64
	attempt                              uint64
	kind                                 ProductionOutputReceiptKindV1
	parent                               Handle
	child, delivery                      uint64
	prepared, claimed, retired, finished bool
	actual                               int32
	claimCount, finishCount, retireCount int
	claimRetired                         bool
	finishActual                         int32
}

func (o *productionOutputTestV1) ValidateInvocationV1(r *HandleRegistry, owner, call, epoch uint64) int32 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.registry == nil {
		o.registry = r
	}
	if r != o.registry || owner != 1 || call == 0 || call >= 512 || o.ended[call] {
		return 3
	}
	return 0
}

type productionOutputPlatformV1 struct {
	*productionSnapshotPlatformV1
	output              *productionOutputTestV1
	boundBeforeRegister bool
}

func (p *productionOutputPlatformV1) RegisterProductionCurrentV1(epoch uint64, e *ProductionCurrentExpectationV1, invalidate func() ErrorCode) (MaintenanceRevisionRegistrationV1, ErrorCode) {
	p.output.mu.Lock()
	p.boundBeforeRegister = p.output.epoch == epoch && p.output.handle != 0 && p.output.lanes[0] != 0
	p.output.mu.Unlock()
	return p.productionSnapshotPlatformV1.RegisterProductionCurrentV1(epoch, e, invalidate)
}
func (*productionOutputPlatformV1) RegisterProductionSocketV1(context.Context, *ProductionSocketExpectationV1) (ProductionSocketRegistrationV1, int32) {
	return nil, 3
}

func TestProductionOutputV1OpeningBindBeforeRegister(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	r := new(HandleRegistry)
	o := new(productionOutputTestV1)
	p := &productionOutputPlatformV1{productionSnapshotPlatformV1: &productionSnapshotPlatformV1{snapshot: f.current, stage: "register"}, output: o}
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	env := new(productionRealCurrentV1)
	parts := productionInputPartsV1(f.current)
	request := productionOpenFixtureV1(1, productionDefaultSettingsBytesV1(), parts[0], parts[1], parts[2], parts[3])
	inv, _ := NewProductionOutputInvocationV1(r, o, 1, 1, 0)
	config := ProductionSessionConfigV1{Environment: env, Platform: p, Factory: &productionReservationFixtureV1{}, ProbeRates: rates, Now: func() time.Time { return f.now }, MonotonicNow: time.Now, OutputMetadataBytes: uint64(unsafe.Sizeof(*o))}
	h, n, s := OpenProductionV1Scoped(r, request, make([]byte, 32768), config, inv)
	if h != 0 || n != 0 || s == 0 || !p.boundBeforeRegister || !o.terminal || inv.epoch != 0 {
		t.Fatalf("binding/invalidated open: %d %d %d bound=%v terminal=%v epoch=%d", h, n, s, p.boundBeforeRegister, o.terminal, inv.epoch)
	}
	config.OutputMetadataBytes = 0
	before := env.calls
	if _, _, s = OpenProductionV1Scoped(r, request, make([]byte, 32768), config, inv); s != 2 || env.calls != before {
		t.Fatal("metadata admitted work", s)
	}
	config.OutputMetadataBytes = 80 << 20
	if _, _, s = OpenProductionV1Scoped(r, request, make([]byte, 32768), config, inv); s != 5 || env.calls != before {
		t.Fatal("remaining budget admitted work", s)
	}
}
func (o *productionOutputTestV1) event(v uint8) {
	if o.count < len(o.events) {
		o.events[o.count] = v
		o.count++
	}
}
func (o *productionOutputTestV1) BindParentV1(call, epoch uint64) int32 {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.epoch = epoch
	o.event(1)
	return o.refuse
}
func (o *productionOutputTestV1) BindHandleV1(call, epoch uint64, h Handle) int32 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.epoch != epoch {
		return 3
	}
	o.handle = h
	o.event(2)
	return o.refuse
}
func (o *productionOutputTestV1) BindLaneV1(call, epoch uint64, lane uint16, attempt uint64) int32 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if epoch != o.epoch || int(lane) >= len(o.lanes) {
		return 3
	}
	o.bindAttempts[lane]++
	if o.oneLane {
		for _, bound := range o.lanes {
			if bound == call {
				return 18
			}
		}
	}
	if o.lanes[lane] != 0 {
		return 5
	}
	if o.refuse != 0 {
		return o.refuse
	}
	o.lanes[lane] = call
	o.laneEpochs[lane] = attempt
	o.event(3)
	return 0
}
func (o *productionOutputTestV1) PrepareV1(call, epoch, attempt, child, delivery uint64, deadline time.Time, terminal bool) int32 {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.event(4)
	o.prepareCalls++
	if o.prepareRefuse != 0 {
		return o.prepareRefuse
	}
	if o.strictAttempt {
		matched := false
		for lane, bound := range o.lanes {
			if bound == call && o.laneEpochs[lane] == attempt {
				matched = true
				break
			}
		}
		if !matched {
			return 3
		}
	}
	if !terminal && (o.terminal || attempt != 0 && attempt == o.retiredAttempt) {
		return 7
	}
	if o.refuse == 0 && o.expectedReceipt != 0 && call < 512 {
		o.receipts[call] = productionOutputReceiptTestV1{epoch: epoch, attempt: attempt, kind: o.expectedReceipt, parent: o.handle, child: child, delivery: delivery, prepared: true}
	}
	return o.refuse
}
func (o *productionOutputTestV1) ParentTerminalV1(epoch uint64, reason int32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.terminal = true
	o.event(5)
}
func (o *productionOutputTestV1) AttemptTerminalV1(epoch, attempt uint64, reason int32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.retiredAttempt = attempt
	o.event(6)
}
func (o *productionOutputTestV1) ClaimReceiptV1(call, epoch uint64, kind ProductionOutputReceiptKindV1, parent Handle, child, delivery uint64) (bool, int32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if call >= 512 {
		return false, 3
	}
	r := &o.receipts[call]
	if !r.prepared || r.claimed || r.finished || r.epoch != epoch || r.kind != kind || r.parent != parent || r.child != child || r.delivery != delivery {
		return false, 3
	}
	r.claimed = true
	r.claimCount++
	r.claimRetired = r.retired && r.actual == 0
	return r.retired && r.actual == 0, 0
}
func (o *productionOutputTestV1) FinishReceiptV1(call, epoch uint64, kind ProductionOutputReceiptKindV1, parent Handle, child, delivery uint64, actual int32) int32 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if call >= 512 || !o.receipts[call].claimed {
		return 3
	}
	r := &o.receipts[call]
	if r.epoch != epoch || r.kind != kind || r.parent != parent || r.child != child || r.delivery != delivery {
		return 3
	}
	r.finishCount++
	r.finishActual = actual
	r.claimed = false
	r.finished = true
	if r.actual == 0 {
		r.actual = actual
	}
	return r.actual
}
func (o *productionOutputTestV1) ResourceRetiredV1(epoch uint64, kind ProductionOutputReceiptKindV1, parent Handle, attempt, child, delivery uint64, actual int32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.event(7)
	for i := range o.receipts {
		r := &o.receipts[i]
		if r.prepared && r.epoch == epoch && r.attempt == attempt && r.kind == kind && r.parent == parent && r.child == child && r.delivery == delivery {
			r.retireCount++
			r.retired = actual == 0
			if r.actual == 0 {
				r.actual = actual
			}
		}
	}
}

func TestProductionOutputV1AdmissionBudget(t *testing.T) {
	r := new(HandleRegistry)
	o := new(productionOutputTestV1)
	for _, c := range []struct {
		r           *HandleRegistry
		o           ProductionOutputObserverV1
		owner, call uint64
	}{{nil, o, 1, 1}, {r, nil, 1, 1}, {r, o, 0, 1}, {r, o, 1, 0}} {
		if _, s := NewProductionOutputInvocationV1(c.r, c.o, c.owner, c.call, 0); s != 2 {
			t.Fatalf("invalid constructor=%d", s)
		}
	}
	inv, s := NewProductionOutputInvocationV1(r, o, 1, 1, 0)
	if s != 0 {
		t.Fatal(s)
	}
	for _, c := range []struct {
		inv        ProductionOutputInvocationV1
		bytes, cap uint64
		want       int32
	}{{inv, 0, 128 << 20, 2}, {inv, 128<<20 + 1, 128 << 20, 2}, {ProductionOutputInvocationV1{}, 1, 128 << 20, 2}, {inv, uint64(unsafe.Sizeof(*o)), 128 << 20, 0}} {
		if got := productionOutputOpeningV1(r, c.inv, c.bytes, c.cap); got != c.want {
			t.Fatalf("metadata=%d want=%d", got, c.want)
		}
	}
	if got := productionOutputOpeningV1(new(HandleRegistry), inv, 1, 128<<20); got != 2 {
		t.Fatal("registry mismatch", got)
	}
	later, _ := NewProductionOutputInvocationV1(r, o, 1, 2, 9)
	if got := productionOutputOpeningV1(r, later, 1, 128<<20); got != 2 {
		t.Fatal("opening epoch", got)
	}
}

func productionOutputParentFixtureV1(t *testing.T) (*productionParentV1, *productionOutputTestV1, ProductionOutputInvocationV1) {
	r := new(HandleRegistry)
	p := newTestProductionParentV1(t, r, time.Now().Add(time.Minute))
	o := new(productionOutputTestV1)
	p.output, p.outputOwner = o, 1
	o.epoch = p.ticket.epoch
	inv, _ := NewProductionOutputInvocationV1(r, o, 1, 2, p.ticket.epoch)
	t.Cleanup(func() { p.cancelV1(7); p.retireV1() })
	return p, o, inv
}
func TestProductionOutputV1OuterLaneSurvivesInnerReturn(t *testing.T) {
	p, o, inv := productionOutputParentFixtureV1(t)
	use, s := p.beginUseOutputV1(2, productionBudgetChargeV1{}, inv, false)
	if s != 0 {
		t.Fatal(s)
	}
	if s = p.finishUseV1(use); s != 0 {
		t.Fatal(s)
	}
	next, _ := NewProductionOutputInvocationV1(inv.registry, o, 1, 3, inv.epoch)
	if _, s = p.beginUseOutputV1(2, productionBudgetChargeV1{}, next, false); s != 5 {
		t.Fatal("outer lane released with inner", s)
	}
	for _, bad := range []ProductionOutputInvocationV1{{registry: inv.registry, observer: o, owner: 1, call: 4}, {registry: new(HandleRegistry), observer: o, owner: 1, call: 4, epoch: inv.epoch}, {registry: inv.registry, observer: o, owner: 2, call: 4, epoch: inv.epoch}, {registry: inv.registry, observer: o, owner: 1, call: 4, epoch: inv.epoch + 1}} {
		if _, s = p.beginUseOutputV1(3, productionBudgetChargeV1{}, bad, false); s != 3 {
			t.Fatal("bad scoped identity", s)
		}
	}
}
func TestProductionOutputV1TerminalControlDistinction(t *testing.T) {
	p, o, inv := productionOutputParentFixtureV1(t)
	o.strictAttempt = true
	if s := p.enqueueControlFixedV1(productionControlTransportConnectingV1, nil); s != 0 {
		t.Fatal(s)
	}
	o.prepareRefuse = 5
	beforePrepare := o.prepareCalls
	descriptor := p.controlDescriptors[p.controlHead]
	if n, s := p.nextControlScopedV1(context.Background(), make([]byte, 34), inv); n != 0 || s != 5 {
		t.Fatal("refused prepare", n, s)
	}
	if p.controlCount != 1 || p.controlDescriptors[p.controlHead] != descriptor || o.prepareCalls != beforePrepare+1 || o.lanes[1] != inv.call {
		t.Fatal("refusal consumed event")
	}
	o.prepareRefuse = 0
	o.lanes[1] = 0
	if s := p.enqueueControlFixedV1(productionControlStoppedV1, nil); s != 0 {
		t.Fatal(s)
	}
	out := make([]byte, 34)
	if n, s := p.nextControlScopedV1(context.Background(), out, inv); n != 32 || s != 0 || out[5] != 12 {
		t.Fatal("terminal drain", n, s, out[5])
	}
}

func TestProductionOutputV1ControlPollSpansAttemptBeforeExactBinding(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(fmt.Sprintf("terminal=%t", terminal), func(t *testing.T) {
			p, o, inv := productionOutputParentFixtureV1(t)
			o.strictAttempt = true
			use, s := p.beginControlPollScopedV1(inv)
			if s != 0 {
				t.Fatal("admit actual control use", s)
			}
			defer func() {
				if s := p.finishUseV1(use); s != 0 {
					t.Fatal("finish actual control use", s)
				}
			}()
			// A deterministic pause between the real poll admission and dequeue.
			// nextAttempt explicitly permits this still-live non-attempt-scoped use.
			if epoch, s := p.nextAttemptV1(); epoch != 2 || s != 0 {
				t.Fatal("advance with live poll", epoch, s)
			}
			if s := p.useCurrentV1(use); s != 0 {
				t.Fatal("live poll lost on transition", s)
			}
			kind := productionControlTransportConnectingV1
			if terminal {
				kind = productionControlStoppedV1
			}
			if s := p.enqueueControlFixedV1(kind, nil); s != 0 {
				t.Fatal(s)
			}
			out := bytes.Repeat([]byte{0xa5}, 32)
			p.mu.Lock()
			n, s := p.dequeueControlScopedLockedV1(out, inv, time.Now().Add(time.Second))
			p.mu.Unlock()
			if n != 32 || s != 0 {
				t.Fatal("descriptor epoch must bind instead of poll admission epoch", n, s)
			}
			if binary.BigEndian.Uint64(out[12:20]) != 2 || out[5] != byte(kind) || o.laneEpochs[1] != 2 {
				t.Fatal("wrong event or output-lane epoch")
			}
		})
	}
}

func TestProductionOutputV1ControlDefersLaneUntilSizedDescriptorAndPreservesRefusals(t *testing.T) {
	p, o, inv := productionOutputParentFixtureV1(t)
	o.strictAttempt = true
	use, s := p.beginControlPollScopedV1(inv)
	if s != 0 {
		t.Fatal(s)
	}
	defer p.finishUseV1(use)
	read := func(dst []byte) (int, int32) {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.dequeueControlScopedLockedV1(dst, inv, time.Now().Add(time.Second))
	}
	out := bytes.Repeat([]byte{0xa5}, 32)
	if n, s := read(out); n != 0 || s != 20 || o.lanes[1] != 0 || o.prepareCalls != 0 {
		t.Fatal("NO_EVENT bound or prepared an output", n, s, o.lanes[1])
	}
	if s := p.enqueueControlFixedV1(productionControlTransportConnectingV1, nil); s != 0 {
		t.Fatal(s)
	}
	descriptor, sequence := p.controlDescriptors[p.controlHead], p.nextControlSequence
	unchanged := func() {
		t.Helper()
		if !bytes.Equal(out, bytes.Repeat([]byte{0xa5}, 32)) || p.controlCount != 1 ||
			p.controlDescriptors[p.controlHead] != descriptor || p.nextControlSequence != sequence {
			t.Fatal("refusal consumed or copied event")
		}
	}
	if n, s := read(out[:31]); n != 0 || s != 4 || o.lanes[1] != 0 || o.prepareCalls != 0 {
		t.Fatal("short output bound", n, s)
	}
	unchanged()
	// The prior JNI output frame may still own this C lane after its Go use ended.
	if s := o.BindLaneV1(inv.call+1, inv.epoch, 1, p.attempt); s != 0 {
		t.Fatal(s)
	}
	if n, s := read(out); n != 0 || s != 5 || o.prepareCalls != 0 {
		t.Fatal("duplicate lane", n, s)
	}
	unchanged()
	o.lanes[1] = 0 // test observer's outer-frame End
	o.prepareRefuse = 5
	if n, s := read(out); n != 0 || s != 5 || o.lanes[1] != inv.call || o.prepareCalls != 1 {
		t.Fatal("Prepare refusal", n, s)
	}
	unchanged()
}

func TestProductionOutputV1LaterEpochRequired(t *testing.T) {
	r := new(HandleRegistry)
	o := new(productionOutputTestV1)
	inv, _ := NewProductionOutputInvocationV1(r, o, 1, 1, 0)
	h := Handle(1)
	checks := []int32{ConfirmProductionSocketV1Scoped(r, h, 1, 1, 0, 0, inv), SubmitProductionPacketV1Scoped(r, h, nil, inv), ConfirmProductionPacketV1Scoped(r, h, 1, 1, inv), RejectProductionPacketV1Scoped(r, h, 1, inv), ReconnectProductionV1Scoped(r, h, 1, inv), HandoverProductionV1Scoped(r, h, 0, 0, inv), CancelProductionV1Scoped(r, h, inv), CloseProductionV1Scoped(r, h, inv), SendProductionStreamV1Scoped(r, h, 1, nil, inv), ConfirmProductionStreamV1Scoped(r, h, 1, 1, 1, inv), RejectProductionStreamV1Scoped(r, h, 1, 1, inv), HalfCloseProductionStreamV1Scoped(r, h, 1, inv), CancelProductionStreamV1Scoped(r, h, 1, inv), CloseProductionStreamV1Scoped(r, h, 1, inv)}
	for _, s := range checks {
		if s != 3 {
			t.Fatal("epoch0", s)
		}
	}
	if _, s := NextProductionControlV1Scoped(r, h, nil, inv); s != 3 {
		t.Fatal(s)
	}
	if _, _, s := ReceiveProductionPacketV1Scoped(r, h, nil, inv); s != 3 {
		t.Fatal(s)
	}
	if _, s := OpenProductionStreamV1Scoped(r, h, nil, inv); s != 3 {
		t.Fatal(s)
	}
	if _, _, s := ReceiveProductionStreamV1Scoped(r, h, 1, nil, inv); s != 3 {
		t.Fatal(s)
	}
	if _, s := RunProductionProbeV1Scoped(r, h, make([]byte, 9), make([]byte, 21), inv); s != 3 {
		t.Fatal(s)
	}
}

func TestProductionOutputV1AttemptTerminalWins(t *testing.T) {
	p, _, inv := productionOutputParentFixtureV1(t)
	v := &productionSessionV1{parent: p, wake: make(chan struct{}, 1)}
	p.session = v
	p.admission = &productionAdmissionV1{parent: p}
	p.mu.Lock()
	s := p.outputPrepareLockedV1(inv, 1, 0, 0, p.deadline, false)
	p.mu.Unlock()
	if s != 0 {
		t.Fatal(s)
	}
	v.retireAttemptV1()
	p.mu.Lock()
	s = p.outputPrepareLockedV1(inv, 1, 0, 0, p.deadline, false)
	p.admission = nil
	p.mu.Unlock()
	if s != 7 {
		t.Fatal("retired attempt allowed late output", s)
	}
}
func TestProductionOutputV1AdmissionBeforeWork(t *testing.T) {
	p, o, inv := productionOutputParentFixtureV1(t)
	v := &productionSessionV1{parent: p}
	o.refuse = 5
	if _, _, s := v.beginIOOutputV1(2, 4096, inv, false); s != 5 {
		t.Fatal("lane refusal", s)
	}
	if p.activeUses != 0 {
		t.Fatal("refusal admitted native work")
	}
}
func productionOutputPumpFixtureV1(t *testing.T, offset ...*atomic.Int64) (*productionSessionV1, *productionOutputTestV1, ProductionOutputInvocationV1, net.Listener) {
	f, snapshot := productionOutputTLSCurrentFixtureV1(t, false, true)
	readNow := func() time.Time {
		if len(offset) != 0 {
			return f.now.Add(time.Duration(offset[0].Load()))
		}
		return f.now
	}
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	parentTicket, _ := reserveProductionSlotV1(&HandleRegistry{})
	p, _ := newProductionParentV1(parentTicket, 80<<20, time.Time{})
	opening, _ := p.beginUseV1(0, productionBudgetChargeV1{})
	settings := projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false))
	settings.tunnelMode = 2
	o, s := newProductionAdmissionV1(p, opening, f.current, settings, &productionRealCurrentV1{}, &productionSnapshotPlatformV1{snapshot: f.current}, readNow, time.Now, rates, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 80 << 20, MaxArtifactBytes: 1 << 20, MaxPublicationBytes: 1 << 20})
	p.finishUseV1(opening)
	if s != 0 {
		t.Fatal("admit", s, "current", p.admission.current != nil, "plan", len(p.admission.plan.Endpoints), "resources", p.admission.resources != nil)
	}
	t.Cleanup(func() { o.closeV1(context.Background()) })
	attemptUse, _ := p.beginUseV1(202, productionBudgetChargeV1{})
	a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, attemptUse)
	if s != 0 {
		t.Fatal(s)
	}
	b, s := a.BorrowV1()
	if s != 0 {
		t.Fatal(s)
	}
	t.Cleanup(func() { b.Close(); o.resources.destroyV1(); p.finishUseV1(attemptUse) })
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	relayReady := make(chan *runtimeengine.ServicePumpV1, 1)
	peer := make(chan error, 1)
	result, carrier := productionActualHandshakeV1(t, b, snapshot, func(rr *auth.ProcessHandshakeResultV1, plan sessionplan.PlanV2, program liveprogram.ProgramV1, c *tlstcp.Conn) error {
		go func() {
			defer rr.Close()
			stream, err := c.SelectRecordStreamV3(ctx, time.Minute)
			if err != nil {
				peer <- err
				return
			}
			admission, ok := snapshot.AdmissionByProfileV1(plan.ProfileContentID, plan.ProfileGeneration)
			if !ok {
				peer <- runtimeengine.ServiceNotAdmittedV1
				return
			}
			scope, err := runtimeengine.NewAuthenticatedProbeScopeV1(envelope.CanonicalProfileV1{ProviderID: admission.ProviderID, LineageID: admission.LineageID, ProfileID: admission.ProfileID})
			if err != nil {
				peer <- err
				return
			}
			port, _ := runtimeengine.NewPacketPortV1(int(plan.MTU))
			defer port.Close()
			rp, err := runtimeengine.NewRelayServicePumpV1(rr, plan, runtimeengine.ServicePumpConfigV1{PacketIO: port, Carrier: stream, CarrierOwnedBytes: 1 << 20, PacketOwnedBytes: 65536, PacketQueuedBytes: uint64(2 * plan.MTU), StreamLimit: 4, StreamQueueBytes: 32768, ProbeLimit: 1, BufferBudget: 64 << 20, MaxRecordBytes: uint32(program.Limits.MaxFrameBytes), Generation: 1, AuthorityDeadline: time.Unix(admission.ValidUntil, 0), Now: func() time.Time { return f.now }, CheckAuthority: func(at time.Time) error {
				if at.Unix() >= admission.ValidUntil {
					return runtimeengine.ServiceAuthorityExpiredV1
				}
				return nil
			}, ProbeScope: scope, ProbeRates: rates, RelayNetwork: productionStreamNetworkFixtureV1{listener.Addr().String()}, NetworkOperationBytes: 8192})
			if err != nil {
				peer <- err
				return
			}
			defer rp.Close()
			exporter, err := c.CarrierBinding()
			if err == nil {
				err = rp.BindV1(ctx, exporter)
			}
			if err != nil {
				peer <- err
				return
			}
			relayReady <- rp
			peer <- rp.Run(ctx)
		}()
		return nil
	})
	if _, s = b.RevalidateV1(ctx); s != 0 {
		t.Fatal(s)
	}
	pump, e := b.AttachServiceV1(ctx, result, carrier)
	if e != nil {
		t.Fatal(e)
	}
	exporter, e := carrier.CarrierBinding()
	if e != nil {
		t.Fatal(e)
	}
	if e = pump.BindV1(ctx, exporter); e != nil {
		t.Fatal(e)
	}
	select {
	case <-relayReady:
	case e := <-peer:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	v := &productionSessionV1{parent: p, pump: pump, attemptContext: ctx, wake: make(chan struct{}, 1)}
	p.session = v
	started := make(chan error, 1)
	run := make(chan error, 1)
	go func() {
		run <- pump.RunWithPublicationV1(ctx, func(publication *runtimeengine.ServiceRunPublicationV1) error {
			e := publication.CommitV1()
			if e == nil {
				p.mu.Lock()
				v.ready = true
				p.mu.Unlock()
			}
			started <- e
			return e
		})
	}()
	if e = <-started; e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { pump.Close(); <-run; <-peer })

	p.ticket.registry.mu.Lock()
	p.ticket.registry.slots[p.ticket.index].productionGeneration = 1
	p.ticket.registry.mu.Unlock()
	p.mu.Lock()
	v.handle = encodeHandle(p.ticket.index, 1, HandleProductionSession)
	v.published = true
	v.projection.effectiveMode = 2
	v.projection.effectiveStreamMax = 4
	v.projection.streamChunkMax = 16384
	observer := new(productionOutputTestV1)
	observer.epoch = p.ticket.epoch
	observer.handle = v.handle
	p.output, p.outputOwner, p.outputHandle = observer, 1, v.handle
	p.mu.Unlock()
	inv, status := NewProductionOutputInvocationV1(p.ticket.registry, observer, 1, 2, p.ticket.epoch)
	if status != 0 {
		t.Fatal(status)
	}
	return v, observer, inv, listener
}
func TestProductionOutputV1StreamRowSelection(t *testing.T) {
	v, o, inv, _ := productionOutputPumpFixtureV1(t)
	request := []byte{1, 1, 0, 4, 8, 8, 8, 8, 1, 187}
	child, s := OpenProductionStreamV1(inv.registry, v.handle, request)
	if s != 0 {
		t.Fatal(s)
	}
	if s = CancelProductionStreamV1(inv.registry, v.handle, child); s != 0 {
		t.Fatal(s)
	}
	next, s := OpenProductionStreamV1Scoped(inv.registry, v.handle, request, inv)
	if s != 0 || next == 0 {
		t.Fatal("next row", next, s)
	}
	o.mu.Lock()
	lane0, lane1 := o.lanes[6], o.lanes[9]
	o.mu.Unlock()
	if lane0 != 0 || lane1 != inv.call {
		t.Fatal("outer selected tombstoned row", lane0, lane1)
	}
	v.parent.mu.Lock()
	before := v.nextChild
	v.parent.mu.Unlock()
	o.mu.Lock()
	o.refuse = 5
	o.mu.Unlock()
	inv.call++
	if child, s = OpenProductionStreamV1Scoped(inv.registry, v.handle, request, inv); child != 0 || s != 5 {
		t.Fatal("refused lanes", child, s)
	}
	v.parent.mu.Lock()
	after := v.nextChild
	v.parent.mu.Unlock()
	if before != after {
		t.Fatal("refused lane allocated child")
	}
}
func TestProductionOutputV1StreamRowRetryEligibility(t *testing.T) {
	for _, exhausted := range []bool{true, false} {
		t.Run(map[bool]string{true: "child-exhaustion", false: "refused-lane-next-row"}[exhausted], func(t *testing.T) {
			v, o, inv, _ := productionOutputPumpFixtureV1(t)
			o.mu.Lock()
			o.oneLane = true
			if !exhausted {
				o.lanes[6] = inv.call + 1
			}
			o.mu.Unlock()
			p := v.parent
			p.mu.Lock()
			if exhausted {
				v.nextChild = math.MaxUint64
			}
			before, rows := v.nextChild, v.streams
			p.mu.Unlock()
			opaque := productionOpaqueIDsV1.Load()
			streams := v.pump.BoundsV1().ActiveStreams
			request := []byte{1, 1, 0, 4, 8, 8, 8, 8, 1, 187}
			child, status := OpenProductionStreamV1Scoped(inv.registry, v.handle, request, inv)
			p.mu.Lock()
			after, selected := v.nextChild, v.streams
			live := false
			for i := 0; i < int(v.projection.effectiveStreamMax); i++ {
				live = live || p.uses[6+3*i].live || v.streams[i].opening
			}
			p.mu.Unlock()
			o.mu.Lock()
			attempts, lanes, prepares := o.bindAttempts, o.lanes, o.prepareCalls
			o.mu.Unlock()
			if live {
				t.Fatal("row reservation or query use leaked")
			}
			if exhausted {
				if status != 5 || child != 0 || before != after || rows != selected || productionOpaqueIDsV1.Load() != opaque {
					t.Fatalf("post-bind exhaustion retried or allocated: status=%d child=%d counter=%d", status, child, after)
				}
				if attempts[6] != 1 || lanes[6] != inv.call || prepares != 0 || v.pump.BoundsV1().ActiveStreams != streams {
					t.Fatal("exhaustion admission or runtime work", attempts[6], lanes[6], prepares)
				}
				for i := 0; i < len(attempts); i++ {
					if i != 6 && (attempts[i] != 0 || lanes[i] != 0) {
						t.Fatal("post-bind exhaustion attempted another lane", i, attempts[i], lanes[i])
					}
				}
				// With no child allocation, the real opening path has returned
				// before its request copy and runtime OpenStream call.
			} else {
				if status != 0 || child == 0 || after != child || selected[0] != rows[0] || selected[1].child != child || prepares != 1 {
					t.Fatal("pre-bind refusal did not select next row", status, child)
				}
				if attempts[6] != 1 || attempts[9] != 1 || lanes[6] != inv.call+1 || lanes[9] != inv.call {
					t.Fatal("refused-lane retry trace", attempts, lanes)
				}
				for i := 0; i < len(attempts); i++ {
					if i != 6 && i != 9 && (attempts[i] != 0 || lanes[i] != 0) {
						t.Fatal("unexpected third row", i)
					}
				}
			}
		})
	}
}

func TestProductionOutputV1ReceiptClaimAndCompletion(t *testing.T) {
	p, o, inv := productionOutputParentFixtureV1(t)
	h := encodeHandle(p.ticket.index, 1, HandleProductionSession)
	p.outputHandle = h
	o.handle = h
	o.expectedReceipt = ProductionOutputParentV1
	p.mu.Lock()
	s := p.outputPrepareLockedV1(inv, 1, 0, 0, p.deadline, false)
	p.mu.Unlock()
	if s != 0 {
		t.Fatal(s)
	}
	p.cancelV1(7)
	if s = p.retireV1(); s != 0 {
		t.Fatal(s)
	}
	for _, bad := range []ProductionOutputInvocationV1{{registry: new(HandleRegistry), observer: o, owner: 1, call: inv.call, epoch: inv.epoch}, {registry: inv.registry, observer: o, owner: 2, call: inv.call, epoch: inv.epoch}} {
		if s = DiscardProductionParentOutputV1(bad, h); s != 3 {
			t.Fatal("wrong retired identity", s)
		}
	}
	if s = DiscardProductionStreamOutputV1(inv, h, 1); s != 3 {
		t.Fatal("wrong receipt kind", s)
	}
	if s = DiscardProductionParentOutputV1(inv, h); s != 0 {
		t.Fatal("actual retired receipt", s)
	}
	if s = DiscardProductionParentOutputV1(inv, h); s != 3 {
		t.Fatal("duplicate receipt", s)
	}
	o.ended[inv.call] = true
	if s = DiscardProductionParentOutputV1(inv, h); s != 3 {
		t.Fatal("ended frame", s)
	}
}
func TestProductionOutputV1ProbePartialFence(t *testing.T) {
	for _, terminal := range []int32{0, 7, 12} {
		t.Run(string(rune('a'+terminal)), func(t *testing.T) {
			p, _, inv := productionOutputParentFixtureV1(t)
			p.admission = &productionAdmissionV1{parent: p, monotonicDeadline: time.Now().Add(time.Minute)}
			v := &productionSessionV1{parent: p, ready: true}
			p.session = v
			use, s := p.beginUseOutputV1(198, productionBudgetChargeV1{}, inv, false)
			if s != 0 {
				t.Fatal(s)
			}
			if terminal == 7 {
				p.cancelV1(7)
			}
			if terminal == 12 {
				p.admission.monotonicDeadline = time.Now().Add(-time.Second)
			}
			out := make([]byte, 21)
			q := runtimeengine.ProbeRequestV1{Samples: 2}
			a := runtimeengine.ProbeAggregateV1{Path: runtimeengine.ProbeActiveRelayEndToEndV1, Attempted: 1, HasLatency: true, LatencyMicros: 1000}
			n, s := v.publishProbeOutputV1(use, q, a, context.DeadlineExceeded, out, inv)
			if terminal == 0 {
				if n != 21 || s != 0 || out[20] != 8 {
					t.Fatal("categorical timeout", n, s, out)
				}
			} else if n != 0 || s != terminal {
				t.Fatal("late partial", n, s)
			}
			p.finishUseV1(use)
			p.admission = nil
		})
	}
}
func TestProductionOutputV1NativeJoinExcludesOuter(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	platform := &productionSnapshotPlatformV1{snapshot: f.current}
	admission := productionAdmittedFixtureV1(t, f, platform, rates)
	p := admission.parent
	o := new(productionOutputTestV1)
	o.epoch = p.ticket.epoch
	p.output, p.outputOwner = o, 1
	inv, s := NewProductionOutputInvocationV1(p.ticket.registry, o, 1, 2, p.ticket.epoch)
	if s != 0 {
		t.Fatal(s)
	}
	use, s := p.beginUseOutputV1(2, productionBudgetChargeV1{}, inv, false)
	if s != 0 {
		t.Fatal(s)
	}
	p.finishUseV1(use)
	done := make(chan ErrorCode, 1)
	go func() { done <- platform.invalidate() }()
	select {
	case code := <-done:
		if code != CodeOK {
			t.Fatal(code)
		}
	case <-time.After(time.Second):
		t.Fatal("native join waited for outer frame")
	}
	o.mu.Lock()
	lane := o.lanes[2]
	o.mu.Unlock()
	if lane != inv.call {
		t.Fatal("outer frame vanished")
	}
	if s = o.PrepareV1(inv.call, inv.epoch, 1, 0, 0, time.Now().Add(time.Minute), false); s != 7 {
		t.Fatal("outer commit survived invalidation", s)
	}
}
func TestProductionOutputV1FailedRetirementStaysFailed(t *testing.T) {
	p, o, inv := productionOutputParentFixtureV1(t)
	h := encodeHandle(p.ticket.index, 1, HandleProductionSession)
	p.outputHandle = h
	o.handle = h
	o.expectedReceipt = ProductionOutputParentV1
	p.mu.Lock()
	p.outputPrepareLockedV1(inv, 1, 0, 0, p.deadline, false)
	p.cleanupResult = 18
	p.mu.Unlock()
	p.cancelV1(7)
	if s := p.retireV1(); s != 18 {
		t.Fatal(s)
	}
	if s := DiscardProductionParentOutputV1(inv, h); s != 18 {
		t.Fatal("failed cleanup changed", s)
	}
}
func TestProductionOutputV1DeadlineClasses(t *testing.T) {
	p, _, inv := productionOutputParentFixtureV1(t)
	p.mu.Lock()
	s := p.outputPrepareLockedV1(inv, 1, 0, 0, time.Time{}, false)
	p.mu.Unlock()
	if s != 18 {
		t.Fatal("ordinary absent deadline", s)
	}
	if s = p.enqueueControlFixedV1(productionControlStoppedV1, nil); s != 0 {
		t.Fatal(s)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if n, s := p.nextControlScopedV1(ctx, make([]byte, 34), inv); n != 0 || s != 8 {
		t.Fatal("terminal caller deadline", n, s)
	}
}

func productionOutputTLSCurrentFixtureV1(t *testing.T, raw bool, proxy ...bool) (maintenanceSignedFixture, *selfhost.RelayRuntimeSnapshotV1) {
	t.Helper()
	base := t.TempDir()
	dir, recovery := filepath.Join(base, "node"), filepath.Join(base, "recovery")
	now := time.Unix(1780000062, 0).UTC()
	pass := []byte("private local admission fixture recovery")
	if _, e := selfhost.Initialize(selfhost.InitOptions{DataDir: dir, DeploymentName: "production-admission-fixture", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: pass, Now: now.Add(-2 * time.Minute)}); e != nil {
		t.Fatal(e)
	}
	if e := selfhost.ConfirmRecovery(dir, recovery, pass, now.Add(-time.Minute)); e != nil {
		t.Fatal(e)
	}
	model, e := compiler.Generate(71)
	if e != nil {
		t.Fatal(e)
	}
	// Signed test authority outlives the actual 30-second stream tombstone.
	model.Limits.MaxSessionMillis = 120000
	model.GenerationHash, e = ir.CanonicalHash(model)
	if e != nil {
		t.Fatal(e)
	}
	features := ir.SecurityCapabilities()
	program, e := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: model, ClientMandatoryFeatures: features[:2], RelayMandatoryFeatures: features[:2], SelectedFeatures: features})
	if e != nil {
		t.Fatal(e)
	}
	wire, e := liveprogram.EncodeV1(program)
	if e != nil {
		t.Fatal(e)
	}
	request, private, e := enrollment.Generate(now, 24*time.Hour, rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	requestWire, e := enrollment.EncodeRequestV1(request)
	if e != nil {
		t.Fatal(e)
	}
	privateWire, e := enrollment.EncodePrivateBundleV1(private)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(privateWire); clear(private.RecipientPrivate); clear(private.ClientAuthSeed) })
	var services *runtimepolicy.ServicesV1
	if !raw {
		services = &runtimepolicy.ServicesV1{Version: 1, Probes: &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 1, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000}}, MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 10, MaxOperationMillis: 30000}}
		if len(proxy) == 1 && proxy[0] {
			services.Proxy = &runtimepolicy.ProxyV1{AddressKinds: []uint8{1}, DestinationCIDRs: []runtimepolicy.PrefixV2{{Address: []byte{8, 8, 8, 8}, PrefixLen: 32}}, DestinationPorts: []runtimepolicy.PortRangeV1{{First: 443, Last: 443}}, MaxConcurrentStreams: 4, MaxBufferBytes: 64 << 20, ConnectTimeoutMillis: 1000, IdleTimeoutSeconds: 30, MaxQueuedBytesPerDirection: 32768}
		}
	}
	issued, e := selfhost.CreateProfile(dir, selfhost.CreateProfileOptions{Name: "admitted-device", ValidFor: 12 * time.Hour, Now: now, RecipientRequest: requestWire, LiveProgram: wire, RegistryDir: filepath.Join(base, "registry"), Services: services})
	if e != nil {
		t.Fatal(e)
	}
	activation, e := selfhost.NewAndroidLiveActivationSessionForRecipient(issued.Artifact, now, lifecycle.VerifiedState{}, request, private)
	if e != nil {
		t.Fatal(e)
	}
	defer activation.Destroy()
	var staged profile.ActivationRecord
	for {
		command, ok := activation.Next()
		if !ok {
			break
		}
		result := profile.ActivationCommandResult{}
		if command.Kind == profile.ActivationCommandStageCandidate {
			staged = command.Record
		}
		if command.Kind == profile.ActivationCommandReopenCandidate {
			result.Record = staged
		}
		if e = activation.Submit(command, result); e != nil {
			t.Fatal(e)
		}
	}
	record, e := activation.Result()
	if e != nil {
		t.Fatal(e)
	}
	recordWire, e := EncodeActivationRecord(record)
	if e != nil {
		t.Fatal(e)
	}
	verifyWire, e := EncodeVerifyRequest(VerifyRequest{Ingress: envelope.IngressFile, Class: envelope.ArtifactDeviceRecipient, Parts: [][]byte{issued.Artifact}})
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := selfhost.OpenRelayRuntimeSnapshotV1(dir, now.Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(snapshot.Close)
	return maintenanceSignedFixture{now: now.Add(time.Minute), current: MaintenanceCurrentInputV1{verifyWire, recordWire, requestWire, privateWire}, artifact: issued.Artifact, record: record}, snapshot
}

func TestProductionOutputV1LegacyScalarCompletion(t *testing.T) {
	p, _, _ := productionOutputParentFixtureV1(t)
	v := &productionSessionV1{parent: p}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.cancelV1(7)
	if s := v.outputStreamScalarV1(ProductionOutputInvocationV1{}, productionUseV1{}, 1, ctx); s != 0 {
		t.Fatal("legacy completed scalar gained a new publication fence", s)
	}
}

func TestProductionOutputV1StreamQueryBindBoundary(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "terminal"}[terminal], func(t *testing.T) {
			var offset atomic.Int64
			v, o, inv, _ := productionOutputPumpFixtureV1(t, &offset)
			request := []byte{1, 1, 0, 4, 8, 8, 8, 8, 1, 187}
			child, s := OpenProductionStreamV1(inv.registry, v.handle, request)
			if s != 0 {
				t.Fatal(s)
			}
			if s = CancelProductionStreamV1(inv.registry, v.handle, child); s != 0 {
				t.Fatal(s)
			}
			p := v.parent
			p.mu.Lock()
			row := v.streams[0]
			v.streams[0].opening = true
			before := v.nextChild
			p.mu.Unlock()
			use, _, s := v.beginIOOutputV1(6, 259, inv, true)
			if s != 0 {
				t.Fatal(s)
			}
			defer p.finishUseV1(use)
			// Cancellation admits a queued reset; wait for its actual write before
			// advancing the fake clock past the independent 30-second I/O limit.
			flushed := time.Now().Add(time.Second)
			for v.pump.BoundsV1().QueueUsed != 0 {
				if !time.Now().Before(flushed) {
					t.Fatal("cancel reset did not flush")
				}
				runtime.Gosched()
			}
			offset.Store(int64(31 * time.Second))
			until := time.Now().Add(time.Second)
			for {
				retired, err := v.pump.StreamRetiredV1(row.wire)
				if err != nil {
					t.Fatal(err)
				}
				if retired {
					break
				}
				if !time.Now().Before(until) {
					t.Fatal("runtime did not retire tombstone")
				}
				runtime.Gosched()
			}
			// Caller barrier: the actual runtime query has completed, and no
			// observer method or native parent fence is active here.
			streams := v.pump.BoundsV1().ActiveStreams
			if terminal {
				p.cancelV1(7)
			}
			next, s, retry := v.selectStreamOutputRowV1(0, row, use, inv)
			if retry {
				t.Fatal("live or terminal row fence requested retry")
			}
			p.mu.Lock()
			after, selected, live := v.nextChild, v.streams[0], p.uses[6].live
			p.mu.Unlock()
			if terminal {
				row.opening = false
				if next != 0 || s != 7 || before != after || selected != row || live || o.lanes[6] != 0 {
					t.Fatal("terminal crossed final row fence", next, s, before, after, live)
				}
			} else if s != 0 || next == 0 || after != next || selected.child != next || o.lanes[6] != inv.call {
				t.Fatal("live final selection", next, s)
			}
			if v.pump.BoundsV1().ActiveStreams != streams {
				t.Fatal("final row selection started wire work")
			}
		})
	}
}

func productionOutputManagedFixtureV1(t *testing.T, retirementGate <-chan struct{}) (*productionSessionV1, *productionOutputTestV1, ProductionOutputInvocationV1, net.Listener) {
	t.Helper()
	v, o, inv, listener := productionOutputPumpFixtureV1(t)
	v.done, v.cleanupDone = make(chan struct{}), make(chan struct{})
	var s int32
	v.ticket, s = v.parent.budget.reserveV1(productionBudgetChargeV1{})
	if s != 0 {
		t.Fatal(s)
	}
	// The fixture's joined coordinator invokes the real native retirement path.
	// It owns no replacement cleanup implementation or fabricated completion.
	go func() {
		<-v.parent.cancelContext.Done()
		if retirementGate != nil {
			<-retirementGate
		}
		v.retireAttemptV1()
		close(v.done)
	}()
	t.Cleanup(func() { v.closeOutputParentV1() })
	return v, o, inv, listener
}

func TestProductionOutputV1AcquiredReceiptMatrix(t *testing.T) {
	for _, kind := range []ProductionOutputReceiptKindV1{ProductionOutputParentV1, ProductionOutputStreamV1, ProductionOutputPacketDeliveryV1, ProductionOutputStreamDeliveryV1} {
		for _, mode := range []string{"live", "completed", "terminal", "failure", "active"} {
			t.Run(fmt.Sprintf("kind%d/%s", kind, mode), func(t *testing.T) {
				var gate chan struct{}
				var release sync.Once
				if mode == "terminal" {
					gate = make(chan struct{})
					defer release.Do(func() { close(gate) })
				}
				v, o, inv, listener := productionOutputManagedFixtureV1(t, gate)
				p, parent := v.parent, v.handle
				o.expectedReceipt = kind
				var child, delivery uint64
				var wire uint32
				var writer <-chan error
				switch kind {
				case ProductionOutputParentV1:
					p.mu.Lock()
					s := p.outputPrepareLockedV1(inv, p.attempt, 0, 0, p.admission.monotonicDeadline, false)
					p.mu.Unlock()
					if s != 0 {
						t.Fatal(s)
					}
				case ProductionOutputStreamV1, ProductionOutputStreamDeliveryV1:
					request := []byte{1, 1, 0, 4, 8, 8, 8, 8, 1, 187}
					var s int32
					if kind == ProductionOutputStreamV1 {
						child, s = OpenProductionStreamV1Scoped(inv.registry, parent, request, inv)
					} else {
						child, s = OpenProductionStreamV1(inv.registry, parent, request)
					}
					if s != 0 {
						t.Fatal("acquire stream", s)
					}
					wire = v.streams[0].wire
					conn, err := listener.Accept()
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { conn.Close() })
					if kind == ProductionOutputStreamDeliveryV1 {
						written := make(chan error, 1)
						writer = written
						go func() { _, err := conn.Write([]byte{11, 22, 33}); written <- err }()
						n, token, s := ReceiveProductionStreamV1Scoped(inv.registry, parent, child, make([]byte, 64), inv)
						if n != 3 || token == 0 || s != 0 {
							t.Fatal("acquire stream delivery", n, token, s)
						}
						delivery = token
					} else {
						if s = CancelProductionStreamV1(inv.registry, parent, child); s != 0 {
							t.Fatal(s)
						}
						if retired, err := v.pump.StreamRetiredV1(wire); err != nil || retired {
							t.Fatal("must force tombstone fallback", retired, err)
						}
					}
				case ProductionOutputPacketDeliveryV1:
					port, err := runtimeengine.NewPacketPortV1(1500)
					if err != nil {
						t.Fatal(err)
					}
					v.port = port
					v.projection.packetMax = 1500
					written := make(chan error, 1)
					writer = written
					go func() { _, err := port.Write([]byte{11, 22, 33}); written <- err }()
					n, token, s := ReceiveProductionPacketV1Scoped(inv.registry, parent, make([]byte, 64), inv)
					if n != 3 || token == 0 || s != 0 {
						t.Fatal("acquire packet", n, token, s)
					}
					delivery = token
				}
				discard := func(i ProductionOutputInvocationV1, h Handle, c, d uint64) int32 {
					switch kind {
					case ProductionOutputParentV1:
						return DiscardProductionParentOutputV1(i, h)
					case ProductionOutputStreamV1:
						return DiscardProductionStreamOutputV1(i, h, c)
					case ProductionOutputPacketDeliveryV1:
						return DiscardProductionPacketOutputV1(i, h, d)
					default:
						return DiscardProductionStreamDeliveryOutputV1(i, h, c, d)
					}
				}
				before := o.receipts[inv.call]
				if !before.prepared || before.kind != kind || before.child != child || before.delivery != delivery {
					t.Fatal("wrong acquired receipt", before)
				}
				for _, mutate := range []func(*ProductionOutputInvocationV1){func(i *ProductionOutputInvocationV1) { i.owner++ }, func(i *ProductionOutputInvocationV1) { i.registry = new(HandleRegistry) }, func(i *ProductionOutputInvocationV1) { i.call++ }, func(i *ProductionOutputInvocationV1) { i.epoch++ }} {
					bad := inv
					mutate(&bad)
					if s := discard(bad, parent, child, delivery); s != 3 {
						t.Fatal("wrong identity", s)
					}
				}
				if s := discard(inv, parent+1, child, delivery); s != 3 {
					t.Fatal("wrong parent", s)
				}
				if child != 0 {
					if s := discard(inv, parent, child+1, delivery); s != 3 {
						t.Fatal("wrong child", s)
					}
				}
				if delivery != 0 {
					if s := discard(inv, parent, child, delivery+1); s != 3 {
						t.Fatal("wrong delivery", s)
					}
				}
				if retired, s := inv.claimV1(kind%4+1, parent, child, delivery); retired || s != 3 {
					t.Fatal("wrong kind", retired, s)
				}
				if o.receipts[inv.call] != before || p.state != productionParentOpenV1 {
					t.Fatal("rejected claims mutated native ownership")
				}
				want := int32(0)
				if mode == "active" {
					if retired, s := inv.claimV1(kind, parent, child, delivery); s != 0 || retired {
						t.Fatal("active claim", retired, s)
					}
					if s := discard(inv, parent, child, delivery); s != 3 || p.state != productionParentOpenV1 {
						t.Fatal("conflicting claim cleaned resource", s)
					}
					if s := inv.finishV1(kind, parent, child, delivery, 18); s != 18 {
						t.Fatal(s)
					}
					v.closeOutputParentV1()
					if o.receipts[inv.call].actual != 18 {
						t.Fatal("later actual retirement healed failed Finish")
					}
					return
				}
				var failure *maintenanceCleanupFailureRegistration
				if mode == "failure" {
					failure = new(maintenanceCleanupFailureRegistration)
					p.mu.Lock()
					p.admission.registration = failure
					p.mu.Unlock()
					want = 3
				}
				if mode == "terminal" {
					// Terminal notification alone is not a completion receipt.
					p.cancelV1(7)
					if o.receipts[inv.call].retired {
						t.Fatal("terminal manufactured retirement")
					}
				}
				if mode == "completed" {
					if s := v.closeOutputParentV1(); s != 0 {
						t.Fatal("actual close", s)
					}
				}
				if mode == "terminal" {
					done := make(chan int32, 1)
					go func() { done <- discard(inv, parent, child, delivery) }()
					until := time.Now().Add(time.Second)
					for {
						o.mu.Lock()
						claimed := o.receipts[inv.call].claimed
						o.mu.Unlock()
						if claimed {
							break
						}
						if !time.Now().Before(until) {
							t.Fatal("claim not reached")
						}
						runtime.Gosched()
					}
					select {
					case s := <-done:
						t.Fatal("merely terminal claimed clean", s)
					default:
					}
					release.Do(func() { close(gate) })
					if s := <-done; s != want {
						t.Fatal(s)
					}
				} else if s := discard(inv, parent, child, delivery); s != want {
					t.Fatal("discard", s, want)
				}
				receipt := o.receipts[inv.call]
				if receipt.claimCount != 1 || receipt.finishCount != 1 || receipt.finishActual != want || receipt.actual != want || receipt.claimRetired != (mode == "completed") || (receipt.retireCount == 0 && !(mode == "failure" && kind == ProductionOutputParentV1)) {
					t.Fatal("exact completion trace", receipt)
				}
				if failure != nil && failure.closeCount != 1 {
					t.Fatal("actual fallback failure not reached", failure.closeCount)
				}
				if mode != "failure" && (p.activeUses != 0 || v.streams[0].child != 0 || v.packet.token != 0) {
					t.Fatal("native resources remain")
				}
				if s := discard(inv, parent, child, delivery); s != 3 {
					t.Fatal("duplicate", s)
				}
				if writer != nil {
					if err := <-writer; kind == ProductionOutputPacketDeliveryV1 && err == nil {
						t.Fatal("discard acknowledged packet")
					}
				}
			})
		}
	}
}
