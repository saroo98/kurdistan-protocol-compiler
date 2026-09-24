// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"fmt"
	"kurdistan/internal/product/envelope"
	runtimeengine "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"
)

type maintenanceOutputTestV1 struct {
	mu               sync.Mutex
	registry         *HandleRegistry
	ended            [512]bool
	epoch            uint64
	handle           Handle
	lanes            [2]uint64
	events           [512]uint8
	count            int
	refuse           MaintenanceResultV1
	prepareRefuse    MaintenanceResultV1
	preparedDeadline time.Time
	preparedCalls    int
	supersedeRefuse  MaintenanceResultV1
	superseded       [512]bool
	preparedFrames   [512]bool
	terminal         bool
	candidate        MaintenanceCandidateID
	invalidCandidate MaintenanceCandidateID
	retiredCandidate MaintenanceCandidateID
	expectedReceipt  MaintenanceOutputReceiptKindV1
	receipts         [512]maintenanceOutputReceiptTestV1
}
type maintenanceOutputReceiptTestV1 struct {
	epoch                                uint64
	kind                                 MaintenanceOutputReceiptKindV1
	parent                               Handle
	child                                MaintenanceCandidateID
	prepared, claimed, retired, finished bool
	actual                               MaintenanceResultV1
	claimCount, finishCount, retireCount int
	claimRetired                         bool
	finishActual                         MaintenanceResultV1
}

func (o *maintenanceOutputTestV1) ValidateInvocationV1(r *HandleRegistry, owner, call, epoch uint64) MaintenanceResultV1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.registry == nil {
		o.registry = r
	}
	if r != o.registry || owner != 1 || call == 0 || call >= 512 || o.ended[call] {
		return MaintenanceInvalidState
	}
	return 0
}
func (o *maintenanceOutputTestV1) event(v uint8) {
	if o.count < len(o.events) {
		o.events[o.count] = v
		o.count++
	}
}
func (o *maintenanceOutputTestV1) BindParentV1(call, epoch uint64) MaintenanceResultV1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.epoch = epoch
	o.event(1)
	return o.refuse
}
func (o *maintenanceOutputTestV1) BindHandleV1(call, epoch uint64, h Handle) MaintenanceResultV1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if epoch != o.epoch {
		return MaintenanceInvalidState
	}
	o.handle = h
	o.event(2)
	return o.refuse
}
func (o *maintenanceOutputTestV1) BindLaneV1(call, epoch uint64, control bool) MaintenanceResultV1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	i := 0
	if control {
		i = 1
	}
	if o.lanes[i] != 0 {
		return MaintenanceResourceLimit
	}
	if o.refuse != 0 {
		return o.refuse
	}
	o.lanes[i] = call
	o.event(3)
	return 0
}
func (o *maintenanceOutputTestV1) SupersedeNormalV1(call, epoch uint64) MaintenanceResultV1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.event(8)
	if o.supersedeRefuse != 0 {
		return o.supersedeRefuse
	}
	if normal := o.lanes[0]; normal != 0 && normal != call {
		o.superseded[normal] = true
	}
	return o.refuse
}
func (o *maintenanceOutputTestV1) PrepareV1(call, epoch uint64, child MaintenanceCandidateID, deadline time.Time, terminal bool) MaintenanceResultV1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.event(4)
	if o.superseded[call] || o.ended[call] {
		return MaintenanceCancelled
	}
	if o.prepareRefuse != 0 {
		return o.prepareRefuse
	}
	o.preparedDeadline = deadline
	o.preparedCalls++
	o.preparedFrames[call] = true
	if o.terminal && !terminal {
		return MaintenanceCancelled
	}
	o.candidate = child
	if o.refuse == 0 && o.expectedReceipt != 0 && call < 512 {
		o.receipts[call] = maintenanceOutputReceiptTestV1{epoch: epoch, kind: o.expectedReceipt, parent: o.handle, child: child, prepared: true}
	}
	return o.refuse
}
func (o *maintenanceOutputTestV1) ParentTerminalV1(epoch uint64, reason MaintenanceResultV1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.terminal = true
	o.event(5)
}
func (o *maintenanceOutputTestV1) CandidateTerminalV1(epoch uint64, child MaintenanceCandidateID, reason MaintenanceResultV1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.invalidCandidate = child
	o.event(6)
}
func (o *maintenanceOutputTestV1) ClaimReceiptV1(call, epoch uint64, kind MaintenanceOutputReceiptKindV1, parent Handle, child MaintenanceCandidateID, delivery uint64) (bool, MaintenanceResultV1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if call >= 512 || delivery != 0 {
		return false, MaintenanceInvalidState
	}
	r := &o.receipts[call]
	if !r.prepared || r.claimed || r.finished || r.epoch != epoch || r.kind != kind || r.parent != parent || r.child != child {
		return false, MaintenanceInvalidState
	}
	r.claimed = true
	r.claimCount++
	r.claimRetired = r.retired && r.actual == 0
	return r.retired && r.actual == 0, 0
}
func (o *maintenanceOutputTestV1) FinishReceiptV1(call, epoch uint64, kind MaintenanceOutputReceiptKindV1, parent Handle, child MaintenanceCandidateID, delivery uint64, actual MaintenanceResultV1) MaintenanceResultV1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if call >= 512 || !o.receipts[call].claimed {
		return MaintenanceInvalidState
	}
	r := &o.receipts[call]
	if r.epoch != epoch || r.kind != kind || r.parent != parent || r.child != child || delivery != 0 {
		return MaintenanceInvalidState
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
func (o *maintenanceOutputTestV1) ResourceRetiredV1(epoch uint64, kind MaintenanceOutputReceiptKindV1, parent Handle, child MaintenanceCandidateID, actual MaintenanceResultV1) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.retiredCandidate = child
	o.event(7)
	for i := range o.receipts {
		r := &o.receipts[i]
		if r.prepared && r.epoch == epoch && r.kind == kind && r.parent == parent && r.child == child {
			r.retireCount++
			r.retired = actual == 0
			if r.actual == 0 {
				r.actual = actual
			}
		}
	}
}

func TestMaintenanceOutputV1OpeningAndBudget(t *testing.T) {
	r := new(HandleRegistry)
	o := new(maintenanceOutputTestV1)
	for _, c := range []struct {
		r           *HandleRegistry
		o           MaintenanceOutputObserverV1
		owner, call uint64
	}{{nil, o, 1, 1}, {r, nil, 1, 1}, {r, o, 0, 1}, {r, o, 1, 0}} {
		if _, s := NewMaintenanceOutputInvocationV1(c.r, c.o, c.owner, c.call, 0); s != MaintenanceInvalidRequest {
			t.Fatal(s)
		}
	}
	inv, s := NewMaintenanceOutputInvocationV1(r, o, 1, 1, 0)
	if s != 0 {
		t.Fatal(s)
	}
	if s = maintenanceOutputOpeningV1(r, inv, 0, 128<<20); s != MaintenanceInvalidRequest {
		t.Fatal(s)
	}
	if s = maintenanceOutputOpeningV1(r, inv, 1, 128<<20); s != 0 {
		t.Fatal(s)
	}
	if s = maintenanceOutputOpeningV1(new(HandleRegistry), inv, 1, 128<<20); s != MaintenanceInvalidRequest {
		t.Fatal(s)
	}
	if s = maintenanceOutputOpeningV1(r, MaintenanceOutputInvocationV1{}, 1, 128<<20); s != MaintenanceInvalidRequest {
		t.Fatal(s)
	}
	f := newMaintenanceSignedFixture(t)
	platform := &maintenanceOutputPlatformV1{output: o}
	config := MaintenanceConfigV1{Now: func() time.Time { return f.now }, OwnedBudgetBytes: 128 << 20, OutputMetadataBytes: uint64(unsafe.Sizeof(*o)), Limits: selfhost.LiveMaintenanceLimits{MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20}}
	if h, s := OpenMaintenanceV1Scoped(r, f.current, maintenanceRealVerifier{}, platform, config, inv); h != 0 || s == 0 || !platform.boundBeforeRegister || !o.terminal || inv.epoch != 0 {
		t.Fatal("opening fence", h, s, platform.boundBeforeRegister, o.terminal)
	}
}

type maintenanceOutputPlatformV1 struct {
	maintenanceIntegrationPlatform
	output              *maintenanceOutputTestV1
	boundBeforeRegister bool
}

func (p *maintenanceOutputPlatformV1) Register(epoch uint64, invalidate func() ErrorCode) (MaintenanceRevisionRegistrationV1, ErrorCode) {
	p.output.mu.Lock()
	p.boundBeforeRegister = p.output.epoch == epoch && p.output.lanes[0] != 0
	p.output.mu.Unlock()
	invalidate()
	return &p.maintenanceIntegrationPlatform, CodeOK
}

func TestMaintenanceOutputV1RevocationSupersedesOuter(t *testing.T) {
	p := newMaintenanceStateFixture(t)
	p.registry = new(HandleRegistry)
	o := new(maintenanceOutputTestV1)
	p.output, p.outputOwner = o, 1
	o.epoch = p.parentEpoch
	inv, result := NewMaintenanceOutputInvocationV1(p.registry, o, 1, 1, p.parentEpoch)
	if result != 0 {
		t.Fatal(result)
	}
	op, s := p.beginOperationOutputV1(inv, false)
	if s != 0 {
		t.Fatal(s)
	}
	if s = p.finishPublication(op, maintenanceClockLease{}); s != 0 {
		t.Fatal(s)
	}
	p.finishOperation(op)
	inv.call = 2
	if _, s = p.beginOperationOutputV1(inv, false); s != MaintenanceResourceLimit {
		t.Fatal("outer lost", s)
	}
	revoke, s := p.beginRevocationOutputV1(inv)
	if s != 0 {
		t.Fatal(s)
	}
	p.finishRevocationOperation(revoke)
	if s = o.PrepareV1(1, p.parentEpoch, 0, p.parentTimerAt, false); s != MaintenanceCancelled {
		t.Fatal("returned normal frame survived supersession", s)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	found := false
	for _, e := range o.events[:o.count] {
		found = found || e == 8
	}
	if !found {
		t.Fatal("normal outer not superseded")
	}
}

func maintenanceOutputOpenFixtureV1(t *testing.T) (maintenanceSignedFixture, *HandleRegistry, Handle, *maintenanceAuthorityV1, *maintenanceOutputTestV1, MaintenanceOutputInvocationV1) {
	t.Helper()
	f := newMaintenanceSignedFixture(t)
	r := new(HandleRegistry)
	o := new(maintenanceOutputTestV1)
	inv, s := NewMaintenanceOutputInvocationV1(r, o, 1, 1, 0)
	if s != 0 {
		t.Fatal(s)
	}
	h, s := OpenMaintenanceV1Scoped(r, f.current, maintenanceRealVerifier{}, new(maintenanceIntegrationPlatform), MaintenanceConfigV1{Now: func() time.Time { return f.now }, OwnedBudgetBytes: 128 << 20, OutputMetadataBytes: uint64(unsafe.Sizeof(*o)), Limits: selfhost.LiveMaintenanceLimits{MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20}}, inv)
	if s != 0 {
		t.Fatal("open", s)
	}
	t.Cleanup(func() { r.Free(h) })
	p, s := maintenanceParentV1(r, h)
	if s != 0 {
		t.Fatal(s)
	}
	p.stopSupervisor()
	o.mu.Lock()
	o.lanes[0] = 0
	o.mu.Unlock()
	inv, s = NewMaintenanceOutputInvocationV1(r, o, 1, 2, p.parentEpoch)
	if s != 0 {
		t.Fatal(s)
	}
	return f, r, h, p, o, inv
}
func TestMaintenanceOutputV1CandidateTimerWins(t *testing.T) {
	f, r, h, p, o, inv := maintenanceOutputOpenFixtureV1(t)
	result := VerifyMaintenanceCandidateV1Scoped(r, h, f.replacement, inv)
	if result.Result != 0 || result.Candidate == 0 {
		t.Fatal(result.Result)
	}
	p.mu.Lock()
	seq, kind := p.timerSeq, p.timerKind
	p.mu.Unlock()
	if p.expireTimer(seq, kind) {
		t.Fatal("candidate expiry terminalized parent")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.candidate != result.Candidate || o.invalidCandidate != result.Candidate || o.retiredCandidate != result.Candidate {
		t.Fatal("missing exact child fences", o.candidate, o.invalidCandidate, o.retiredCandidate)
	}
}
func TestMaintenanceOutputV1MaterializeConsumption(t *testing.T) {
	f, r, h, _, o, inv := maintenanceOutputOpenFixtureV1(t)
	result := VerifyMaintenanceCandidateV1Scoped(r, h, f.replacement, inv)
	if result.Result != 0 {
		t.Fatal(result.Result)
	}
	o.mu.Lock()
	o.lanes[0] = 0
	o.mu.Unlock()
	inv.call++
	if n, s := MaterializeMaintenanceCandidateV1Scoped(r, h, result.Candidate, make([]byte, 1), inv); n != 0 || s != MaintenanceSizeLimit {
		t.Fatal("size limit", n, s)
	}
	o.mu.Lock()
	o.lanes[0] = 0
	o.mu.Unlock()
	inv.call++
	out := make([]byte, len(f.replacement))
	n, s := MaterializeMaintenanceCandidateV1Scoped(r, h, result.Candidate, out, inv)
	if n != len(f.replacement) || s != 0 {
		t.Fatal("materialize", n, s)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.candidate != 0 || o.invalidCandidate != 0 || o.retiredCandidate != result.Candidate {
		t.Fatal("consumption conflated with invalidation", o.candidate, o.invalidCandidate, o.retiredCandidate)
	}
}
func TestMaintenanceOutputV1ReceiptClaimAndCompletion(t *testing.T) {
	_, r, h, p, o, inv := maintenanceOutputOpenFixtureV1(t)
	o.expectedReceipt = MaintenanceOutputParentV1
	p.mu.Lock()
	s := p.outputPrepareLockedV1(inv, 0, p.parentTimerAt, false)
	p.mu.Unlock()
	if s != 0 {
		t.Fatal(s)
	}
	if code := r.Free(h); code != CodeOK {
		t.Fatal(code)
	}
	for _, bad := range []MaintenanceOutputInvocationV1{{registry: new(HandleRegistry), observer: o, owner: 1, call: inv.call, epoch: inv.epoch}, {registry: r, observer: o, owner: 2, call: inv.call, epoch: inv.epoch}} {
		if s = DiscardMaintenanceParentOutputV1(bad, h); s != MaintenanceInvalidState {
			t.Fatal("wrong retired owner", s)
		}
	}
	if s = DiscardMaintenanceCandidateOutputV1(inv, h, 1); s != MaintenanceInvalidState {
		t.Fatal("wrong kind", s)
	}
	if s = DiscardMaintenanceParentOutputV1(inv, h); s != 0 {
		t.Fatal("actual retired receipt", s)
	}
	if s = DiscardMaintenanceParentOutputV1(inv, h); s != MaintenanceInvalidState {
		t.Fatal("duplicate receipt", s)
	}
}
func TestMaintenanceOutputV1NativeJoinExcludesOuter(t *testing.T) {
	_, _, _, p, o, inv := maintenanceOutputOpenFixtureV1(t)
	platform := p.registration.(*maintenanceIntegrationPlatform)
	op, s := p.beginOperationOutputV1(inv, false)
	if s != 0 {
		t.Fatal(s)
	}
	p.finishOperation(op)
	done := make(chan ErrorCode, 1)
	go func() { done <- platform.invalidate() }()
	select {
	case code := <-done:
		if code != CodeOK {
			t.Fatal(code)
		}
	case <-time.After(time.Second):
		t.Fatal("native join included outer")
	}
	o.mu.Lock()
	lane := o.lanes[0]
	o.mu.Unlock()
	if lane != inv.call {
		t.Fatal("outer vanished")
	}
	if s = o.PrepareV1(inv.call, inv.epoch, 0, time.Now().Add(time.Minute), false); s != MaintenanceCancelled {
		t.Fatal("outer remained publishable", s)
	}
}
func TestMaintenanceOutputV1LaterEpochRequired(t *testing.T) {
	r := new(HandleRegistry)
	o := new(maintenanceOutputTestV1)
	inv, s := NewMaintenanceOutputInvocationV1(r, o, 1, 1, 0)
	if s != 0 {
		t.Fatal(s)
	}
	if r := CheckSameDeploymentUpdateV1Scoped(r, 1, 1000, inv); r.Result != MaintenanceInvalidState {
		t.Fatal(r.Result)
	}
	if _, s := RunMaintenanceProbeV1Scoped(r, 1, runtimeengine.ProbeRequestV1{}, inv); s != MaintenanceInvalidState {
		t.Fatal(s)
	}
	if s := CancelMaintenanceV1Scoped(r, 1, inv); s != MaintenanceInvalidState {
		t.Fatal(s)
	}
	if s := CloseMaintenanceV1Scoped(r, 1, inv); s != MaintenanceInvalidState {
		t.Fatal(s)
	}
}
func TestMaintenanceOutputV1DeadlineClasses(t *testing.T) {
	_, _, _, p, _, inv := maintenanceOutputOpenFixtureV1(t)
	p.mu.Lock()
	s := p.outputPrepareLockedV1(inv, 0, time.Time{}, false)
	p.mu.Unlock()
	if s != MaintenanceInternalFailure {
		t.Fatal("ordinary absent deadline", s)
	}
	p.mu.Lock()
	p.terminalSet = true
	p.terminal = MaintenanceRevoked
	p.output.ParentTerminalV1(p.parentEpoch, MaintenanceRevoked)
	p.parentTimerAt = time.Now().Add(-time.Second)
	s = p.outputPrepareLockedV1(inv, 0, time.Time{}, true)
	p.mu.Unlock()
	if s != 0 {
		t.Fatal("categorical terminal carries no expired authority", s)
	}
}

func TestMaintenanceOutputV1ProbePartialPublication(t *testing.T) {
	for _, mode := range []string{"timeout", "rate", "cancel", "revoke", "expiry", "network", "revision", "nil_lease", "refuse", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _, p, o, inv := maintenanceOutputOpenFixtureV1(t)
			if mode == "legacy" {
				inv = MaintenanceOutputInvocationV1{}
			}
			op, s := p.beginOperationOutputV1(inv, false)
			if s != 0 {
				t.Fatal(s)
			}
			defer p.finishOperation(op)
			network := newMaintenanceTestNetwork()
			if s = p.installTransport(op, &maintenanceTestEnvironment{network: network}); s != 0 {
				t.Fatal(s)
			}
			original := op.ctx
			if s = p.boundOperation(op, f.now, time.Now().Add(-2*time.Second), f.now.Add(time.Second)); s != 0 {
				t.Fatal(s)
			}
			if op.ctx.Err() != context.DeadlineExceeded || original.Err() != nil {
				t.Fatal("not an actual work-only timeout", op.ctx.Err(), original.Err())
			}
			before := o.preparedCalls
			result := MaintenanceTimeout
			want := result
			switch mode {
			case "rate":
				result, want = MaintenanceRateLimited, MaintenanceRateLimited
			case "cancel":
				op.cancel()
				want = MaintenanceCancelled
			case "revoke":
				p.failOperation(op, MaintenanceRevoked)
				want = MaintenanceRevoked
			case "expiry":
				p.parentTimerAt = time.Now().Add(-time.Second)
				want = MaintenanceExpired
			case "network":
				network.current.Store(false)
				want = MaintenanceNetworkUnavailable
			case "revision":
				p.registration.(*maintenanceIntegrationPlatform).afterAcquire = func() { p.failOperation(op, MaintenanceCancelled) }
				want = MaintenanceCancelled
			case "nil_lease":
				p.registration = maintenanceOutputNilLeaseV1{p.registration}
				want = MaintenanceInternalFailure
			case "refuse":
				o.prepareRefuse = MaintenanceResourceLimit
				want = MaintenanceResourceLimit
			}
			partial := runtimeengine.ProbeAggregateV1{Path: runtimeengine.ProbeDisconnectedTCPConnectV1, Attempted: 1, HasLatency: true, LatencyMicros: 1000}
			out, got := p.publishProbe(op, partial, result)
			if got != want {
				t.Fatal("status", got, want)
			}
			allowed := mode == "timeout" || mode == "rate" || mode == "legacy"
			if allowed && out != partial {
				t.Fatal("lost categorical aggregate", out)
			}
			if !allowed && out != (runtimeengine.ProbeAggregateV1{}) {
				t.Fatal("partial survived failed fence", out)
			}
			if allowed && mode != "legacy" && (o.preparedCalls != before+1 || !o.preparedDeadline.After(time.Now()) || !o.preparedDeadline.Equal(p.parentTimerAt)) {
				t.Fatal("no remaining-authority prepare", o.preparedCalls-before, o.preparedDeadline)
			}
			if (!allowed || mode == "legacy") && o.preparedCalls != before {
				t.Fatal("unexpected successful prepare")
			}
			if op.ctx.Err() != context.DeadlineExceeded {
				t.Fatal("work deadline changed", op.ctx.Err())
			}
		})
	}
}

func (o *maintenanceOutputTestV1) commitFrameV1(call uint64) MaintenanceResultV1 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ended[call] || o.superseded[call] || o.terminal || !o.preparedFrames[call] {
		return MaintenanceCancelled
	}
	o.ended[call] = true
	for i := range o.lanes {
		if o.lanes[i] == call {
			o.lanes[i] = 0
		}
	}
	return MaintenanceSuccess
}

type maintenanceOutputNilLeaseV1 struct {
	MaintenanceRevisionRegistrationV1
}

func (maintenanceOutputNilLeaseV1) AcquirePublication(context.Context) (MaintenancePublicationLeaseV1, MaintenanceResultV1) {
	return nil, MaintenanceSuccess
}

func TestMaintenanceOutputV1SupersessionWinners(t *testing.T) {
	for _, winner := range []string{"revocation", "normal", "refused"} {
		t.Run(winner, func(t *testing.T) {
			_, _, _, p, o, inv := maintenanceOutputOpenFixtureV1(t)
			op, s := p.beginOperationOutputV1(inv, false)
			if s != 0 {
				t.Fatal(s)
			}
			if s = p.finishPublication(op, maintenanceClockLease{}); s != 0 {
				t.Fatal(s)
			}
			p.finishOperation(op)
			if winner == "normal" && o.commitFrameV1(inv.call) != 0 {
				t.Fatal("normal commit lost before revocation")
			}
			if winner == "refused" {
				o.supersedeRefuse = MaintenanceResourceLimit
			}
			control, s := NewMaintenanceOutputInvocationV1(inv.registry, o, 1, inv.call+1, inv.epoch)
			if s != 0 {
				t.Fatal(s)
			}
			revoke, s := p.beginRevocationOutputV1(control)
			if winner == "refused" {
				if s != MaintenanceResourceLimit || revoke != nil || o.commitFrameV1(inv.call) != 0 {
					t.Fatal("refused supersession altered normal output", s)
				}
				return
			}
			if s != 0 {
				t.Fatal(s)
			}
			p.finishRevocationOperation(revoke)
			if winner == "revocation" && o.commitFrameV1(inv.call) != MaintenanceCancelled {
				t.Fatal("normal commit survived supersession")
			}
			if winner == "normal" && (!o.ended[inv.call] || o.superseded[inv.call]) {
				t.Fatal("supersession rewrote completed normal frame")
			}
		})
	}
}

func TestMaintenanceOutputV1AcquiredReceiptMatrix(t *testing.T) {
	for _, kind := range []MaintenanceOutputReceiptKindV1{MaintenanceOutputParentV1, MaintenanceOutputCandidateV1} {
		for _, mode := range []string{"live", "completed", "terminal", "failure", "active"} {
			t.Run(fmt.Sprintf("kind%d/%s", kind, mode), func(t *testing.T) {
				f, registry, parent, p, o, inv := maintenanceOutputOpenFixtureV1(t)
				o.expectedReceipt = kind
				var child MaintenanceCandidateID
				if kind == MaintenanceOutputCandidateV1 {
					result := VerifyMaintenanceCandidateV1Scoped(registry, parent, f.replacement, inv)
					if result.Result != 0 || result.Candidate == 0 {
						t.Fatal("acquire candidate", result)
					}
					child = result.Candidate
				} else {
					p.mu.Lock()
					s := p.outputPrepareLockedV1(inv, 0, p.parentTimerAt, false)
					p.mu.Unlock()
					if s != 0 {
						t.Fatal(s)
					}
				}
				discard := func(i MaintenanceOutputInvocationV1, h Handle, c MaintenanceCandidateID) MaintenanceResultV1 {
					if kind == MaintenanceOutputParentV1 {
						return DiscardMaintenanceParentOutputV1(i, h)
					}
					return DiscardMaintenanceCandidateOutputV1(i, h, c)
				}
				before := o.receipts[inv.call]
				if !before.prepared || before.kind != kind || before.child != child {
					t.Fatal("wrong acquired receipt", before)
				}
				for _, mutate := range []func(*MaintenanceOutputInvocationV1){func(i *MaintenanceOutputInvocationV1) { i.owner++ }, func(i *MaintenanceOutputInvocationV1) { i.registry = new(HandleRegistry) }, func(i *MaintenanceOutputInvocationV1) { i.call++ }, func(i *MaintenanceOutputInvocationV1) { i.epoch++ }} {
					bad := inv
					mutate(&bad)
					if s := discard(bad, parent, child); s != MaintenanceInvalidState {
						t.Fatal("wrong identity", s)
					}
				}
				if s := discard(inv, parent+1, child); s != MaintenanceInvalidState {
					t.Fatal("wrong parent", s)
				}
				if child != 0 {
					if s := discard(inv, parent, child+1); s != MaintenanceInvalidState {
						t.Fatal("wrong child", s)
					}
				}
				if retired, s := inv.claimV1(3-kind, parent, child); retired || s != MaintenanceInvalidState {
					t.Fatal("wrong kind", retired, s)
				}
				if retired, s := o.ClaimReceiptV1(inv.call, inv.epoch, kind, parent, child, 1); retired || s != MaintenanceInvalidState {
					t.Fatal("nonzero maintenance delivery", retired, s)
				}
				if o.receipts[inv.call] != before || p.terminalSet {
					t.Fatal("rejected claims changed ownership")
				}
				if mode == "active" {
					if retired, s := inv.claimV1(kind, parent, child); retired || s != 0 {
						t.Fatal(retired, s)
					}
					if s := discard(inv, parent, child); s != MaintenanceInvalidState || p.terminalSet {
						t.Fatal("active claim retired native owner", s)
					}
					if s := inv.finishV1(kind, parent, child, MaintenanceInternalFailure); s != MaintenanceInternalFailure {
						t.Fatal(s)
					}
					if c := registry.Free(parent); c != CodeOK {
						t.Fatal(c)
					}
					if o.receipts[inv.call].actual != MaintenanceInternalFailure || o.receipts[inv.call].retireCount == 0 {
						t.Fatal("actual later retirement healed failure")
					}
					return
				}
				want := MaintenanceSuccess
				var gate chan struct{}
				var release sync.Once
				var failure *maintenanceCleanupFailureRegistration
				if mode == "failure" {
					failure = new(maintenanceCleanupFailureRegistration)
					p.registration = failure
					want = MaintenanceInternalFailure
					if child != 0 {
						// A real admitted native op makes narrow candidate release unavailable.
						op, s := p.beginOperation()
						if s != 0 {
							t.Fatal(s)
						}
						go func() { <-op.ctx.Done(); p.finishOperation(op) }()
					}
				}
				if mode == "terminal" {
					op, s := p.beginOperation()
					if s != 0 {
						t.Fatal(s)
					}
					gate = make(chan struct{})
					defer release.Do(func() { close(gate) })
					go func() { <-op.ctx.Done(); <-gate; p.finishOperation(op) }()
					p.failOperation(op, MaintenanceCancelled)
					if o.receipts[inv.call].retired {
						t.Fatal("terminal manufactured retirement")
					}
				}
				if mode == "completed" {
					if child == 0 {
						if c := registry.Free(parent); c != CodeOK {
							t.Fatal(c)
						}
					} else if s := ReleaseMaintenanceCandidateV1(registry, parent, child); s != 0 {
						t.Fatal(s)
					}
				}
				if mode == "terminal" {
					done := make(chan MaintenanceResultV1, 1)
					go func() { done <- discard(inv, parent, child) }()
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
						t.Fatal("terminal mistaken for retired", s)
					default:
					}
					release.Do(func() { close(gate) })
					if s := <-done; s != want {
						t.Fatal(s)
					}
				} else if s := discard(inv, parent, child); s != want {
					t.Fatal("discard", s, want)
				}
				receipt := o.receipts[inv.call]
				if receipt.claimCount != 1 || receipt.finishCount != 1 || receipt.finishActual != want || receipt.actual != want || receipt.claimRetired != (mode == "completed") || receipt.retireCount == 0 {
					t.Fatal("exact receipt trace", receipt)
				}
				if p.candidate != nil || p.candidateID != 0 {
					t.Fatal("candidate survived actual cleanup")
				}
				if failure != nil && failure.closeCount != 1 {
					t.Fatal("fallback skipped real failed close", failure.closeCount)
				}
				if s := discard(inv, parent, child); s != MaintenanceInvalidState {
					t.Fatal("duplicate", s)
				}
				if kind == MaintenanceOutputCandidateV1 && mode != "failure" && mode != "terminal" && p.terminalSet {
					t.Fatal("narrow release closed unrelated parent")
				}
			})
		}
	}
}

func TestMaintenanceOutputV1ProbePublicationControlBudget(t *testing.T) {
	f, _, _, p, o, inv := maintenanceOutputOpenFixtureV1(t)
	base, s := maintenanceBridgeReservation(f.current)
	if s != 0 {
		t.Fatal(s)
	}
	// Two additional scoped-owned control objects: the authority publication
	// context and its timer, each charged by the existing 4KiB control bound.
	charged := p.budget - p.limits.OwnedBudgetBytes - base - uint64(unsafe.Sizeof(inv)) - uint64(unsafe.Sizeof(*o))
	if charged != 8192 {
		t.Fatal("publication controls not reserved before owner work", charged)
	}
	for _, scoped := range []bool{false, true} {
		for _, spare := range []uint64{0, 1} {
			r := new(HandleRegistry)
			observer := new(maintenanceOutputTestV1)
			opening := MaintenanceOutputInvocationV1{}
			metadata, controls := uint64(0), uint64(0)
			if scoped {
				opening, s = NewMaintenanceOutputInvocationV1(r, observer, 1, 1, 0)
				if s != 0 {
					t.Fatal(s)
				}
				metadata, controls = uint64(unsafe.Sizeof(*observer)), 8192
			}
			called := false
			config := MaintenanceConfigV1{OwnedBudgetBytes: base + uint64(unsafe.Sizeof(opening)) + metadata + controls + spare, OutputMetadataBytes: metadata, Now: func() time.Time { called = true; return f.now }, Limits: selfhost.LiveMaintenanceLimits{MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20}}
			h, result := OpenMaintenanceV1Scoped(r, f.current, maintenanceRealVerifier{}, new(maintenanceIntegrationPlatform), config, opening)
			if h != 0 {
				r.Free(h)
				t.Fatal("one byte cannot fund verified owner")
			}
			if spare == 0 && (called || result != MaintenanceResourceLimit) {
				t.Fatal("exact reserved boundary admitted work", scoped, called, result)
			}
			if spare == 1 && !called {
				t.Fatal("one-byte remaining boundary rejected before verifier", scoped, result)
			}
		}
	}
}
