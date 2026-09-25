// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type pumpGateWaitContextV1 struct {
	context.Context
	entered, release chan struct{}
}

type productionProbeWaitGateV1 struct {
	context.Context
	entered, release chan struct{}
	once             sync.Once
	ready            func() bool
}

func (g *productionProbeWaitGateV1) Done() <-chan struct{} {
	if g.ready() {
		g.once.Do(func() { close(g.entered); <-g.release })
	}
	return g.Context.Done()
}

func TestServiceProbeRunnerV1NextSampleRechecksRetiredGroupBeforeID(t *testing.T) {
	p, _, _, _ := pumpPairFixtureV1(t, nil, false)
	a, e := p.admitProbeV1(ProbeRequestV1{7, 1, 1000, 4000, 2})
	if e != nil {
		t.Fatal(e)
	}
	leaf, cancel := context.WithCancel(context.Background())
	wait := &productionProbeWaitGateV1{Context: leaf, entered: make(chan struct{}), release: make(chan struct{})}
	wait.ready = func() bool {
		p.cfg.ProbeRates.mu.Lock()
		defer p.cfg.ProbeRates.mu.Unlock()
		return p.cfg.ProbeRates.states[0].state.count == 1
	}
	finishEntered, workerRetired, leafRelease := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	var releaseWait, releaseLeaf, notifyRetired sync.Once
	finished, workerDone := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() {
		releaseWait.Do(func() { close(wait.release) })
		releaseLeaf.Do(func() { close(leafRelease) })
		cancel()
		p.Close()
		<-p.Done()
	})
	blockedCancel := func() {
		if calls.Add(1) == 1 {
			close(finishEntered)
		} else {
			notifyRetired.Do(func() { close(workerRetired) })
		}
		<-leafRelease
		cancel()
	}
	p.mu.Lock()
	qi, e := p.reserveV1(context.Background(), p.deadline, false)
	if e != nil {
		p.mu.Unlock()
		t.Fatal(e)
	}
	p.queue[qi].id = 99
	p.nextID = 1
	p.probes[0] = serviceProbeSlotV1{handle: 1, id: 1, state: 1, admission: a, deadline: p.lastNow.Add(4 * time.Second), worker: true, cancel: blockedCancel, hasResult: true, result: ServiceSuccessV1, sampleCount: 1}
	p.probes[0].samples[0] = ProbeSampleV1{Attempted: true, Success: true, DurationMicros: 100, AttemptTimeoutMillis: 1000}
	if e = p.reserveUsesLockedV1(3); e != nil {
		p.mu.Unlock()
		t.Fatal(e)
	}
	p.mu.Unlock()
	go func() { p.workerV1(func() error { return p.probeGroupV1(0, 1, wait) }); close(workerDone) }()
	go p.workerV1(p.txV1)
	go p.workerV1(p.superviseV1)
	select {
	case <-wait.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("next-sample did not reach queue wait")
	}
	go func() { finished <- p.finishProbeV1(0, 1, ServiceCancelledV1) }()
	select {
	case <-finishEntered:
	case <-time.After(time.Second):
		t.Fatal("finish did not publish before leaf cancellation")
	}
	if leaf.Err() != nil {
		t.Fatal("cancellation masked queue race")
	}
	p.mu.Lock()
	p.queue[qi].state = 4
	p.notifyLockedV1()
	p.mu.Unlock()
	releaseWait.Do(func() { close(wait.release) })
	select {
	case <-workerRetired:
	case <-time.After(time.Second):
		t.Fatal("worker did not retire while leaf cancellation blocked")
	}
	p.mu.Lock()
	next, state, samples, aggregate, terminal := p.nextID, p.probes[0].state, p.probes[0].sampleCount, p.probes[0].aggregate, p.terminal
	published := false
	for _, q := range p.queue {
		published = published || (q.opcode == ServiceProbeV1 && (q.state == 2 || q.state == 3))
	}
	p.mu.Unlock()
	if next != 1 || state != 3 || samples != 1 || published || terminal {
		t.Errorf("retired group published sample: id=%d state=%d samples=%d published=%v terminal=%v", next, state, samples, published, terminal)
	}
	if aggregate.Attempted != 1 || !aggregate.HasLatency || aggregate.LatencyMicros != 100 || aggregate.LossPermille != 0 {
		t.Error("terminal aggregate changed", aggregate)
	}
	p.cfg.ProbeRates.mu.Lock()
	starts := 0
	for _, entry := range p.cfg.ProbeRates.states {
		if entry.live && entry.digest == p.cfg.ProbeScope.digest {
			starts = entry.state.count
		}
	}
	p.cfg.ProbeRates.mu.Unlock()
	if starts != 1 {
		t.Error("legitimate queue-wait rate start refunded or duplicated", starts)
	}
	releaseLeaf.Do(func() { close(leafRelease) })
	select {
	case e = <-finished:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("finish join")
	}
	select {
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("worker join")
	}
}

func TestServiceProbeRunnerV1Fix2CleanupPreservesMeasuredOutcome(t *testing.T) {
	for _, scenario := range []string{"success", "dial-error", "real-deadline", "reset"} {
		t.Run(scenario, func(t *testing.T) {
			_, local := pumpLocalListenerV1(t)
			n := &pumpCleanupNetworkV1{pumpLocalNetworkV1: local, dialEntered: make(chan context.Context, 2), dialRelease: make(chan struct{}), closeEntered: make(chan error, 2), closeRelease: make(chan struct{})}
			if scenario == "dial-error" {
				n.dialErr = ServiceUnreachableV1
			}
			_, r, _, _ := pumpPairFixtureV1(t, n, false)
			a, e := r.admitProbeV1(ProbeRequestV1{7, 1, 1000, 2000, 1})
			if e != nil {
				t.Fatal(e)
			}
			limit := time.Second
			if scenario == "real-deadline" {
				limit = 100 * time.Millisecond
			}
			leaf, cancel := context.WithTimeout(context.Background(), limit)
			defer cancel()
			realDeadline, _ := leaf.Deadline()
			r.mu.Lock()
			qi, e := r.reserveV1(leaf, r.deadline, false)
			if e != nil {
				r.mu.Unlock()
				t.Fatal(e)
			}
			r.queue[qi].id = 1
			r.probes[0] = serviceProbeSlotV1{id: 1, state: 1, admission: a, deadline: r.lastNow.Add(time.Second), worker: true, cancel: cancel, responseQueue: qi, responseSerial: r.queue[qi].serial}
			r.reserveUsesLockedV1(1)
			r.mu.Unlock()
			go r.workerV1(func() error { return r.relayProbeV1(0, 1, leaf) })
			<-n.dialEntered
			close(n.dialRelease)
			if entryErr := <-n.closeEntered; entryErr != context.Canceled {
				t.Error("completed probe Close entered before explicit cancel", entryErr)
			}
			if scenario == "real-deadline" {
				<-time.After(time.Until(realDeadline) + time.Millisecond)
			}
			if scenario == "reset" {
				if e = r.acceptProbeResetV1(0, 1); e != nil {
					t.Fatal(e)
				}
			}
			close(n.closeRelease)
			if scenario == "reset" {
				pumpWaitUntilV1(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return !r.probes[0].worker })
				r.mu.Lock()
				published := r.queue[qi].state == 2
				r.mu.Unlock()
				if published {
					t.Error("cleanup cancellation concealed external RESET")
				}
				return
			}
			pumpWaitUntilV1(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.queue[qi].state == 2 })
			r.mu.Lock()
			result := ServiceResultV1(binary.BigEndian.Uint16(r.queue[qi].data[8:10]))
			duration := binary.BigEndian.Uint32(r.queue[qi].data[10:14])
			r.queue[qi].state = 0
			r.notifyLockedV1()
			r.mu.Unlock()
			want := ServiceSuccessV1
			if scenario == "dial-error" {
				want = ServiceUnreachableV1
			}
			if scenario == "real-deadline" {
				want = ServiceTimeoutV1
			}
			if result != want {
				t.Error("cleanup changed measured result", result, want)
			}
			if want != ServiceSuccessV1 && duration != 0 {
				t.Error("failed attempt retained success duration")
			}
			pumpWaitUntilV1(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return !r.probes[0].worker })
		})
	}
}

func (c pumpGateWaitContextV1) Done() <-chan struct{} {
	close(c.entered)
	<-c.release
	return c.Context.Done()
}
func TestServiceProbeRunnerV1Fix1BoundaryTombstoneClearsJoinedTarget(t *testing.T) {
	c, r, _, _ := pumpPairFixtureV1(t, nil, false)
	var forced atomic.Int64
	original := c.cfg.Now
	c.cfg.Now = func() time.Time {
		if n := forced.Load(); n != 0 {
			return time.Unix(0, n)
		}
		return original()
	}
	pumpStartPairV1(t, c, r)
	a, e := c.admitProbeV1(ProbeRequestV1{7, 1, 1000, 2000, 1})
	if e != nil {
		t.Fatal(e)
	}
	wait := pumpGateWaitContextV1{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
	c.mu.Lock()
	now := c.lastNow
	deadline := now.Add(time.Second)
	c.probes[0] = serviceProbeSlotV1{id: 1, handle: 1, state: 1, worker: true, admission: a, sentAt: now, sentMono: time.Now(), attemptDeadline: deadline, deadline: now.Add(2 * time.Second)}
	c.users++
	c.mu.Unlock()
	go c.workerV1(func() error { return c.probeGroupV1(0, 1, wait) })
	<-wait.entered
	forced.Store(deadline.UnixNano())
	r.mu.Lock()
	_, e = r.queueControlLockedV1(context.Background(), 1, ServiceProbeResultV1, []byte{0, 0, 0, 0, 0, 1}, 1000, r.deadline)
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.probes[0].state == 3 })
	close(wait.release)
	pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return !c.probes[0].worker })
	c.mu.Lock()
	g := c.probes[0]
	c.mu.Unlock()
	if len(g.admission.target.Address) != 0 || len(g.admission.target.Methods) != 0 || len(g.admission.target.Modes) != 0 {
		t.Error("boundary tombstone retained target authority after worker join")
	}
	if g.admission.request.AttemptTimeoutMillis != 1000 || g.sampleCount != 0 || g.failure != ServiceTimeoutV1 {
		t.Error("scalar timeout/aggregate lost")
	}
}
func TestServiceProbeRunnerV1Fix1PeerResetClearsTargetAfterBorrower(t *testing.T) {
	l, n := pumpLocalListenerV1(t)
	gated := pumpGatedDialV1{n, make(chan struct{}), make(chan struct{})}
	c, r, _, _ := pumpPairFixtureV1(t, gated, false)
	pumpStartPairV1(t, c, r)
	h, e := c.StartProbe(context.Background(), ProbeRequestV1{7, 1, 1000, 2000, 1})
	if e != nil {
		t.Fatal(e)
	}
	<-gated.entered
	if e = c.CancelProbe(h); e != nil {
		t.Fatal(e)
	}
	pumpWaitUntilV1(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.probes[0].state == 3 })
	r.mu.Lock()
	retained := len(r.probes[0].admission.target.Address) != 0 && r.probes[0].worker
	r.mu.Unlock()
	if !retained {
		t.Error("live dial borrower lost its target authority")
	}
	close(gated.release)
	pumpWaitUntilV1(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return !r.probes[0].worker })
	r.mu.Lock()
	a := r.probes[0].admission
	r.mu.Unlock()
	if len(a.target.Address) != 0 || len(a.target.Methods) != 0 || len(a.target.Modes) != 0 {
		t.Error("peer-reset tombstone retained target after worker join")
	}
	if a.request.AttemptTimeoutMillis != 1000 {
		t.Error("crossing-result timeout lost")
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	conn.Close()
}

func TestServiceProbeRunnerV1Fix1WorkerReservationPrecedesRateAndID(t *testing.T) {
	c, r, _, _ := pumpPairFixtureV1(t, nil, false)
	pumpStartPairV1(t, c, r)
	held := 0
	defer func() {
		for range held {
			c.endUseV1()
		}
	}()
	for {
		c.mu.Lock()
		full := c.users == 7+3*len(c.streams)+3*len(c.probes)
		c.mu.Unlock()
		if full {
			break
		}
		if e := c.beginUseV1(true); e != nil {
			t.Fatal(e)
		}
		held++
	}
	request := ProbeRequestV1{7, 1, 1000, 2000, 1}
	if _, e := c.StartProbe(context.Background(), request); e != ServiceResourceLimitV1 {
		t.Error("client worker registration exceeded bound", e)
	}
	c.mu.Lock()
	id, handle := c.nextID, c.nextHandle
	c.mu.Unlock()
	if id != 0 || handle != 0 {
		t.Error("worker-cap refusal consumed identity")
	}
	for held > 0 {
		c.endUseV1()
		held--
	}
	if _, e := c.StartProbe(context.Background(), request); e != nil {
		t.Error("worker refusal spent a probe rate token", e)
	}
}
func TestServiceProbeRunnerV1Fix1RelayWorkerCapacityRepliesResource(t *testing.T) {
	c, r, _, _ := pumpPairFixtureV1(t, nil, false)
	pumpStartPairV1(t, c, r)
	held := 0
	defer func() {
		for range held {
			r.endUseV1()
		}
	}()
	for {
		e := r.beginUseV1(true)
		if e == ServiceResourceLimitV1 {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		held++
	}
	h, e := c.StartProbe(context.Background(), ProbeRequestV1{7, 1, 1000, 2000, 1})
	if e != nil {
		t.Fatal(e)
	}
	a, e := c.AwaitProbe(context.Background(), h)
	if e != ServiceResourceLimitV1 || a.Attempted != 0 {
		t.Error("relay capacity did not fill its reserved refusal", a, e)
	}
}

func TestServiceProbeRunnerV1CompletedResultDoesNotSendStaleReset(t *testing.T) {
	for _, resultSeen := range []bool{false, true} {
		t.Run(map[bool]string{false: "request-still-in-flight", true: "remote-result-received"}[resultSeen], func(t *testing.T) {
			c, _, _, _ := pumpPairFixtureV1(t, nil, false)
			admission, err := c.admitProbeV1(ProbeRequestV1{7, 1, 1000, 2000, 1})
			if err != nil {
				t.Fatal(err)
			}
			c.probes[0] = serviceProbeSlotV1{handle: 1, id: 1, state: 1, admission: admission, sentAt: serviceTestNowV1, resultSeen: resultSeen}
			if err = c.finishProbeV1(0, 1, ServiceResourceLimitV1); err != nil {
				t.Fatal(err)
			}
			g := c.probes[0]
			if g.state != 3 || g.failure != ServiceResourceLimitV1 || g.aggregate.Attempted != 0 {
				t.Fatal("categorical failure or zero-attempt result lost", g.state, g.failure, g.aggregate)
			}
			resets := 0
			for _, q := range c.queue {
				if q.state == 2 && q.opcode == ServiceResetV1 && q.id == 1 {
					resets++
				}
			}
			want := 1
			if resultSeen {
				want = 0
			}
			if resets != want {
				t.Fatalf("reset count=%d, want=%d after resultSeen=%v", resets, want, resultSeen)
			}
		})
	}
}

type pumpGatedDialV1 struct {
	*pumpLocalNetworkV1
	entered, release chan struct{}
}

func (n pumpGatedDialV1) DialTCP(ctx context.Context, a netip.AddrPort) (ServiceTCPConnV1, error) {
	c, e := n.pumpLocalNetworkV1.DialTCP(ctx, a)
	close(n.entered)
	<-n.release
	return c, e
}
func TestServiceProbeRunnerV1ExactBoundaryLateSuccessIsNotAnAttempt(t *testing.T) {
	l, n := pumpLocalListenerV1(t)
	gated := pumpGatedDialV1{n, make(chan struct{}), make(chan struct{})}
	c, r, _, _ := pumpPairFixtureV1(t, gated, false)
	original := c.cfg.Now
	var forced atomic.Int64
	c.cfg.Now = func() time.Time {
		c.BoundsV1()
		if n := forced.Load(); n != 0 {
			return time.Unix(0, n)
		}
		return original()
	}
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h, e := c.StartProbe(ctx, ProbeRequestV1{7, 1, 1000, 2000, 2})
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-gated.entered:
	case <-ctx.Done():
		t.Fatal("actual dial not entered")
	}
	c.mu.Lock()
	deadline := c.probes[0].attemptDeadline
	c.mu.Unlock()
	if deadline.IsZero() {
		t.Fatal("scheduler did not anchor sent deadline")
	}
	forced.Store(deadline.UnixNano())
	close(gated.release)
	a, e := c.AwaitProbe(ctx, h)
	if e != ServiceTimeoutV1 || a.Attempted != 0 || a.HasLatency {
		t.Fatal("boundary success fabricated confirmed sample", a, e)
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	conn.Close()
	time.Sleep(30 * time.Millisecond)
	c.mu.Lock()
	unchanged := c.probes[0].aggregate == a && c.probes[0].sampleCount == 0
	c.mu.Unlock()
	if !unchanged {
		t.Fatal("late result mutated published aggregate")
	}
}

func TestServiceProbeRunnerV1ActualDialAndSharedRate(t *testing.T) {
	l, network := pumpLocalListenerV1(t)
	c, r, _, _ := pumpPairFixtureV1(t, network, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request := ProbeRequestV1{TargetID: 7, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 2000, Samples: 1}
	handle, e := c.StartProbe(ctx, request)
	if e != nil {
		t.Fatal("start", e)
	}
	aggregate, e := c.AwaitProbe(ctx, handle)
	if e != nil || aggregate.Attempted != 1 || !aggregate.HasLatency || aggregate.LossPermille != 0 || aggregate.Path != ProbeActiveRelayEndToEndV1 {
		t.Fatal("actual active result", aggregate, e)
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	conn.Close()
	if _, e = c.StartProbe(ctx, request); !errors.Is(e, ErrProbeRateLimitedV1) {
		t.Fatal("fresh handle bypassed shared rate", e)
	}
}
func TestServiceProbeRunnerV1SerialSamplesRespectRelayRateAfterDelayedRequest(t *testing.T) {
	l, n := pumpLocalListenerV1(t)
	c, r, _, _ := pumpPairFixtureV1(t, n, false)
	gate := &serviceFINWriteGateV1{ReadWriteCloser: c.cfg.Carrier, entered: make(chan struct{}), release: make(chan struct{})}
	c.cfg.Carrier = gate
	var release sync.Once
	defer release.Do(func() { close(gate.release) })
	pumpStartPairV1(t, c, r)
	gate.armed.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h, e := c.StartProbe(ctx, ProbeRequestV1{7, 1, 1000, 4000, 3})
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("first probe did not enter the carrier")
	}
	// The relay spends its own rate token only after this delayed request arrives.
	time.Sleep(200 * time.Millisecond)
	release.Do(func() { close(gate.release) })
	a, e := c.AwaitProbe(ctx, h)
	if e != nil || a.Attempted != 3 || a.LossPermille != 0 {
		r.cfg.ProbeRates.mu.Lock()
		starts := r.cfg.ProbeRates.states[0].state.count
		r.cfg.ProbeRates.mu.Unlock()
		t.Fatal("serial request violated relay spacing", a, e, "relay starts", starts)
	}
	for range 3 {
		conn, e := l.AcceptTCP()
		if e != nil {
			t.Fatal(e)
		}
		conn.Close()
	}
}

func TestServiceProbeRunnerV1SerialSamplesReuseCompletedRelayCapacity(t *testing.T) {
	l, n := pumpLocalListenerV1(t)
	c, r, _, _ := pumpPairFixtureV1(t, n, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h, e := c.StartProbe(ctx, ProbeRequestV1{7, 1, 1000, 4000, 3})
	if e != nil {
		t.Fatal(e)
	}
	a, e := c.AwaitProbe(ctx, h)
	if e != nil || a.Attempted != 3 || a.LossPermille != 0 {
		t.Fatal("serial samples exhausted idle relay slots", a, e)
	}
	for range 3 {
		conn, e := l.AcceptTCP()
		if e != nil {
			t.Fatal(e)
		}
		conn.Close()
	}
}

func TestServiceProbeRunnerV1SerialSpacingDoesNotExtendTotalBudget(t *testing.T) {
	l, n := pumpLocalListenerV1(t)
	c, r, _, _ := pumpPairFixtureV1(t, n, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	h, e := c.StartProbe(ctx, ProbeRequestV1{7, 1, 1000, 1000, 2})
	if e != nil {
		t.Fatal(e)
	}
	a, e := c.AwaitProbe(ctx, h)
	if e != ErrProbeRateLimitedV1 || a.Attempted != 1 || a.LossPermille != 0 {
		t.Fatal("serial spacing changed the total budget", a, e)
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	conn.Close()
}

type pumpDeadlineNetworkV1 struct{ pumpNoNetworkV1 }

func (pumpDeadlineNetworkV1) DialTCP(ctx context.Context, _ netip.AddrPort) (ServiceTCPConnV1, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestServiceProbeRunnerV1NoResultTimeoutExcludesUnconfirmedAttempt(t *testing.T) {
	c, r, _, _ := pumpPairFixtureV1(t, pumpDeadlineNetworkV1{}, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h, e := c.StartProbe(ctx, ProbeRequestV1{7, 1, 1000, 2000, 2})
	if e != nil {
		t.Fatal(e)
	}
	a, e := c.AwaitProbe(ctx, h)
	if e != ServiceTimeoutV1 || a.Attempted != 0 || a.HasLatency {
		t.Fatal("unconfirmed dial fabricated loss", a, e)
	}
}
func TestServiceProbeRunnerV1CancelSuppressesLateDialAndDoneJoinsIt(t *testing.T) {
	l, n := pumpLocalListenerV1(t)
	gated := pumpGatedDialV1{n, make(chan struct{}), make(chan struct{})}
	c, r, _, _ := pumpPairFixtureV1(t, gated, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h, e := c.StartProbe(ctx, ProbeRequestV1{7, 1, 1000, 2000, 2})
	if e != nil {
		t.Fatal(e)
	}
	select {
	case <-gated.entered:
	case <-ctx.Done():
		t.Fatal("dial not entered")
	}
	if e = c.CancelProbe(h); e != nil {
		t.Fatal(e)
	}
	a, e := c.AwaitProbe(ctx, h)
	if e != ServiceCancelledV1 || a.Attempted != 0 || a.HasLatency {
		t.Fatal("cancel fabricated attempt", a, e)
	}
	r.Close()
	select {
	case <-r.Done():
		t.Fatal("Done preceded outstanding dial borrower")
	default:
	}
	close(gated.release)
	select {
	case <-r.Done():
	case <-ctx.Done():
		t.Fatal("dial not joined")
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = conn.Read(make([]byte, 1)); e != io.EOF {
		t.Fatal("late socket not closed", e)
	}
}
func TestServiceProbeRunnerV1RelayDenialDoesNotFabricateAttempts(t *testing.T) {
	c, r, _, _ := pumpPairFixtureV1(t, nil, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request := ProbeRequestV1{7, 1, 1000, 1000, 1}
	admission, e := r.admission.AdmitProbe(request, ProbeActiveRelayV1, 2)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.cfg.ProbeRates.TryStart(r.cfg.ProbeScope, admission, r.cfg.Now()); e != nil {
		t.Fatal(e)
	}
	h, e := c.StartProbe(ctx, request)
	if e != nil {
		t.Fatal(e)
	}
	a, e := c.AwaitProbe(ctx, h)
	if e != ServiceResourceLimitV1 || a.Attempted != 0 || a.HasLatency {
		t.Fatal("wire denial fabricated attempt or precise rate cause", a, e)
	}
}
