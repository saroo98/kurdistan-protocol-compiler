// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"kurdistan/internal/product/runtimepolicy"
	"sync"
	"testing"
	"time"
)

type productionWriteGateV1 struct {
	io.ReadWriteCloser
	entered, release chan struct{}
	once             sync.Once
}

func (g *productionWriteGateV1) Write(b []byte) (int, error) {
	g.once.Do(func() { close(g.entered); <-g.release })
	return g.ReadWriteCloser.Write(b)
}

func TestProductionPacketAdmissionV1SourceQueueAndCarrierHoldReference(t *testing.T) {
	c, r, cp, rp := pumpPairFixtureV1(t, nil, false)
	f, e := newProductionFlowTableV1(1, 0, time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	a := &productionPacketAdmissionV1{generation: 1, raw: true, now: c.lastNow, flow: f, mtu: c.mtu, client4: c.client4, dns4: c.dns4, client6: c.client6, dns6: c.dns6, protocols: c.protocols, protocolCount: c.protocolCount}
	cp.production = a
	c.production = a
	// Bind before installing the actual carrier-write gate.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	bound := make(chan error, 1)
	go func() { bound <- r.BindV1(ctx, [32]byte{1}) }()
	if e = c.BindV1(ctx, [32]byte{1}); e != nil {
		t.Fatal(e)
	}
	if e = <-bound; e != nil {
		t.Fatal(e)
	}
	gate := &productionWriteGateV1{ReadWriteCloser: c.cfg.Carrier, entered: make(chan struct{}), release: make(chan struct{})}
	c.cfg.Carrier = gate
	var release sync.Once
	t.Cleanup(func() {
		release.Do(func() { close(gate.release) })
		c.Close()
		r.Close()
		<-c.Done()
		<-r.Done()
		cp.joinV1()
		f.destroyV1()
	})
	go c.Run(context.Background())
	go r.Run(context.Background())
	// Wait on the port's concrete admission publication rather than scheduler timing.
	cp.mu.Lock()
	for {
		a.mu.Lock()
		active := a.active
		a.mu.Unlock()
		if active {
			break
		}
		cp.waitV1(ctx)
		if ctx.Err() != nil {
			cp.mu.Unlock()
			t.Fatal("run publication")
		}
	}
	cp.mu.Unlock()
	packet := testIPv4TCPPacketV1(c.client4, [4]byte{1, 1, 1, 1}, 12345, 443, 0x10, []byte{1})
	if e = cp.Submit(ctx, packet); e != nil {
		t.Fatal(e)
	}
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("carrier gate")
	}
	c.mu.Lock()
	ref := c.queue[c.head].flow
	state := c.queue[c.head].state
	c.mu.Unlock()
	if state != 3 || ref.index == 0 {
		t.Fatal("reference did not reach actual TX")
	}
	a.mu.Lock()
	a.now = a.now.Add(time.Second)
	a.mu.Unlock()
	other := testIPv4TCPPacketV1(c.client4, [4]byte{1, 1, 1, 1}, 12346, 443, 0x10, []byte{1})
	if e = cp.Submit(ctx, other); !errors.Is(e, ServiceResourceLimitV1) {
		t.Fatal("blocked write lost flow ownership", e)
	}
	release.Do(func() { close(gate.release) })
	buf := make([]byte, 1280)
	token, n, e := rp.Receive(ctx, buf)
	if e != nil {
		t.Fatal(e)
	}
	if e = rp.Acknowledge(ctx, token, n, nil); e != nil {
		t.Fatal(e)
	}
	c.Close()
	r.Close()
	<-c.Done()
	<-r.Done()
	cp.joinV1()
	f.mu.Lock()
	for _, entry := range f.entries {
		if entry.references != 0 {
			f.mu.Unlock()
			t.Fatal("joined pump leaked reference")
		}
	}
	f.mu.Unlock()
}

func productionPortFixtureV1(t *testing.T, tcp, udp uint16) (*PacketPortV1, *productionPacketAdmissionV1) {
	t.Helper()
	port, e := NewPacketPortV1(1280)
	if e != nil {
		t.Fatal(e)
	}
	f, e := newProductionFlowTableV1(tcp, udp, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	a := &productionPacketAdmissionV1{generation: 1, raw: true, active: true, now: time.Now(), flow: f, mtu: 1280, client4: [4]byte{10, 89, 0, 2}, dns4: [4]byte{10, 89, 0, 1}, protocolCount: 4, protocols: [4]runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolTCP, runtimepolicy.PayloadProtocolUDP, runtimepolicy.PayloadProtocolICMP, runtimepolicy.PayloadProtocolICMPv6}}
	port.production = a
	t.Cleanup(func() { port.Close(); port.joinV1(); f.destroyV1() })
	return port, a
}

func productionTCPPacketV1(port uint16) []byte {
	tcp := make([]byte, 20)
	tcp[0], tcp[1], tcp[2], tcp[3], tcp[12] = byte(port>>8), byte(port), 0, 80, 0x50
	return testIPv4PacketV1([4]byte{10, 89, 0, 2}, [4]byte{1, 1, 1, 1}, 6, tcp)
}

func TestProductionPacketAdmissionV1BeforeCopyAndReferenceTransfer(t *testing.T) {
	p, a := productionPortFixtureV1(t, 1, 0)
	ctx := context.Background()
	packet := productionTCPPacketV1(1)
	if e := p.Submit(ctx, packet); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Read(make([]byte, 1280)); !errors.Is(e, ServiceInvalidRequestV1) {
		t.Fatal("alternate reader stole reference", e)
	}
	if _, r, e := p.readProductionV1(make([]byte, len(packet)-1), a); !errors.Is(e, io.ErrShortBuffer) || r != (productionFlowRefV1{}) {
		t.Fatal("short transfer", e)
	}
	output := make([]byte, 1280)
	n, r, e := p.readProductionV1(output, a)
	if e != nil || n != len(packet) || r.index == 0 || !bytes.Equal(output[:n], packet) {
		t.Fatal("transfer", e)
	}
	if e = p.Submit(ctx, productionTCPPacketV1(2)); !errors.Is(e, ServiceResourceLimitV1) || p.outBytes != 0 {
		t.Fatal("reference was released by Read", e)
	}
	a.flow.releaseV1(r)
	udp := testIPv4PacketV1(a.client4, a.dns4, 17, []byte{0, 1, 0, 53, 0, 8, 0, 0})
	if e = p.Submit(ctx, udp); !errors.Is(e, ServiceResourceLimitV1) || p.outBytes != 0 {
		t.Fatal("UDP zero DNS bypass", e)
	}
	bad := productionTCPPacketV1(1)
	bad[32] = 0x40
	if e = p.Submit(ctx, bad); !errors.Is(e, ErrPacketInvalid) || p.outBytes != 0 {
		t.Fatal("malformed copied", e)
	}
	a.mu.Lock()
	a.active = false
	a.mu.Unlock()
	if e = p.Submit(ctx, packet); !errors.Is(e, ServiceInvalidRequestV1) {
		t.Fatal("dormant admission", e)
	}
	a.mu.Lock()
	a.active = true
	a.raw = false
	a.mu.Unlock()
	if e = p.Submit(ctx, packet); !errors.Is(e, ServiceNotAdmittedV1) || p.outBytes != 0 {
		t.Fatal("proxy-only raw copied", e)
	}
}

func TestProductionPacketAdmissionV1CancelledPortWaitRetainsOnlyExistingReference(t *testing.T) {
	p, a := productionPortFixtureV1(t, 1, 0)
	if e := p.Submit(context.Background(), productionTCPPacketV1(1)); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait := &pumpWaitContextV1{Context: ctx, waited: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- p.Submit(wait, productionTCPPacketV1(2)) }()
	t.Cleanup(func() { cancel(); p.Close(); p.joinV1() })
	select {
	case <-wait.waited:
	case <-time.After(time.Second):
		t.Fatal("full-port wait not reached")
	}
	if e := p.Submit(context.Background(), productionTCPPacketV1(3)); !errors.Is(e, ErrPacketPortBusy) {
		t.Fatal("concurrent submit", e)
	}
	p.mu.Lock()
	original := p.outFlow
	unchanged := bytes.Equal(p.outbound[:p.outBytes], productionTCPPacketV1(1))
	p.mu.Unlock()
	if original.index == 0 || !unchanged {
		t.Fatal("waiting submit changed the existing slot")
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled submit did not join")
	}
	p.Close()
	p.joinV1()
	if _, e := a.flow.reserveV1(productionFlowKeyFixtureV1(6, 3), a.now); e != nil {
		t.Fatal("port close leaked reference", e)
	}
}

func TestProductionPacketAdmissionV1SourceWaitPinsReferenceUntilJoinedCancel(t *testing.T) {
	c, _, cp, _ := pumpPairFixtureV1(t, nil, false)
	f, e := newProductionFlowTableV1(1, 0, time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	a := &productionPacketAdmissionV1{generation: 1, raw: true, active: true, now: c.lastNow, flow: f, mtu: c.mtu, client4: c.client4, dns4: c.dns4, client6: c.client6, dns6: c.dns6, protocols: c.protocols, protocolCount: c.protocolCount}
	cp.production, c.production = a, a
	wait := &pumpWaitContextV1{Context: c.ctx, waited: make(chan struct{})}
	c.ctx = wait
	c.mu.Lock()
	_, e = c.reserveV1(context.Background(), c.deadline, true)
	registration := c.reserveUsesLockedV1(1)
	c.mu.Unlock()
	if e != nil || registration != nil {
		t.Fatal("source gate setup", e, registration)
	}
	t.Cleanup(func() { c.Close(); <-c.Done(); cp.joinV1(); f.destroyV1() })
	go c.workerV1(c.packetSourceV1)
	packet := testIPv4TCPPacketV1(c.client4, [4]byte{1, 1, 1, 1}, 12345, 443, 0x10, nil)
	if e = cp.Submit(context.Background(), packet); e != nil {
		t.Fatal(e)
	}
	select {
	case <-wait.waited:
	case <-time.After(time.Second):
		t.Fatal("source did not wait for K")
	}
	cp.mu.Lock()
	empty := cp.outBytes == 0 && cp.outFlow.index == 0
	cp.mu.Unlock()
	if !empty {
		t.Fatal("source did not transfer port reference")
	}
	a.mu.Lock()
	a.now = a.now.Add(time.Second)
	a.mu.Unlock()
	other := testIPv4TCPPacketV1(c.client4, [4]byte{1, 1, 1, 1}, 12346, 443, 0x10, nil)
	if e = cp.Submit(context.Background(), other); !errors.Is(e, ServiceResourceLimitV1) {
		t.Fatal("source-local reference expired", e)
	}
	c.Close()
	<-c.Done()
	cp.joinV1()
	f.mu.Lock()
	for _, entry := range f.entries {
		if entry.references != 0 {
			f.mu.Unlock()
			t.Fatal("source cancellation leaked reference")
		}
	}
	f.mu.Unlock()
}

func TestProductionPacketAdmissionV1ReturnRefreshRequiresAuthenticatedCommit(t *testing.T) {
	for _, scenario := range []string{"commit", "short-ack", "discard", "stale-generation"} {
		t.Run(scenario, func(t *testing.T) { testProductionReturnCompletionV1(t, scenario) })
	}
}

func testProductionReturnCompletionV1(t *testing.T, scenario string) {
	c, r, cp, _ := pumpPairFixtureV1(t, nil, false)
	f, e := newProductionFlowTableV1(1, 0, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	a := &productionPacketAdmissionV1{generation: 1, raw: true, active: true, now: c.lastNow, flow: f, mtu: c.mtu, client4: c.client4, dns4: c.dns4, client6: c.client6, dns6: c.dns6, protocols: c.protocols, protocolCount: c.protocolCount}
	cp.production = a
	c.production = a
	t.Cleanup(func() {
		c.Close()
		r.Close()
		<-c.Done()
		<-r.Done()
		cp.joinV1()
		f.destroyV1()
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	bound := make(chan error, 1)
	go func() { bound <- r.BindV1(ctx, [32]byte{1}) }()
	if e = c.BindV1(ctx, [32]byte{1}); e != nil {
		t.Fatal(e)
	}
	if e = <-bound; e != nil {
		t.Fatal(e)
	}
	out := testIPv4TCPPacketV1(c.client4, [4]byte{1, 1, 1, 1}, 12345, 443, 0x10, nil)
	info, e := effectivePacketInfoV1(out, true, c.mtu, c.client4, c.dns4, c.client6, c.dns6, c.protocols[:c.protocolCount])
	if e != nil {
		t.Fatal(e)
	}
	key, _, _ := productionFlowTupleV1(out, info, false)
	ref, e := f.reserveV1(key, c.lastNow)
	if e != nil {
		t.Fatal(e)
	}
	f.acceptV1(ref, c.lastNow)
	f.releaseV1(ref)
	initial := c.lastNow
	c.lastNow = initial.Add(time.Second / 2)
	in := testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, c.client4, 443, 12345, 0x10, []byte{9})
	record, e := r.endpoint.SealDataV3(in, 2, 3)
	if e != nil {
		t.Fatal(e)
	}
	pending, e := c.endpoint.OpenFrameV3(record)
	if e != nil {
		t.Fatal(e)
	}
	type consumed struct {
		receipt productionReturnReceiptV1
		err     error
	}
	done := make(chan consumed, 1)
	joined := false
	go func() { receipt, err := c.consumeFrameV1(pending); done <- consumed{receipt, err} }()
	t.Cleanup(func() {
		cp.Close()
		if !joined {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("consumer cleanup did not join")
			}
		}
	})
	buf := make([]byte, 1280)
	token, n, e := cp.Receive(ctx, buf)
	if e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	before := f.entries[ref.index-1].activity
	f.mu.Unlock()
	if before != initial {
		t.Fatal("unacknowledged delivery refreshed")
	}
	ackCount := n
	if scenario == "short-ack" {
		ackCount--
	}
	if e = cp.Acknowledge(ctx, token, ackCount, nil); e != nil && scenario != "short-ack" {
		t.Fatal(e)
	}
	var got consumed
	select {
	case got = <-done:
		joined = true
	case <-ctx.Done():
		t.Fatal("consume join")
	}
	if scenario == "short-ack" {
		if got.err == nil {
			t.Fatal("short acknowledgment accepted")
		}
		pending.Discard()
		f.mu.Lock()
		after := f.entries[ref.index-1].activity
		f.mu.Unlock()
		if after != initial {
			t.Fatal("failed destination refreshed flow")
		}
		return
	}
	if got.err != nil || got.receipt.flow != ref {
		t.Fatal("receipt lost before slab clear", got.err)
	}
	if !bytes.Equal(c.rx, make([]byte, len(c.rx))) {
		t.Fatal("RX slab not cleared")
	}
	f.mu.Lock()
	before = f.entries[ref.index-1].activity
	f.mu.Unlock()
	if before != initial {
		t.Fatal("Write alone refreshed")
	}
	if scenario == "discard" {
		pending.Discard()
		if e = pending.Commit(); e == nil {
			t.Fatal("discarded record committed")
		}
		f.mu.Lock()
		after := f.entries[ref.index-1].activity
		f.mu.Unlock()
		if after != initial {
			t.Fatal("failed commit refreshed flow")
		}
		return
	}
	if scenario == "stale-generation" {
		c.lastNow = initial.Add(2 * time.Second)
		next, err := f.reserveV1(key, c.lastNow)
		if err != nil || next == ref {
			t.Fatal("flow generation did not retire", err)
		}
		f.acceptV1(next, c.lastNow)
		f.releaseV1(next)
		c.lastNow = initial.Add(2500 * time.Millisecond)
	}
	if e = pending.Commit(); e != nil {
		t.Fatal(e)
	}
	c.commitProductionReturnV1(got.receipt)
	f.mu.Lock()
	after := f.entries[ref.index-1].activity
	f.mu.Unlock()
	if scenario == "stale-generation" {
		if after != initial.Add(2*time.Second) {
			t.Fatal("stale receipt refreshed replacement")
		}
	} else if after != c.lastNow {
		t.Fatal("successful replay commit did not refresh")
	}
}

func TestProductionPumpV1ProxyOnlyRejectsAuthenticatedRawBeforeDestination(t *testing.T) {
	c, r, cp, rp := pumpPairFixtureV1(t, nil, false)
	a := &productionPacketAdmissionV1{generation: 1, raw: false, now: c.lastNow, mtu: c.mtu}
	c.production = a
	cp.production = a
	c.packetScratch = nil
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c.mu.Lock()
	users := c.users
	c.mu.Unlock()
	if users != 4 {
		t.Fatal("proxy-only launched raw source", users)
	}
	in := testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, c.client4, 443, 12345, 0x10, []byte{1})
	if e := rp.Submit(ctx, in); e != nil {
		t.Fatal(e)
	}
	select {
	case <-c.Done():
	case <-ctx.Done():
		t.Fatal("raw authenticated receive was not rejected")
	}
	c.mu.Lock()
	reason := c.reason
	c.mu.Unlock()
	if !errors.Is(reason, ServiceNotAdmittedV1) {
		t.Fatal("proxy-only raw reason", reason)
	}
	if c.BoundsV1().PacketsProcessed != 0 {
		t.Fatal("raw destination consumed")
	}
}

func TestProductionPumpV1TUNOnlyRejectsStreamBeforeAdmission(t *testing.T) {
	c, _, _, _ := pumpPairFixtureV1(t, nil, false)
	c.production = &productionPacketAdmissionV1{generation: 1, raw: true}
	c.streams = nil
	if _, e := c.admitProxyV1(ProxyRequestV1{Kind: 1, Address: []byte{1, 1, 1, 1}, Port: 443}); !errors.Is(e, ServiceNotAdmittedV1) {
		t.Fatal("signed proxy implicitly enabled local service", e)
	}
}
