// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The context exposes the actual queue wait, without a production test hook.
type pumpWaitContextV1 struct {
	context.Context
	waited chan struct{}
	once   sync.Once
}

func (c *pumpWaitContextV1) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waited) })
	return c.Context.Done()
}
func pumpWaitUntilV1(t testing.TB, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("bounded condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}
func pumpHoldQueueV1(t testing.TB, p *ServicePumpV1) func() {
	t.Helper()
	pumpWaitUntilV1(t, func() bool { return p.BoundsV1().QueueUsed == 0 })
	p.mu.Lock()
	i, e := p.reserveV1(context.Background(), p.deadline, true)
	p.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	return func() { p.mu.Lock(); p.queue[i].state = 4; p.notifyLockedV1(); p.mu.Unlock() }
}
func pumpSendControlV1(t testing.TB, p *ServicePumpV1, id uint32, op ServiceOpcodeV1, body []byte) {
	t.Helper()
	p.mu.Lock()
	_, e := p.queueControlLockedV1(context.Background(), id, op, body, 0, p.deadline)
	p.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
}

func TestServiceStreamV1CancelAfterConfirmedDeliveryDoesNotAbortSession(t *testing.T) {
	c, _, _, _ := pumpPairFixtureV1(t, nil, false)
	// Reproduce the interval after acknowledgement but before the RX owner
	// clears its delivery slot. No receiver goroutine can race this setup.
	c.mu.Lock()
	c.streams[0].id = 1
	c.streams[0].state = 2
	c.delivery.id = 1
	c.delivery.token = 7
	c.delivery.length = 2
	c.delivery.received = true
	c.delivery.deadline = c.deadline
	c.mu.Unlock()
	if err := c.markStreamDeliveryV1(1, 7, 2); err != nil {
		t.Fatal(err)
	}
	if err := c.cancelStreamV1(1, ServiceCancelledV1); err != nil {
		t.Fatalf("closing an acknowledged stream aborted the session: %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal || c.streams[0].state != 3 || !c.delivery.confirmed {
		t.Fatal("stream cancellation lost acknowledged delivery or terminated the session")
	}
}

type pumpPausedWaitContextV1 struct {
	context.Context
	waited chan struct{}
	resume chan struct{}
}

func (c *pumpPausedWaitContextV1) Done() <-chan struct{} {
	close(c.waited)
	<-c.resume
	return c.Context.Done()
}

func TestServiceStreamV1AcknowledgedDeliverySurvivesCloseBeforeReceiverWakes(t *testing.T) {
	c, _, _, _ := pumpPairFixtureV1(t, nil, false)
	gate := &pumpPausedWaitContextV1{context.Background(), make(chan struct{}), make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(gate.resume) })
	c.ctx = gate
	c.streams[0].id, c.streams[0].state = 1, 2
	c.delivery.deadline = c.deadline
	var raw [10]byte
	n, err := c.codec.Encode(raw[:], ServiceRecordViewV1{Opcode: ServiceDataV1, ID: 1, Body: []byte{42, 43}}, ServiceRelayToClientV1, 0)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		consumed := false
		err := c.consumeServiceV1(raw[:n], &consumed)
		if err == nil && !consumed {
			err = fmt.Errorf("acknowledged bytes not consumed")
		}
		result <- err
	}()
	select {
	case <-gate.waited:
	case <-time.After(2 * time.Second):
		t.Fatal("receiver did not wait for acknowledgement")
	}
	c.mu.Lock()
	c.delivery.received, c.delivery.token = true, 7
	c.mu.Unlock()
	if err := c.markStreamDeliveryV1(1, 7, 2); err != nil {
		t.Fatal(err)
	}
	if err := c.cancelStreamV1(1, ServiceCancelledV1); err != nil {
		t.Fatal(err)
	}
	release.Do(func() { close(gate.resume) })
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("completed delivery rejected after stream close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("receiver did not finish")
	}
}

func TestServiceStreamV1NativeFenceRejectsMisuse(t *testing.T) {
	for _, fault := range []string{"repeated", "missing", "short", "stale", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			listener, network := pumpLocalListenerV1(t)
			c, r, _, _ := pumpPairFixtureV1(t, network, false)
			pumpStartPairV1(t, c, r)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			id, err := c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err = conn.Write([]byte{1, 2}); err != nil {
				t.Fatal(err)
			}
			token, n, err := c.ReceiveStream(ctx, id, make([]byte, 2))
			if err != nil {
				t.Fatal(err)
			}
			if fault == "short" {
				n--
			}
			if fault == "stale" {
				token++
			}
			err = c.ConfirmStreamDeliveryFencedV1(id, token, n, func(commit func() error) error {
				if fault == "missing" {
					return nil
				}
				if fault == "cancelled" {
					return ServiceCancelledV1
				}
				result := commit()
				if fault == "repeated" {
					_ = commit()
				}
				return result
			})
			if err == nil {
				t.Fatal("misused fence returned success")
			}
			select {
			case <-c.Done():
			case <-ctx.Done():
				t.Fatal("fence cancellation did not join")
			}
		})
	}
}

type serviceFINWriteGateV1 struct {
	io.ReadWriteCloser
	armed            atomic.Bool
	entered, release chan struct{}
	once             sync.Once
}

func (g *serviceFINWriteGateV1) Write(b []byte) (int, error) {
	if g.armed.Load() {
		g.once.Do(func() { close(g.entered); <-g.release })
	}
	return g.ReadWriteCloser.Write(b)
}

func TestServiceStreamV1NativeFencedConfirmationAndActualRetirement(t *testing.T) {
	l, network := pumpLocalListenerV1(t)
	c, r, _, _ := pumpPairFixtureV1(t, network, false)
	gate := &serviceFINWriteGateV1{ReadWriteCloser: c.cfg.Carrier, entered: make(chan struct{}), release: make(chan struct{})}
	c.cfg.Carrier = gate
	var release sync.Once
	releaseFIN := func() { release.Do(func() { close(gate.release) }) }
	defer releaseFIN()
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	id, e := c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
	if e != nil {
		t.Fatal(e)
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if retired, e := c.StreamRetiredV1(id); retired || e != nil {
		t.Fatal("live retired", retired, e)
	}
	for _, bad := range []uint32{0, id + 1} {
		if _, e := c.StreamRetiredV1(bad); e == nil {
			t.Fatal("unissued retirement", bad)
		}
	}
	if _, e = conn.Write([]byte{7, 8}); e != nil {
		t.Fatal(e)
	}
	var out [2]byte
	token, n, e := c.ReceiveStream(ctx, id, out[:])
	if e != nil || n != 2 {
		t.Fatal("receive", n, e)
	}
	var escaped func() error
	if e = c.ConfirmStreamDeliveryFencedV1(id, token, n, func(commit func() error) error { escaped = commit; return commit() }); e != nil {
		t.Fatal("fenced exact acknowledgment", e)
	}
	if e = escaped(); e == nil {
		t.Fatal("escaped commit remained usable")
	}
	gate.armed.Store(true)
	if e = c.CloseWrite(ctx, id); e != nil {
		t.Fatal(e)
	}
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("FIN did not enter carrier")
	}
	if e = conn.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	if _, _, e = c.ReceiveStream(ctx, id, out[:]); e != io.EOF {
		t.Fatal("true half close", e)
	}
	if retired, e := c.StreamRetiredV1(id); retired || e != nil {
		t.Fatal("retired before queued FIN drained", retired, e)
	}
	releaseFIN()
	pumpWaitUntilV1(t, func() bool {
		retired, err := c.StreamRetiredV1(id)
		if err != nil {
			t.Fatal(err)
		}
		return retired
	})
}
func TestServiceStreamV1Fix1CloseReservationExcludesOtherCloserAndWriter(t *testing.T) {
	for _, writer := range []bool{false, true} {
		t.Run(fmt.Sprint(writer), func(t *testing.T) {
			l, network := pumpLocalListenerV1(t)
			c, r, _, _ := pumpPairFixtureV1(t, network, false)
			pumpStartPairV1(t, c, r)
			id, e := c.OpenStream(context.Background(), ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
			if e != nil {
				t.Fatal(e)
			}
			conn, e := l.AcceptTCP()
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			release := pumpHoldQueueV1(t, c)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			wait := &pumpWaitContextV1{Context: ctx, waited: make(chan struct{})}
			first := make(chan error, 1)
			go func() { first <- c.CloseWrite(wait, id) }()
			select {
			case <-wait.waited:
			case <-ctx.Done():
				t.Fatal("closer did not wait")
			}
			second := make(chan error, 1)
			go func() {
				if writer {
					_, e := c.WriteStream(ctx, id, []byte{1})
					second <- e
				} else {
					second <- c.CloseWrite(ctx, id)
				}
			}()
			select {
			case e := <-second:
				if e != ErrAuthenticatedFrameState {
					t.Error("overlapping transition not refused", e)
				}
			case <-time.After(50 * time.Millisecond):
				t.Error("closing transition was not reserved before queue wait")
			}
			release()
			if e := <-first; e != nil {
				t.Error(e)
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			if n, e := conn.Read(make([]byte, 1)); n != 0 || e != io.EOF {
				t.Error("FIN did not preserve data ordering", n, e)
			}
		})
	}
}
func TestServiceStreamV1Fix1CancelledPublicWriteRetiresReservation(t *testing.T) {
	l, network := pumpLocalListenerV1(t)
	c, r, _, _ := pumpPairFixtureV1(t, network, false)
	pumpStartPairV1(t, c, r)
	id, e := c.OpenStream(context.Background(), ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
	if e != nil {
		t.Fatal(e)
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	release := pumpHoldQueueV1(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wait := &pumpWaitContextV1{Context: ctx, waited: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		n, e := c.WriteStream(wait, id, []byte{1})
		if n != 0 {
			result <- fmt.Errorf("cancelled write reported %d bytes", n)
		} else {
			result <- e
		}
	}()
	select {
	case <-wait.waited:
	case <-ctx.Done():
		t.Fatal("write did not wait")
	}
	var body [2]byte
	binary.BigEndian.PutUint16(body[:], uint16(ServiceCancelledV1))
	pumpSendControlV1(t, r, id, ServiceResetV1, body[:])
	pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.streams[0].state == 3 })
	release()
	select {
	case e := <-result:
		if e != ErrAuthenticatedFrameState {
			t.Error("stale write admission", e)
		}
	case <-ctx.Done():
		t.Fatal("writer did not exit")
	}
	pumpWaitUntilV1(t, func() bool { return c.BoundsV1().QueueUsed == 0 })
}

func TestServiceStreamV1Fix1AdmittedConfirmationCannotOutrunRevocation(t *testing.T) {
	l, network := pumpLocalListenerV1(t)
	c, r, _, _ := pumpPairFixtureV1(t, network, false)
	pumpStartPairV1(t, c, r)
	id, e := c.OpenStream(context.Background(), ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
	if e != nil {
		t.Fatal(e)
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if _, e = conn.Write([]byte{1}); e != nil {
		t.Fatal(e)
	}
	token, n, e := c.ReceiveStream(context.Background(), id, make([]byte, 1))
	if e != nil {
		t.Fatal(e)
	}
	// Split only at the real admitted-use/final-publication boundary. The held
	// public use prevents cleanup from erasing the still-valid delivery token.
	if e = c.beginUseV1(true); e != nil {
		t.Fatal(e)
	}
	defer c.endUseV1()
	admitted, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() { close(admitted); <-release; result <- c.confirmStreamDeliveryV1(id, token, n) }()
	<-admitted
	c.CancelWithReason(ServiceAuthorityRevokedV1)
	close(release)
	if e = <-result; e != ServiceAuthorityRevokedV1 {
		t.Error("confirmation published after revocation", e)
	}
	c.mu.Lock()
	confirmed := c.delivery.confirmed
	c.mu.Unlock()
	if confirmed {
		t.Error("terminal delivery was confirmed")
	}
}

type pumpTimeoutNetworkV1 struct {
	pumpNoNetworkV1
	entered, release chan struct{}
}

// Gate real socket cleanup at Close entry, preserving its operation context.
type pumpCleanupNetworkV1 struct {
	*pumpLocalNetworkV1
	dialEntered               chan context.Context
	dialRelease, closeRelease chan struct{}
	closeEntered              chan error
	dialErr                   error
	calls                     atomic.Int32
}
type pumpCleanupConnV1 struct {
	ServiceTCPConnV1
	ctx     context.Context
	entered chan error
	release chan struct{}
}

// Model a deadline whose cancellation notification has not been scheduled yet.
type pumpDelayedTimerContextV1 struct {
	context.Context
	deadline time.Time
}

func (c pumpDelayedTimerContextV1) Deadline() (time.Time, bool) { return c.deadline, true }

func (c pumpCleanupConnV1) Close() error {
	c.entered <- c.ctx.Err()
	<-c.release
	return c.ServiceTCPConnV1.Close()
}
func (n *pumpCleanupNetworkV1) ResolveProxy(_ context.Context, _ []byte, out *[16]netip.Addr) (int, error) {
	out[0], out[1] = netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")
	return 2, nil
}
func (n *pumpCleanupNetworkV1) DialTCP(ctx context.Context, address netip.AddrPort) (ServiceTCPConnV1, error) {
	call := n.calls.Add(1)
	c, e := n.pumpLocalNetworkV1.DialTCP(ctx, address)
	if e != nil {
		return nil, e
	}
	n.dialEntered <- ctx
	<-n.dialRelease
	if call > 1 {
		return c, nil
	}
	return pumpCleanupConnV1{c, ctx, n.closeEntered, n.closeRelease}, n.dialErr
}

func TestServiceStreamV1Fix2CompletedCleanupCancelsBeforeClose(t *testing.T) {
	for _, scenario := range []string{"trusted-deadline", "last-failure", "live-fallback", "real-deadline-fallback", "authority", "retired"} {
		t.Run(scenario, func(t *testing.T) {
			_, local := pumpLocalListenerV1(t)
			n := &pumpCleanupNetworkV1{pumpLocalNetworkV1: local, dialEntered: make(chan context.Context, 2), dialRelease: make(chan struct{}), closeEntered: make(chan error, 2), closeRelease: make(chan struct{})}
			if scenario == "last-failure" || scenario == "live-fallback" || scenario == "real-deadline-fallback" {
				n.dialErr = ServiceUnreachableV1
			}
			_, r, _, _ := pumpPairFixtureV1(t, n, false)
			leaf, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var operation context.Context = leaf
			if scenario == "real-deadline-fallback" {
				operation = pumpDelayedTimerContextV1{leaf, time.Now().Add(50 * time.Millisecond)}
			}
			request := ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443}
			if scenario == "live-fallback" || scenario == "real-deadline-fallback" {
				request = ProxyRequestV1{2, []byte("example.com"), 443}
			}
			request, e := r.admitProxyV1(request)
			if e != nil {
				t.Fatal(e)
			}
			r.mu.Lock()
			deadline := r.lastNow.Add(time.Second)
			qi, e := r.reserveV1(leaf, r.deadline, false)
			if e != nil {
				r.mu.Unlock()
				t.Fatal(e)
			}
			r.queue[qi].id = 1
			r.streams[0] = serviceStreamSlotV1{id: 1, state: 1, request: request, deadline: deadline, worker: true, cancel: cancel, responseQueue: qi, responseSerial: r.queue[qi].serial}
			r.reserveUsesLockedV1(1)
			r.mu.Unlock()
			go r.workerV1(func() error { return r.streamWorkerV1(0, 1, operation) })
			<-n.dialEntered
			if scenario == "real-deadline-fallback" {
				realDeadline, _ := operation.Deadline()
				<-time.After(time.Until(realDeadline) + time.Millisecond)
			}
			if leaf.Err() != nil {
				t.Fatal("real timer expired before gated cleanup")
			}
			if scenario == "trusted-deadline" {
				r.cfg.Now = func() time.Time { return deadline }
			}
			if scenario == "authority" {
				r.cfg.CheckAuthority = func(time.Time) error { return ServiceAuthorityRevokedV1 }
			}
			if scenario == "retired" {
				r.mu.Lock()
				r.streams[0].state = 3
				r.mu.Unlock()
			}
			close(n.dialRelease)
			entryErr := <-n.closeEntered
			if scenario == "live-fallback" {
				if entryErr != nil {
					t.Error("failed first candidate canceled valid fallback", entryErr)
				}
			} else if entryErr != context.Canceled {
				t.Error("completed stream Close entered before explicit cancel", entryErr)
			}
			close(n.closeRelease)
			if scenario == "live-fallback" {
				select {
				case next := <-n.dialEntered:
					if next.Err() != nil {
						t.Error("second candidate inherited canceled operation")
					}
				case <-time.After(time.Second):
					t.Fatal("second candidate not tried")
				}
				pumpWaitUntilV1(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.streams[0].state == 2 })
			} else {
				pumpWaitUntilV1(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return len(r.streams) == 0 || !r.streams[0].worker })
				if scenario == "trusted-deadline" || scenario == "last-failure" || scenario == "real-deadline-fallback" {
					r.mu.Lock()
					result := r.streams[0].result
					r.mu.Unlock()
					want := ServiceTimeoutV1
					if scenario == "last-failure" {
						want = ServiceUnreachableV1
					}
					if result != want {
						t.Error("stream cleanup changed outcome", result, want)
					}
					if scenario == "real-deadline-fallback" && n.calls.Load() != 1 {
						t.Error("expired operation tried a second candidate")
					}
				}
			}
		})
	}
}

type pumpArmedWaitContextV1 struct {
	context.Context
	armed  atomic.Bool
	waited chan struct{}
	once   sync.Once
}

func (c *pumpArmedWaitContextV1) Done() <-chan struct{} {
	if c.armed.Load() {
		c.once.Do(func() { close(c.waited) })
	}
	return c.Context.Done()
}
func TestServiceStreamV1Fix1CancelledRelayReadHeadRetiresReservation(t *testing.T) {
	l, network := pumpLocalListenerV1(t)
	c, r, cp, rp := pumpPairFixtureV1(t, network, false)
	wait := &pumpArmedWaitContextV1{Context: r.ctx, waited: make(chan struct{})}
	r.ctx = wait
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	id, e := c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
	if e != nil {
		t.Fatal(e)
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	packet := testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, [4]byte{10, 77, 0, 2}, 443, 12345, 0x10, nil)
	if e = rp.Submit(ctx, packet); e != nil {
		t.Fatal(e)
	}
	token, n, e := cp.Receive(ctx, make([]byte, 1280))
	if e != nil {
		t.Fatal(e)
	}
	if e = rp.Submit(ctx, packet); e != nil {
		t.Fatal(e)
	}
	pumpWaitUntilV1(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.used == 1 && r.queue[r.head].state == 3 })
	// TX is blocked on the second packet, RX on carrier, source on PacketPort.
	// Only the completed destination read now reaches the root-context queue wait.
	wait.armed.Store(true)
	if _, e = conn.Write([]byte{1, 2, 3}); e != nil {
		t.Fatal(e)
	}
	select {
	case <-wait.waited:
	case <-ctx.Done():
		t.Fatal("relay read head did not wait")
	}
	pumpSendControlV1(t, c, id, ServiceResetV1, []byte{0, 7})
	pumpWaitUntilV1(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.streams[0].state == 3 })
	if e = cp.Acknowledge(ctx, token, n, nil); e != nil {
		t.Fatal(e)
	}
	for {
		token, n, e = cp.Receive(ctx, make([]byte, 1280))
		if e != ErrPacketPortBusy {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	if e = cp.Acknowledge(ctx, token, n, nil); e != nil {
		t.Fatal(e)
	}
	pumpWaitUntilV1(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return !r.streams[0].worker && r.used == 0 })
	c.mu.Lock()
	stale := c.delivery.id == id && c.delivery.length != 0
	c.mu.Unlock()
	if stale {
		t.Fatal("cancelled relay read published new DATA")
	}
}
func (n pumpTimeoutNetworkV1) ResolveProxy(context.Context, []byte, *[16]netip.Addr) (int, error) {
	close(n.entered)
	<-n.release
	return 0, context.DeadlineExceeded
}
func (n pumpTimeoutNetworkV1) DialTCP(context.Context, netip.AddrPort) (ServiceTCPConnV1, error) {
	close(n.entered)
	<-n.release
	return nil, context.DeadlineExceeded
}
func TestServiceStreamV1Fix1ConnectTimeoutCompletesReplyWithoutReset(t *testing.T) {
	for _, domain := range []bool{false, true} {
		t.Run(fmt.Sprint(domain), func(t *testing.T) {
			network := pumpTimeoutNetworkV1{entered: make(chan struct{}), release: make(chan struct{})}
			c, r, cp, rp := pumpPairFixtureV1(t, network, false)
			original := r.cfg.Now
			var forced atomic.Int64
			r.cfg.Now = func() time.Time {
				if n := forced.Load(); n != 0 {
					return time.Unix(0, n)
				}
				return original()
			}
			pumpStartPairV1(t, c, r)
			// A raw authenticated OPEN does not run the client's auto-RESET timeout path.
			body := []byte{1, 0, 4, 1, 1, 1, 1, 1, 187}
			if domain {
				body = append([]byte{2, 0, 11}, []byte("example.com")...)
				body = append(body, 1, 187)
			}
			c.mu.Lock()
			c.streams[0] = serviceStreamSlotV1{id: 1, state: 1, deadline: c.deadline}
			c.mu.Unlock()
			pumpSendControlV1(t, c, 1, ServiceOpenV1, body)
			<-network.entered
			r.mu.Lock()
			deadline := r.streams[0].deadline
			r.mu.Unlock()
			forced.Store(deadline.UnixNano())
			close(network.release)
			pumpWaitUntilV1(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return !r.streams[0].worker })
			r.mu.Lock()
			state, queueState := r.streams[0].state, r.queue[r.head].state
			r.mu.Unlock()
			if state != 3 || queueState == 1 {
				t.Fatalf("connect timeout abandoned opening/reply: state=%d queue=%d", state, queueState)
			}
			pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.streams[0].result == ServiceTimeoutV1 })
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			packet := testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, [4]byte{10, 77, 0, 2}, 443, 12345, 0x10, nil)
			if e := rp.Submit(ctx, packet); e != nil {
				t.Fatal(e)
			}
			token, n, e := cp.Receive(ctx, make([]byte, 1280))
			if e != nil {
				t.Fatal("unrelated packet blocked by abandoned response", e)
			}
			if e = cp.Acknowledge(ctx, token, n, nil); e != nil {
				t.Fatal(e)
			}
		})
	}
}

type pumpV6NetworkV1 struct{ *pumpLocalNetworkV1 }

func (n pumpV6NetworkV1) ResolveProxy(_ context.Context, _ []byte, out *[16]netip.Addr) (int, error) {
	out[0] = netip.MustParseAddr("1.1.1.1")
	out[1] = netip.MustParseAddr("8.8.8.8")
	out[2] = netip.MustParseAddr("2606:4700::1111")
	return 3, nil
}

type pumpLocalNetworkV1 struct {
	address string
	mu      sync.Mutex
	domain  string
	dials   []netip.AddrPort
	wrap    func(ServiceTCPConnV1) ServiceTCPConnV1
}

func (n *pumpLocalNetworkV1) ResolveProxy(_ context.Context, domain []byte, out *[16]netip.Addr) (int, error) {
	n.mu.Lock()
	n.domain = string(domain)
	n.mu.Unlock()
	out[0] = netip.MustParseAddr("1.1.1.1")
	return 1, nil
}
func (n *pumpLocalNetworkV1) DialTCP(ctx context.Context, address netip.AddrPort) (ServiceTCPConnV1, error) {
	n.mu.Lock()
	n.dials = append(n.dials, address)
	n.mu.Unlock()
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", n.address)
	if e != nil {
		return nil, e
	}
	if n.wrap != nil {
		return n.wrap(c.(*net.TCPConn)), nil
	}
	return c.(*net.TCPConn), nil
}

func TestServiceStreamV1EffectiveFamilyBeforeCandidateTruncation(t *testing.T) {
	l, n := pumpLocalListenerV1(t)
	c, r, _, _ := pumpPairNarrowV1(t, pumpV6NetworkV1{n}, false, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1, IPMode: runtimepolicy.IPModeIPv6Only})
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, e := c.OpenStream(ctx, ProxyRequestV1{2, []byte("example.com"), 443}); e != nil {
		t.Fatal("later valid IPv6 answer dropped after IPv4 truncation", e)
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	conn.Close()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.dials) != 1 || n.dials[0].Addr() != netip.MustParseAddr("2606:4700::1111") {
		t.Fatal("wrong effective numeric family")
	}
}

type pumpShortTCPV1 struct {
	ServiceTCPConnV1
	terminal bool
}

func (c pumpShortTCPV1) Write(b []byte) (int, error) {
	if c.terminal {
		n, e := c.ServiceTCPConnV1.Write(b)
		if e == nil {
			e = io.ErrUnexpectedEOF
		}
		return n, e
	}
	return c.ServiceTCPConnV1.Write(b[:min(2, len(b))])
}
func TestServiceStreamV1TCPPartialWritesAndTerminalFinalBytes(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(fmt.Sprint(terminal), func(t *testing.T) {
			l, n := pumpLocalListenerV1(t)
			n.wrap = func(c ServiceTCPConnV1) ServiceTCPConnV1 { return pumpShortTCPV1{c, terminal} }
			c, r, _, _ := pumpPairFixtureV1(t, n, false)
			pumpStartPairV1(t, c, r)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			id, e := c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
			if e != nil {
				t.Fatal(e)
			}
			conn, e := l.AcceptTCP()
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, e = c.WriteStream(ctx, id, []byte("abcdef")); e != nil {
				t.Fatal(e)
			}
			out := make([]byte, 6)
			if _, e = io.ReadFull(conn, out); e != nil || string(out) != "abcdef" {
				t.Fatal("destination partial delivery", e)
			}
			if terminal {
				select {
				case <-r.Done():
				case <-ctx.Done():
					t.Fatal("error with final bytes committed")
				}
			} else {
				if e = c.CloseWrite(ctx, id); e != nil {
					t.Fatal(e)
				}
				if _, e = conn.Read(out); e != io.EOF {
					t.Fatal("missing real FIN", e)
				}
			}
		})
	}
}
func pumpLocalListenerV1(t testing.TB) (*net.TCPListener, *pumpLocalNetworkV1) {
	t.Helper()
	listener, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	return listener, &pumpLocalNetworkV1{address: listener.Addr().String()}
}

// This fixture combines the real socket's final data and subsequent EOF into
// one legal Read result, exercising the n>0,EOF ordering contract.
type pumpCombinedEOFTCPV1 struct{ ServiceTCPConnV1 }

func (c pumpCombinedEOFTCPV1) Read(b []byte) (int, error) {
	n, e := c.ServiceTCPConnV1.Read(b)
	if n > 0 && e == nil {
		var tail [1]byte
		_, e = c.ServiceTCPConnV1.Read(tail[:])
		if e != io.EOF {
			return n, io.ErrUnexpectedEOF
		}
	}
	return n, e
}
func TestServiceStreamV1ActualTCPHalfCloseAndAcknowledgedReturn(t *testing.T) {
	l, network := pumpLocalListenerV1(t)
	network.wrap = func(c ServiceTCPConnV1) ServiceTCPConnV1 { return pumpCombinedEOFTCPV1{c} }
	c, r, _, _ := pumpPairFixtureV1(t, network, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	id, e := c.OpenStream(ctx, ProxyRequestV1{Kind: 2, Address: []byte("xn--bcher-kva.example"), Port: 443})
	if e != nil {
		t.Fatal("open through idle K=1 packet reader", e)
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if n, e := c.WriteStream(ctx, id, []byte("request")); e != nil || n != 7 {
		t.Fatal("stream write", n, e)
	}
	if e = c.CloseWrite(ctx, id); e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(conn)
	if e != nil || string(got) != "request" {
		t.Fatal("actual bytes and FIN", string(got), e)
	}
	if _, e = conn.Write([]byte("response")); e != nil {
		t.Fatal(e)
	}
	if e = conn.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	out := make([]byte, 1024)
	token, n, e := c.ReceiveStream(ctx, id, out)
	if e != nil || !bytes.Equal(out[:n], []byte("response")) || token == 0 {
		t.Fatal("stream receive", n, e)
	}
	if e = c.ConfirmStreamDelivery(id, token, n); e != nil {
		t.Fatal(e)
	}
	if _, _, e = c.ReceiveStream(ctx, id, out); e != io.EOF {
		t.Fatal("real remote half-close", e)
	}
	network.mu.Lock()
	defer network.mu.Unlock()
	if network.domain != "xn--bcher-kva.example" || len(network.dials) != 1 || network.dials[0] != netip.MustParseAddrPort("1.1.1.1:443") {
		t.Fatal("domain or numeric destination changed")
	}
}
func TestServiceStreamV1WrongDeliveryTokenTerminates(t *testing.T) {
	l, network := pumpLocalListenerV1(t)
	c, r, _, _ := pumpPairFixtureV1(t, network, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	id, e := c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
	if e != nil {
		t.Fatal(e)
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.Write([]byte{1, 2, 3})
	if _, _, e = c.ReceiveStream(ctx, id, make([]byte, 2)); e != io.ErrShortBuffer {
		t.Fatal("short buffer consumed", e)
	}
	token, n, e := c.ReceiveStream(ctx, id, make([]byte, 3))
	if e != nil || n != 3 {
		t.Fatal(e)
	}
	if c.ConfirmStreamDelivery(id, token+1, n) == nil {
		t.Fatal("wrong token accepted")
	}
	select {
	case <-c.Done():
	case <-ctx.Done():
		t.Fatal("wrong token did not terminate")
	}
}

func TestServiceStreamV1ClosedStreamsReleaseBoundedSlots(t *testing.T) {
	l, network := pumpLocalListenerV1(t)
	c, r, _, _ := pumpPairFixtureV1(t, network, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for range 6 {
		id, e := c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
		if e != nil {
			t.Fatal("completed stream kept capacity", e)
		}
		conn, e := l.AcceptTCP()
		if e != nil {
			t.Fatal(e)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		if e = c.CloseWrite(ctx, id); e != nil {
			t.Fatal(e)
		}
		if _, e = io.ReadAll(conn); e != nil {
			t.Fatal(e)
		}
		conn.CloseWrite()
		if _, _, e = c.ReceiveStream(ctx, id, make([]byte, 1)); e != io.EOF {
			t.Fatal(e)
		}
		conn.Close()
	}
}
func TestServiceStreamV1OpeningReservationsBoundBlockedPublicCalls(t *testing.T) {
	c, r, cp, rp := pumpPairFixtureV1(t, nil, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	packet := testIPv4TCPPacketV1([4]byte{10, 77, 0, 2}, [4]byte{1, 1, 1, 1}, 12345, 443, 0x10, nil)
	if e := cp.Submit(ctx, packet); e != nil {
		t.Fatal(e)
	}
	if _, _, e := rp.Receive(ctx, make([]byte, 1280)); e != nil {
		t.Fatal(e)
	}
	if e := cp.Submit(ctx, packet); e != nil {
		t.Fatal(e)
	}
	for {
		c.mu.Lock()
		blocked := c.used == 1 && c.queue[c.head].state == 3
		c.mu.Unlock()
		if blocked {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("did not establish carrier pressure")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	results := make(chan error, 5)
	for range 5 {
		go func() { _, e := c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443}); results <- e }()
	}
	select {
	case e := <-results:
		if e != ServiceResourceLimitV1 {
			t.Fatal("excess opening not categorically refused", e)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("more than S opening calls retained behind full ring")
	}
	c.Close()
	for range 4 {
		select {
		case <-results:
		case <-ctx.Done():
			t.Fatal("opening caller not joined")
		}
	}
}

type pumpJoinedResolverV1 struct {
	pumpNoNetworkV1
	entered chan struct{}
	intact  chan bool
}
type pumpNotifyDialV1 struct {
	pumpNoNetworkV1
	entered chan struct{}
}

func (n pumpNotifyDialV1) DialTCP(context.Context, netip.AddrPort) (ServiceTCPConnV1, error) {
	close(n.entered)
	return nil, ServiceUnreachableV1
}
func TestServiceStreamV1ResponseReservationPrecedesRelayDial(t *testing.T) {
	network := pumpNotifyDialV1{entered: make(chan struct{})}
	c, r, cp, rp := pumpPairFixtureV1(t, network, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	packet := testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, [4]byte{10, 77, 0, 2}, 443, 12345, 0x10, nil)
	if e := rp.Submit(ctx, packet); e != nil {
		t.Fatal(e)
	}
	token, n, e := cp.Receive(ctx, make([]byte, 1280))
	if e != nil {
		t.Fatal(e)
	}
	if e = rp.Submit(ctx, packet); e != nil {
		t.Fatal(e)
	}
	for {
		r.mu.Lock()
		blocked := r.used == 1 && r.queue[r.head].state == 3
		r.mu.Unlock()
		if blocked {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("relay queue pressure")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	result := make(chan error, 1)
	go func() { _, e := c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443}); result <- e }()
	select {
	case <-network.entered:
		t.Fatal("dial preceded response-capacity reservation")
	case <-time.After(30 * time.Millisecond):
	}
	if e = cp.Acknowledge(ctx, token, n, nil); e != nil {
		t.Fatal(e)
	}
	for {
		token, n, e = cp.Receive(ctx, make([]byte, 1280))
		if e != ErrPacketPortBusy {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	cp.Acknowledge(ctx, token, n, nil)
	select {
	case e = <-result:
		if e != ServiceUnreachableV1 {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("reserved response not completed")
	}
}
func (n pumpJoinedResolverV1) ResolveProxy(ctx context.Context, address []byte, _ *[16]netip.Addr) (int, error) {
	close(n.entered)
	<-ctx.Done()
	n.intact <- string(address) == "example.com"
	return 0, ctx.Err()
}
func TestServiceStreamV1CancelJoinsResolverBeforeClearingRequest(t *testing.T) {
	n := pumpJoinedResolverV1{entered: make(chan struct{}), intact: make(chan bool, 1)}
	c, r, _, _ := pumpPairFixtureV1(t, n, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, e := c.OpenStream(ctx, ProxyRequestV1{2, []byte("example.com"), 443}); result <- e }()
	select {
	case <-n.entered:
	case <-ctx.Done():
		t.Fatal("resolver not entered")
	}
	if e := r.CancelStream(1); e != nil {
		t.Fatal(e)
	}
	if intact := <-n.intact; !intact {
		t.Fatal("cleared resolver borrower before join")
	}
	select {
	case <-result:
	case <-ctx.Done():
		t.Fatal("open not cancelled")
	}
}
