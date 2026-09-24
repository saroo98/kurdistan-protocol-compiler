// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package boundeddns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/dns/dnsmessage"
)

type testOwner struct {
	udp func(context.Context, netip.AddrPort) (*net.UDPConn, error)
	tcp func(context.Context, netip.AddrPort) (*net.TCPConn, error)
}

func waitDNS(t testing.TB, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS fixture synchronization timed out")
	}
}

func TestResolverSaturationPrecedesAllocatingGrammarAndCloseJoinsDial(t *testing.T) {
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	owner := &testOwner{udp: func(ctx context.Context, _ netip.AddrPort) (*net.UDPConn, error) {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return nil, ctx.Err()
	}}
	r, err := NewResolver([]netip.AddrPort{netip.MustParseAddrPort("10.77.0.1:53")}, owner, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		cancel()
		_ = r.Close()
	}()
	done := make(chan error, 1)
	go func() { var out [16]netip.Addr; _, err := r.ResolveInto(ctx, "example.test", IPv4, &out); done <- err }()
	waitDNS(t, entered)
	var out [16]netip.Addr
	out[0] = netip.MustParseAddr("1.1.1.1")
	if n, err := r.ResolveInto(ctx, strings.Repeat(".", 253), IPv4, &out); n != 0 || !errors.Is(err, ErrResourceLimit) || out != ([16]netip.Addr{}) {
		t.Fatalf("saturation n=%d err=%v", n, err)
	}
	closed := make(chan struct{})
	go func() { _ = r.Close(); close(closed) }()
	waitDNS(t, cancelled)
	select {
	case <-r.Done():
		t.Fatal("Done preceded dial join")
	case <-closed:
		t.Fatal("Close preceded dial join")
	default:
	}
	close(release)
	waitDNS(t, closed)
	if err := <-done; err == nil {
		t.Fatal("closed resolver published success")
	}
	if calls.Load() != 1 {
		t.Fatalf("saturation created sockets: %d", calls.Load())
	}
	if r.slots[0].used {
		t.Fatal("admission retained after close")
	}
	if n, err := r.ResolveInto(ctx, "example.test", IPv4, &out); n != 0 || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("post-close n=%d err=%v", n, err)
	}
}

func TestResolverInvalidInputsNeverDialAndClearOutput(t *testing.T) {
	var calls atomic.Int32
	o := &testOwner{udp: func(context.Context, netip.AddrPort) (*net.UDPConn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected dial")
	}}
	r, err := NewResolver([]netip.AddrPort{netip.MustParseAddrPort("10.77.0.1:53")}, o, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, domain := range []string{"", strings.Repeat("a", 254), "Example.test", "example.test.", "bad..test", "-bad.test", strings.Repeat(".", 253)} {
		var out [16]netip.Addr
		out[0] = netip.MustParseAddr("1.1.1.1")
		if n, err := r.ResolveInto(ctx, domain, IPv4, &out); n != 0 || !errors.Is(err, ErrInvalidRequest) || out != ([16]netip.Addr{}) {
			t.Fatalf("invalid grammar count=%d err=%v", n, err)
		}
	}
	for _, parent := range []context.Context{nil, context.Background()} {
		var out [16]netip.Addr
		if _, err := r.ResolveInto(parent, "example.test", IPv4, &out); err == nil {
			t.Fatal("unbounded parent accepted")
		}
	}
	for _, mask := range []FamilyMask{0, 4, 255} {
		var out [16]netip.Addr
		if _, err := r.ResolveInto(ctx, "example.test", mask, &out); err == nil {
			t.Fatal("invalid family accepted")
		}
	}
	if _, err := r.ResolveInto(ctx, "example.test", IPv4, nil); err == nil {
		t.Fatal("nil output accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input reached socket owner")
	}
}
func (o *testOwner) DialUDP(ctx context.Context, s netip.AddrPort) (*net.UDPConn, error) {
	if o.udp == nil {
		return nil, errors.New("unexpected UDP dial")
	}
	return o.udp(ctx, s)
}
func (o *testOwner) DialTCP(ctx context.Context, s netip.AddrPort) (*net.TCPConn, error) {
	if o.tcp == nil {
		return nil, errors.New("unexpected TCP dial")
	}
	return o.tcp(ctx, s)
}

func TestConstructorValidatesBeforeCopyAndClosesIdempotently(t *testing.T) {
	valid := netip.MustParseAddrPort("10.77.0.1:53")
	for _, servers := range [][]netip.AddrPort{nil, {valid, valid}, {netip.MustParseAddrPort("0.0.0.0:53")}, {netip.MustParseAddrPort("224.0.0.1:53")}, {netip.MustParseAddrPort("[::ffff:10.1.1.1]:53")}, {netip.MustParseAddrPort("[fe80::1%4]:53")}, {netip.MustParseAddrPort("10.1.1.1:0")}, {valid, valid, valid, valid, valid}} {
		if r, err := NewResolver(servers, &testOwner{}, 1); r != nil || !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid constructor err=%v", err)
		}
	}
	for _, max := range []int{0, 17} {
		if r, err := NewResolver([]netip.AddrPort{valid}, &testOwner{}, max); r != nil || !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid concurrency err=%v", err)
		}
	}
	if r, err := NewResolver([]netip.AddrPort{valid}, nil, 1); r != nil || !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil owner err=%v", err)
	}
	servers := []netip.AddrPort{valid}
	r, err := NewResolver(servers, &testOwner{}, 16)
	if err != nil {
		t.Fatal(err)
	}
	servers[0] = netip.MustParseAddrPort("1.1.1.1:53")
	if r.servers[0] != valid || len(r.slots) != 16 {
		t.Fatal("constructor did not own fixed configuration")
	}
	select {
	case <-r.Done():
		t.Fatal("premature Done")
	default:
	}
	if r.Close() != nil || r.Close() != nil {
		t.Fatal("close error")
	}
	select {
	case <-r.Done():
	default:
		t.Fatal("Done did not close")
	}
}

func TestResolverOwnedCapacityAndClearedWorkspace(t *testing.T) {
	r, err := NewResolver([]netip.AddrPort{netip.MustParseAddrPort("10.77.0.1:53")}, &testOwner{}, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := r.OperationOwnedBytes(); got < uint64(unsafe.Sizeof(workspace{}))+4096 {
		t.Fatalf("operation undercharges fixed storage: %d", got)
	}
	if got := r.FixedOwnedBytes(); got < uint64(unsafe.Sizeof(Resolver{}))+4*uint64(unsafe.Sizeof(operationSlot{})) {
		t.Fatalf("fixed undercharges slots: %d", got)
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = r.OperationOwnedBytes(); _ = r.FixedOwnedBytes() }); allocs != 0 {
		t.Fatalf("estimator allocations=%f", allocs)
	}
	w, msg := parseFixture(t, dnsmessage.TypeA, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}}, nil, nil)
	if _, err := w.acceptResponse(msg, dnsmessage.TypeA, 123); err != nil {
		t.Fatal(err)
	}
	w.query[0] = 7
	w.udp[0] = 8
	w.tcp[len(w.tcp)-1] = 9
	w.prefix[0] = 2
	w.clear()
	if *w != (workspace{}) {
		t.Fatal("workspace retained wire/name/result bytes")
	}
	t.Logf("workspace=%d operation=%d scratch=%d resolver=%d slot=%d operation-owned=%d fixed-owned-4=%d", unsafe.Sizeof(workspace{}), unsafe.Sizeof(operation{}), unsafe.Sizeof(parserScratch{}), unsafe.Sizeof(Resolver{}), unsafe.Sizeof(operationSlot{}), r.OperationOwnedBytes(), r.FixedOwnedBytes())
}

type closeGateDNS struct {
	net.Conn
	entered, release chan struct{}
}

func (c *closeGateDNS) Close() error {
	err := c.Conn.Close()
	close(c.entered)
	<-c.release
	return err
}

func TestOperationCancellationCallbackIsJoined(t *testing.T) {
	s := newLocalDNS(t, nil, nil)
	parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	udp, err := new(net.Dialer).DialUDP(parent, "udp4", netip.AddrPort{}, s.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	gate := &closeGateDNS{Conn: udp, entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
	}()
	op := newOperation(parent, time.Now().Add(time.Second))
	if err := op.install(parent, gate); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitDNS(t, gate.entered)
	finished := make(chan struct{})
	go func() { op.finish(); close(finished) }()
	select {
	case <-finished:
		t.Fatal("callback was not joined")
	case <-time.After(20 * time.Millisecond):
	}
	close(gate.release)
	waitDNS(t, finished)
	select {
	case <-op.hookDone:
	default:
		t.Fatal("callback completion missing")
	}
}

type shutdownGateDNS struct {
	net.Conn
	entered, release chan struct{}
}

func (c *shutdownGateDNS) Close() error {
	close(c.entered)
	<-c.release
	return c.Conn.Close()
}

func TestResolverCloseRetainsAdmissionUntilSocketCloseCompletes(t *testing.T) {
	querySeen, reply := make(chan struct{}), make(chan struct{})
	s := newLocalDNS(t, func(query []byte) [][]byte {
		close(querySeen)
		<-reply
		return [][]byte{answerQuery(t, query, []testRR{{kind: dnsmessage.TypeA, data: []byte{1, 2, 3, 4}}})}
	}, nil)
	dialEntered, allowDial := make(chan struct{}), make(chan struct{})
	owner := ownerFor(t, s.endpoint)
	dial := owner.udp
	owner.udp = func(ctx context.Context, endpoint netip.AddrPort) (*net.UDPConn, error) {
		close(dialEntered)
		<-allowDial
		return dial(ctx, endpoint)
	}
	r, err := NewResolver([]netip.AddrPort{s.endpoint}, owner, 1)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	gate := &shutdownGateDNS{entered: make(chan struct{}), release: make(chan struct{})}
	resolved, closed := make(chan struct{}), make(chan struct{})
	defer func() {
		for _, ch := range []chan struct{}{allowDial, reply, gate.release} {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
		cancel()
		_ = r.Close()
		waitDNS(t, resolved)
	}()
	var out [16]netip.Addr
	var n int
	var resolveErr error
	go func() {
		n, resolveErr = r.ResolveInto(parent, "example.test", IPv4, &out)
		close(resolved)
	}()
	waitDNS(t, dialEntered)
	r.mu.Lock()
	op := r.slots[0].op
	r.mu.Unlock()
	// Observe the worker's join boundary while that worker is parked in
	// its owner, before it can read stopHook even if its deadline expires.
	joinReached := make(chan struct{})
	stopHook := op.stopHook
	op.stopHook = func() bool {
		stopped := stopHook()
		close(joinReached)
		return stopped
	}
	close(allowDial)
	waitDNS(t, querySeen)
	// The real UDP read is blocked behind the server's reply gate. Wrap only
	// its close boundary, without changing numeric dialing or wire I/O.
	op.mu.Lock()
	gate.Conn = op.conn
	op.conn = gate
	op.mu.Unlock()
	go func() { _ = r.Close(); close(closed) }()
	waitDNS(t, gate.entered)
	close(reply) // The still-open socket lets the resolving worker unwind.
	waitDNS(t, joinReached)
	select {
	case <-resolved:
		t.Error("Resolve returned before socket close completed")
	case <-time.After(20 * time.Millisecond):
	}
	r.mu.Lock()
	active, used := r.active, r.slots[0].used
	r.mu.Unlock()
	if active != 1 || !used {
		t.Errorf("admission released during socket close: active=%d used=%v", active, used)
	}
	select {
	case <-r.Done():
		t.Error("Done preceded socket close completion")
	default:
	}
	select {
	case <-closed:
		t.Error("Close returned before socket close completed")
	default:
	}
	close(gate.release)
	waitDNS(t, closed)
	waitDNS(t, resolved)
	if n != 0 || resolveErr != ErrInvalidState || out != ([16]netip.Addr{}) {
		t.Fatalf("shutdown published result: n=%d err=%v", n, resolveErr)
	}
	if _, err := gate.Conn.Write([]byte{1}); err == nil {
		t.Fatal("socket remained open after Close")
	}
	if r.active != 0 || r.slots[0].used {
		t.Fatal("admission retained after actual close completion")
	}
}

func TestResolverLateNumericDialSuccessIsClosedAndCannotPublish(t *testing.T) {
	s := newLocalDNS(t, nil, nil)
	parent, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	entered, release := make(chan struct{}), make(chan struct{})
	var late *net.UDPConn
	o := &testOwner{udp: func(ctx context.Context, endpoint netip.AddrPort) (*net.UDPConn, error) {
		if endpoint != s.endpoint {
			return nil, errors.New("wrong endpoint")
		}
		c, err := new(net.Dialer).DialUDP(ctx, "udp4", netip.AddrPort{}, endpoint)
		late = c
		close(entered)
		<-release
		return c, err
	}}
	r, err := NewResolver([]netip.AddrPort{s.endpoint}, o, 1)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		cancel()
		_ = r.Close()
	}()
	done := make(chan error, 1)
	go func() {
		var out [16]netip.Addr
		n, err := r.ResolveInto(parent, "example.test", IPv4, &out)
		if n != 0 || out != ([16]netip.Addr{}) {
			done <- errors.New("late success published")
			return
		}
		done <- err
	}()
	waitDNS(t, entered)
	cancel()
	close(release)
	if err := <-done; !errors.Is(err, ErrCancelled) {
		t.Fatalf("late dial err=%v", err)
	}
	if late == nil {
		t.Fatal("late fixture did not create socket")
	}
	if _, err := late.Write([]byte{1}); err == nil {
		t.Fatal("late socket remained open")
	}
	if r.active != 0 || r.slots[0].op != nil {
		t.Fatal("late operation retained admission")
	}
}

func TestZeroResolverFailsCategorically(t *testing.T) {
	var r Resolver
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var output [16]netip.Addr
	if n, err := r.ResolveInto(ctx, "example.test", IPv4, &output); n != 0 || !errors.Is(err, ErrInvalidState) {
		t.Fatalf("zero resolver n=%d err=%v", n, err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("zero close=%v", err)
	}
}

type passiveDeadline struct {
	context.Context
	at time.Time
}

func (p passiveDeadline) Deadline() (time.Time, bool) { return p.at, true }

func TestContextDeadlineFenceDoesNotDependOnTimerScheduling(t *testing.T) {
	ctx := passiveDeadline{Context: context.Background(), at: time.Now().Add(-time.Second)}
	if err := contextError(ctx); !errors.Is(err, ErrTimeout) {
		t.Fatalf("expired deadline fence=%v", err)
	}
}
