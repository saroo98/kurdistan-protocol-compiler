// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package tlstcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"kurdistan/internal/protocol/wirev1"
)

var _ io.ReadWriteCloser = (*RecordStreamV3)(nil)

type deadlineCountConnV3 struct {
	net.Conn
	readCalls  atomic.Uint32
	writeCalls atomic.Uint32
}

type deadlineTraceConnV3 struct {
	net.Conn
	mu             sync.Mutex
	readDeadlines  []time.Time
	writeDeadlines []time.Time
}

type closeGateConnV3 struct {
	net.Conn
	enabled       atomic.Bool
	readOnce      sync.Once
	writeOnce     sync.Once
	closeOnce     sync.Once
	releaseOnce   sync.Once
	readEntered   chan struct{}
	writeEntered  chan struct{}
	closeEntered  chan struct{}
	releaseClosed chan struct{}
}

type gatedDeadlineContextV3 struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type signalDeadlineContextV3 struct {
	entered  chan struct{}
	once     sync.Once
	deadline time.Time
}

func newSignalDeadlineContextV3() *signalDeadlineContextV3 {
	return &signalDeadlineContextV3{entered: make(chan struct{}), deadline: time.Now().Add(time.Second)}
}

func (ctx *signalDeadlineContextV3) Deadline() (time.Time, bool) {
	ctx.once.Do(func() { close(ctx.entered) })
	return ctx.deadline, true
}

func (*signalDeadlineContextV3) Done() <-chan struct{} { return nil }
func (*signalDeadlineContextV3) Err() error            { return nil }
func (*signalDeadlineContextV3) Value(any) any         { return nil }

type failAfterRawWritesConnV3 struct {
	net.Conn
	enabled   atomic.Bool
	writes    atomic.Uint32
	failAfter uint32
}

type resetGateConnV3 struct {
	net.Conn
	enabled      atomic.Bool
	resetOnce    sync.Once
	resetEntered chan struct{}
	releaseReset chan struct{}
}

type directionDeadlineGateConnV3 struct {
	net.Conn
	gateRead     atomic.Bool
	gateWrite    atomic.Bool
	readOnce     sync.Once
	writeOnce    sync.Once
	readEntered  chan struct{}
	writeEntered chan struct{}
	releaseRead  chan struct{}
	releaseWrite chan struct{}
}

func newDirectionDeadlineGateConnV3(conn net.Conn) *directionDeadlineGateConnV3 {
	return &directionDeadlineGateConnV3{
		Conn: conn, readEntered: make(chan struct{}), writeEntered: make(chan struct{}),
		releaseRead: make(chan struct{}), releaseWrite: make(chan struct{}),
	}
}

func (conn *directionDeadlineGateConnV3) SetReadDeadline(deadline time.Time) error {
	if conn.gateRead.Load() && !deadline.IsZero() {
		conn.readOnce.Do(func() { close(conn.readEntered) })
		<-conn.releaseRead
	}
	return conn.Conn.SetReadDeadline(deadline)
}

func (conn *directionDeadlineGateConnV3) SetWriteDeadline(deadline time.Time) error {
	if conn.gateWrite.Load() && !deadline.IsZero() {
		conn.writeOnce.Do(func() { close(conn.writeEntered) })
		<-conn.releaseWrite
	}
	return conn.Conn.SetWriteDeadline(deadline)
}

func newResetGateConnV3(conn net.Conn) *resetGateConnV3 {
	return &resetGateConnV3{
		Conn: conn, resetEntered: make(chan struct{}), releaseReset: make(chan struct{}),
	}
}

func (conn *resetGateConnV3) SetReadDeadline(deadline time.Time) error {
	if conn.enabled.Load() && deadline.IsZero() {
		conn.resetOnce.Do(func() { close(conn.resetEntered) })
		<-conn.releaseReset
	}
	return conn.Conn.SetReadDeadline(deadline)
}

func (conn *failAfterRawWritesConnV3) Write(value []byte) (int, error) {
	if conn.enabled.Load() && conn.writes.Add(1) > conn.failAfter {
		return 0, errors.New("test raw write failure")
	}
	return conn.Conn.Write(value)
}

func newGatedDeadlineContextV3() *gatedDeadlineContextV3 {
	return &gatedDeadlineContextV3{entered: make(chan struct{}), release: make(chan struct{})}
}

func (ctx *gatedDeadlineContextV3) Deadline() (time.Time, bool) {
	ctx.once.Do(func() { close(ctx.entered) })
	<-ctx.release
	return time.Now().Add(time.Second), true
}

func (*gatedDeadlineContextV3) Done() <-chan struct{} { return nil }
func (*gatedDeadlineContextV3) Err() error            { return nil }
func (*gatedDeadlineContextV3) Value(any) any         { return nil }

func newCloseGateConnV3(conn net.Conn) *closeGateConnV3 {
	return &closeGateConnV3{
		Conn: conn, readEntered: make(chan struct{}), writeEntered: make(chan struct{}),
		closeEntered: make(chan struct{}), releaseClosed: make(chan struct{}),
	}
}

func (conn *closeGateConnV3) Read(value []byte) (int, error) {
	if conn.enabled.Load() {
		conn.readOnce.Do(func() { close(conn.readEntered) })
	}
	return conn.Conn.Read(value)
}

func (conn *closeGateConnV3) Write(value []byte) (int, error) {
	if conn.enabled.Load() {
		conn.writeOnce.Do(func() { close(conn.writeEntered) })
	}
	return conn.Conn.Write(value)
}

func (conn *closeGateConnV3) Close() error {
	err := conn.Conn.Close()
	if conn.enabled.Load() {
		conn.closeOnce.Do(func() { close(conn.closeEntered) })
		<-conn.releaseClosed
	}
	return err
}

func (conn *closeGateConnV3) releaseClose() {
	conn.releaseOnce.Do(func() { close(conn.releaseClosed) })
}

func (conn *deadlineTraceConnV3) SetReadDeadline(deadline time.Time) error {
	conn.mu.Lock()
	conn.readDeadlines = append(conn.readDeadlines, deadline)
	conn.mu.Unlock()
	return conn.Conn.SetReadDeadline(deadline)
}

func (conn *deadlineTraceConnV3) SetWriteDeadline(deadline time.Time) error {
	conn.mu.Lock()
	conn.writeDeadlines = append(conn.writeDeadlines, deadline)
	conn.mu.Unlock()
	return conn.Conn.SetWriteDeadline(deadline)
}

func (conn *deadlineTraceConnV3) resetTrace() {
	conn.mu.Lock()
	conn.readDeadlines = nil
	conn.writeDeadlines = nil
	conn.mu.Unlock()
}

func (conn *deadlineTraceConnV3) trace() ([]time.Time, []time.Time) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return append([]time.Time(nil), conn.readDeadlines...), append([]time.Time(nil), conn.writeDeadlines...)
}

func (conn *deadlineCountConnV3) SetReadDeadline(time.Time) error {
	conn.readCalls.Add(1)
	return errors.New("test read deadline rejected")
}

func (conn *deadlineCountConnV3) SetWriteDeadline(time.Time) error {
	conn.writeCalls.Add(1)
	return errors.New("test write deadline rejected")
}

func TestRecordStreamV3PreservesExactFragmentedRecordBytes(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	client, server, clientErr, serverErr := pair(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()

	clientStream, err := client.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientBinding, err := client.CarrierBinding()
	if err != nil {
		t.Fatal(err)
	}
	serverBinding, err := server.CarrierBinding()
	if err != nil || clientBinding != serverBinding {
		t.Fatalf("selected exporter mismatch: err=%v", err)
	}
	record := testRecordBytesV3(t, []byte("direct TLS record stream"))

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeFragmentsV3(clientStream, record, []int{1, 2, 5})
	}()
	got := make([]byte, len(record))
	if _, err := io.ReadFull(serverStream, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, record) {
		t.Fatalf("record changed: got=%x want=%x", got, record)
	}

	reverse := testRecordBytesV3(t, []byte("relay to client record"))
	writeDone = make(chan error, 1)
	go func() {
		writeDone <- writeFragmentsV3(serverStream, reverse, []int{2, 1, 7})
	}()
	got = make([]byte, len(reverse))
	if _, err := io.ReadFull(clientStream, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, reverse) {
		t.Fatalf("reverse record changed: got=%x want=%x", got, reverse)
	}
}

func TestRecordStreamV3ExcludesLegacyFramedOperationsAfterSelection(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	clientBoundary := &deadlineCountConnV3{Conn: clientRaw}
	serverBoundary := &deadlineCountConnV3{Conn: serverRaw}
	client, server, clientErr, serverErr := pairRaw(
		t, clientBoundary, serverBoundary, clientConfig, serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	if _, err := client.SelectRecordStreamV3(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := server.SelectRecordStreamV3(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	clientBoundary.writeCalls.Store(0)
	serverBoundary.readCalls.Store(0)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	frame := wirev1.Frame{
		Type: wirev1.TypeReliableData, StreamID: 1,
		PlanDigest: planDigest(), Payload: []byte{1},
	}
	if err := client.Send(ctx, frame); !errors.Is(err, ErrCarrier) {
		t.Fatalf("legacy send after selection: %v", err)
	}
	if _, err := server.Receive(ctx); !errors.Is(err, ErrCarrier) {
		t.Fatalf("legacy receive after selection: %v", err)
	}
	if got := clientBoundary.writeCalls.Load(); got != 0 {
		t.Fatalf("legacy send touched write deadline after selection: %d", got)
	}
	if got := serverBoundary.readCalls.Load(); got != 0 {
		t.Fatalf("legacy receive touched read deadline after selection: %d", got)
	}
}

func TestRecordStreamV3SelectionOwnsOneLiveViewAndPreservesBinding(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	client, server, clientErr, serverErr := pair(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer server.Close()
	before, err := client.CarrierBinding()
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	after, err := client.CarrierBinding()
	if err != nil || after != before {
		t.Fatalf("binding changed after selection: err=%v", err)
	}
	if _, err := client.SelectRecordStreamV3(context.Background(), time.Second); !errors.Is(err, ErrCarrier) {
		t.Fatalf("second selection: %v", err)
	}
	copyOfStream := *stream
	if _, err := copyOfStream.Read(make([]byte, 1)); !errors.Is(err, ErrCarrier) {
		t.Fatalf("copied view read: %v", err)
	}
	if _, err := copyOfStream.Write([]byte{1}); !errors.Is(err, ErrCarrier) {
		t.Fatalf("copied view write: %v", err)
	}
	bounds := stream.BoundsV3()
	if bounds.OwnedBytes != RecordStreamOwnedBytesV3() || bounds.QueuedPayloadBytes != 0 || bounds.MaxRecordBytes != 128<<10 {
		t.Fatalf("bounds=%+v estimator=%d", bounds, RecordStreamOwnedBytesV3())
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("second selected close: %v", err)
	}
	if bounds := stream.BoundsV3(); bounds != (RecordStreamBoundsV3{}) {
		t.Fatalf("closed bounds=%+v", bounds)
	}
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, ErrCarrier) {
		t.Fatalf("closed selected read: %v", err)
	}
	if _, err := client.SelectRecordStreamV3(context.Background(), time.Second); !errors.Is(err, ErrCarrier) {
		t.Fatalf("selection after close: %v", err)
	}
	if _, err := client.CarrierBinding(); !errors.Is(err, ErrCarrier) {
		t.Fatalf("binding after close: %v", err)
	}
}

func TestRecordStreamV3InvalidSelectionLeavesFramedCarrierUsable(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	client, server, clientErr, serverErr := pair(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name    string
		parent  context.Context
		timeout time.Duration
	}{
		{name: "nil-parent", timeout: time.Second},
		{name: "cancelled-parent", parent: cancelled, timeout: time.Second},
		{name: "zero-timeout", parent: context.Background()},
		{name: "negative-timeout", parent: context.Background(), timeout: -time.Second},
		{name: "excessive-timeout", parent: context.Background(), timeout: 48*time.Hour + time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if stream, err := client.SelectRecordStreamV3(tc.parent, tc.timeout); stream != nil || !errors.Is(err, ErrCarrier) {
				t.Fatalf("invalid selection accepted: stream=%v err=%v", stream, err)
			}
		})
	}

	frame := wirev1.Frame{
		Type: wirev1.TypeReliableData, StreamID: 23,
		PlanDigest: planDigest(), Payload: []byte("framed after invalid selection"),
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	writeDone := make(chan error, 1)
	go func() { writeDone <- client.Send(ctx, frame) }()
	received, err := server.Receive(ctx)
	if err != nil || <-writeDone != nil || !bytes.Equal(received.Payload, frame.Payload) {
		t.Fatalf("framed carrier changed after invalid selection: payload=%q err=%v", received.Payload, err)
	}
	if _, err := client.SelectRecordStreamV3(context.Background(), 48*time.Hour); err != nil {
		t.Fatalf("maximum legacy adapter timeout rejected: %v", err)
	}
}

func TestRecordStreamV3BusySelectionIsNonblockingAndLeavesFramedCarrierUsable(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	client, server, clientErr, serverErr := pair(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()

	client.readMu.Lock()
	if stream, err := client.SelectRecordStreamV3(context.Background(), time.Second); stream != nil || !errors.Is(err, ErrCarrier) {
		client.readMu.Unlock()
		t.Fatalf("selection with busy read: stream=%v err=%v", stream, err)
	}
	client.readMu.Unlock()

	client.writeMu.Lock()
	if stream, err := client.SelectRecordStreamV3(context.Background(), time.Second); stream != nil || !errors.Is(err, ErrCarrier) {
		client.writeMu.Unlock()
		t.Fatalf("selection with busy write: stream=%v err=%v", stream, err)
	}
	if !client.readMu.TryLock() {
		client.writeMu.Unlock()
		t.Fatal("failed write-direction selection retained read lock")
	}
	client.readMu.Unlock()
	client.writeMu.Unlock()

	frame := wirev1.Frame{
		Type: wirev1.TypeReliableData, StreamID: 29,
		PlanDigest: planDigest(), Payload: []byte("framed after busy selection"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	writeDone := make(chan error, 1)
	go func() { writeDone <- client.Send(ctx, frame) }()
	received, err := server.Receive(ctx)
	if err != nil || <-writeDone != nil || !bytes.Equal(received.Payload, frame.Payload) {
		t.Fatalf("framed carrier changed after busy selection: payload=%q err=%v", received.Payload, err)
	}
}

func TestRecordStreamV3RefusesInFlightFramedDirectionsWithoutWaiting(t *testing.T) {
	t.Run("receive", func(t *testing.T) {
		clientConfig, serverConfig := testConfigs(t)
		clientRaw, serverRaw := net.Pipe()
		clientBoundary := newDirectionDeadlineGateConnV3(clientRaw)
		client, server, clientErr, serverErr := pairRaw(
			t, clientBoundary, serverRaw, clientConfig, serverConfig,
		)
		if clientErr != nil || serverErr != nil {
			t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
		}
		defer client.Close()
		defer server.Close()
		clientBoundary.gateRead.Store(true)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		type receiveResult struct {
			frame wirev1.Frame
			err   error
		}
		receiveDone := make(chan receiveResult, 1)
		go func() {
			frame, err := client.Receive(ctx)
			receiveDone <- receiveResult{frame: frame, err: err}
		}()
		waitSignalV3(t, clientBoundary.readEntered, "in-flight framed receive")
		started := time.Now()
		if stream, err := client.SelectRecordStreamV3(context.Background(), time.Second); stream != nil || !errors.Is(err, ErrCarrier) {
			t.Fatalf("selection with in-flight receive: stream=%v err=%v", stream, err)
		}
		if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
			t.Fatalf("selection waited for in-flight receive: %s", elapsed)
		}
		frame := wirev1.Frame{
			Type: wirev1.TypeReliableData, StreamID: 41,
			PlanDigest: planDigest(), Payload: []byte("receive remains framed"),
		}
		sendDone := make(chan error, 1)
		go func() { sendDone <- server.Send(ctx, frame) }()
		close(clientBoundary.releaseRead)
		got := <-receiveDone
		if got.err != nil || <-sendDone != nil || !bytes.Equal(got.frame.Payload, frame.Payload) {
			t.Fatalf("framed receive after refusal payload=%q err=%v", got.frame.Payload, got.err)
		}
	})

	t.Run("send", func(t *testing.T) {
		clientConfig, serverConfig := testConfigs(t)
		clientRaw, serverRaw := net.Pipe()
		clientBoundary := newDirectionDeadlineGateConnV3(clientRaw)
		client, server, clientErr, serverErr := pairRaw(
			t, clientBoundary, serverRaw, clientConfig, serverConfig,
		)
		if clientErr != nil || serverErr != nil {
			t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
		}
		defer client.Close()
		defer server.Close()
		clientBoundary.gateWrite.Store(true)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		frame := wirev1.Frame{
			Type: wirev1.TypeReliableData, StreamID: 43,
			PlanDigest: planDigest(), Payload: []byte("send remains framed"),
		}
		sendDone := make(chan error, 1)
		go func() { sendDone <- client.Send(ctx, frame) }()
		waitSignalV3(t, clientBoundary.writeEntered, "in-flight framed send")
		started := time.Now()
		if stream, err := client.SelectRecordStreamV3(context.Background(), time.Second); stream != nil || !errors.Is(err, ErrCarrier) {
			t.Fatalf("selection with in-flight send: stream=%v err=%v", stream, err)
		}
		if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
			t.Fatalf("selection waited for in-flight send: %s", elapsed)
		}
		receiveDone := make(chan struct {
			frame wirev1.Frame
			err   error
		}, 1)
		go func() {
			got, err := server.Receive(ctx)
			receiveDone <- struct {
				frame wirev1.Frame
				err   error
			}{frame: got, err: err}
		}()
		close(clientBoundary.releaseWrite)
		got := <-receiveDone
		if got.err != nil || <-sendDone != nil || !bytes.Equal(got.frame.Payload, frame.Payload) {
			t.Fatalf("framed send after refusal payload=%q err=%v", got.frame.Payload, got.err)
		}
	})
}

func TestRecordStreamV3AppliesAndClearsOnlyDirectionDeadline(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	clientBoundary := &deadlineTraceConnV3{Conn: clientRaw}
	serverBoundary := &deadlineTraceConnV3{Conn: serverRaw}
	client, server, clientErr, serverErr := pairRaw(
		t, clientBoundary, serverBoundary, clientConfig, serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	clientStream, err := client.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientBoundary.resetTrace()
	serverBoundary.resetTrace()

	writeDone := make(chan error, 1)
	go func() { writeDone <- writeAllV3(clientStream, []byte("deadline-cleanup")) }()
	got := make([]byte, len("deadline-cleanup"))
	if _, err := io.ReadFull(serverStream, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	clientReads, clientWrites := clientBoundary.trace()
	serverReads, serverWrites := serverBoundary.trace()
	if len(clientReads) != 0 || len(clientWrites) != 2 || clientWrites[0].IsZero() || !clientWrites[1].IsZero() {
		t.Fatalf("client deadline trace reads=%v writes=%v", clientReads, clientWrites)
	}
	if len(serverWrites) != 0 || len(serverReads) != 2 || serverReads[0].IsZero() || !serverReads[1].IsZero() {
		t.Fatalf("server deadline trace reads=%v writes=%v", serverReads, serverWrites)
	}
}

func TestRecordStreamV3DeadlineFreeParentTimesOutAndClearsDeadline(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	clientBoundary := &deadlineTraceConnV3{Conn: clientRaw}
	client, server, clientErr, serverErr := pairRaw(
		t, clientBoundary, serverRaw, clientConfig, serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	stream, err := client.SelectRecordStreamV3(context.Background(), 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	clientBoundary.resetTrace()
	started := time.Now()
	if n, err := stream.Read(make([]byte, 1)); n != 0 || !errors.Is(err, ErrCarrier) {
		t.Fatalf("timed read n=%d err=%v", n, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("timed read exceeded bound: %s", elapsed)
	}
	reads, writes := clientBoundary.trace()
	if len(writes) != 0 || len(reads) != 2 || reads[0].IsZero() || !reads[1].IsZero() {
		t.Fatalf("deadline cleanup reads=%v writes=%v", reads, writes)
	}
}

func TestRecordStreamV3CancellationClosesFullDuplexAndJoinsHook(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	clientBoundary := newCloseGateConnV3(clientRaw)
	client, server, clientErr, serverErr := pairRaw(
		t, clientBoundary, serverRaw, clientConfig, serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer clientBoundary.releaseClose()
	defer client.Close()
	defer server.Close()
	parent, cancel := context.WithCancel(context.Background())
	stream, err := client.SelectRecordStreamV3(parent, time.Second)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	clientBoundary.enabled.Store(true)
	type result struct {
		n   int
		err error
	}
	results := make(chan result, 2)
	go func() {
		n, err := stream.Read(make([]byte, 1))
		results <- result{n: n, err: err}
	}()
	go func() {
		n, err := stream.Write(make([]byte, 1<<20))
		results <- result{n: n, err: err}
	}()
	waitSignalV3(t, clientBoundary.readEntered, "blocked read")
	waitSignalV3(t, clientBoundary.writeEntered, "blocked write")
	cancel()
	waitSignalV3(t, clientBoundary.closeEntered, "cancellation close")

	completed := make([]result, 0, 2)
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
waitBeforeRelease:
	for len(completed) < 2 {
		select {
		case got := <-results:
			completed = append(completed, got)
		case <-timer.C:
			break waitBeforeRelease
		}
	}
	if len(completed) == 2 {
		t.Fatal("both operations returned before the cancellation callback joined")
	}
	clientBoundary.releaseClose()
	for len(completed) < 2 {
		select {
		case got := <-results:
			completed = append(completed, got)
		case <-time.After(time.Second):
			t.Fatal("full-duplex operation did not wake after cancellation")
		}
	}
	for _, got := range completed {
		if !errors.Is(got.err, ErrCarrier) {
			t.Fatalf("cancelled operation n=%d err=%v", got.n, got.err)
		}
	}
	if _, err := client.CarrierBinding(); !errors.Is(err, ErrCarrier) {
		t.Fatalf("cancel did not close carrier binding: %v", err)
	}
}

func TestRecordStreamV3PendingLegacyOperationsRecheckAfterSwitch(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	clientBoundary := &deadlineCountConnV3{Conn: clientRaw}
	client, server, clientErr, serverErr := pairRaw(
		t, clientBoundary, serverRaw, clientConfig, serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	clientBoundary.readCalls.Store(0)
	clientBoundary.writeCalls.Store(0)
	readContext := newGatedDeadlineContextV3()
	writeContext := newGatedDeadlineContextV3()
	readDone := make(chan error, 1)
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Receive(readContext)
		readDone <- err
	}()
	go func() {
		writeDone <- client.Send(writeContext, wirev1.Frame{
			Type: wirev1.TypeReliableData, StreamID: 31,
			PlanDigest: planDigest(), Payload: []byte("pending legacy write"),
		})
	}()
	waitSignalV3(t, readContext.entered, "pending legacy receive")
	waitSignalV3(t, writeContext.entered, "pending legacy send")
	if _, err := client.SelectRecordStreamV3(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	close(readContext.release)
	close(writeContext.release)
	if err := <-readDone; !errors.Is(err, ErrCarrier) {
		t.Fatalf("pending legacy receive: %v", err)
	}
	if err := <-writeDone; !errors.Is(err, ErrCarrier) {
		t.Fatalf("pending legacy send: %v", err)
	}
	if got := clientBoundary.readCalls.Load(); got != 0 {
		t.Fatalf("pending legacy receive reached deadline I/O: %d", got)
	}
	if got := clientBoundary.writeCalls.Load(); got != 0 {
		t.Fatalf("pending legacy send reached deadline I/O: %d", got)
	}
}

func TestRecordStreamV3LegacyWaitersCannotRunAfterSwitch(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	clientBoundary := &deadlineCountConnV3{Conn: clientRaw}
	client, server, clientErr, serverErr := pairRaw(
		t, clientBoundary, serverRaw, clientConfig, serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	clientBoundary.readCalls.Store(0)
	clientBoundary.writeCalls.Store(0)

	client.stateMu.Lock()
	stateLocked := true
	defer func() {
		if stateLocked {
			client.stateMu.Unlock()
		}
	}()
	selectDone := make(chan struct {
		stream *RecordStreamV3
		err    error
	}, 1)
	go func() {
		stream, err := client.SelectRecordStreamV3(context.Background(), time.Second)
		selectDone <- struct {
			stream *RecordStreamV3
			err    error
		}{stream: stream, err: err}
	}()
	waitMutexHeldV3(t, &client.readMu, "selector read lock")
	waitMutexHeldV3(t, &client.writeMu, "selector write lock")

	readContext := newSignalDeadlineContextV3()
	writeContext := newSignalDeadlineContextV3()
	readDone := make(chan error, 1)
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Receive(readContext)
		readDone <- err
	}()
	go func() {
		writeDone <- client.Send(writeContext, wirev1.Frame{
			Type: wirev1.TypeReliableData, StreamID: 37,
			PlanDigest: planDigest(), Payload: []byte("direction waiter"),
		})
	}()
	waitSignalV3(t, readContext.entered, "legacy receive direction wait")
	waitSignalV3(t, writeContext.entered, "legacy send direction wait")
	client.stateMu.Unlock()
	stateLocked = false
	selected := <-selectDone
	if selected.err != nil || selected.stream == nil {
		t.Fatalf("selection err=%v stream=%v", selected.err, selected.stream)
	}
	if err := <-readDone; !errors.Is(err, ErrCarrier) {
		t.Fatalf("waiting legacy receive: %v", err)
	}
	if err := <-writeDone; !errors.Is(err, ErrCarrier) {
		t.Fatalf("waiting legacy send: %v", err)
	}
	if got := clientBoundary.readCalls.Load(); got != 0 {
		t.Fatalf("waiting legacy receive reached deadline I/O: %d", got)
	}
	if got := clientBoundary.writeCalls.Load(); got != 0 {
		t.Fatalf("waiting legacy send reached deadline I/O: %d", got)
	}
}

func TestRecordStreamV3ConcurrentSelectionAndCloseLeaveClosedIdentity(t *testing.T) {
	for attempt := 0; attempt < 16; attempt++ {
		clientConfig, serverConfig := testConfigs(t)
		client, server, clientErr, serverErr := pair(t, clientConfig, serverConfig)
		if clientErr != nil || serverErr != nil {
			t.Fatalf("attempt %d handshake client=%v server=%v", attempt, clientErr, serverErr)
		}
		start := make(chan struct{})
		var stream *RecordStreamV3
		var selectErr, closeErr error
		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			<-start
			stream, selectErr = client.SelectRecordStreamV3(context.Background(), time.Second)
		}()
		go func() {
			defer group.Done()
			<-start
			closeErr = client.Close()
		}()
		close(start)
		group.Wait()
		if closeErr != nil {
			t.Fatalf("attempt %d close: %v", attempt, closeErr)
		}
		if selectErr != nil && !errors.Is(selectErr, ErrCarrier) {
			t.Fatalf("attempt %d selection: %v", attempt, selectErr)
		}
		if stream != nil {
			if bounds := stream.BoundsV3(); bounds != (RecordStreamBoundsV3{}) {
				t.Fatalf("attempt %d selected view remained live: %+v", attempt, bounds)
			}
			if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, ErrCarrier) {
				t.Fatalf("attempt %d read after concurrent close: %v", attempt, err)
			}
		}
		if _, err := client.CarrierBinding(); !errors.Is(err, ErrCarrier) {
			t.Fatalf("attempt %d binding after concurrent close: %v", attempt, err)
		}
		_ = server.Close()
	}
}

func TestRecordStreamV3PreservesPartialWriteCountWithTerminalError(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	clientBoundary := &failAfterRawWritesConnV3{Conn: clientRaw, failAfter: 1}
	client, server, clientErr, serverErr := pairRaw(
		t, clientBoundary, serverRaw, clientConfig, serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	clientStream, err := client.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientBoundary.writes.Store(0)
	clientBoundary.enabled.Store(true)
	input := bytes.Repeat([]byte{0x5a}, 64<<10)
	type readResult struct {
		value []byte
		err   error
	}
	readDone := make(chan readResult, 1)
	go func() {
		got := make([]byte, 0, len(input))
		buffer := make([]byte, 4096)
		for {
			n, err := serverStream.Read(buffer)
			got = append(got, buffer[:n]...)
			if err != nil {
				readDone <- readResult{value: got, err: err}
				return
			}
		}
	}()
	n, err := clientStream.Write(input)
	if n <= 0 || n >= len(input) || !errors.Is(err, ErrCarrier) {
		t.Fatalf("partial write n=%d len=%d err=%v", n, len(input), err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-readDone:
		if !errors.Is(got.err, ErrCarrier) || len(got.value) != n || !bytes.Equal(got.value, input[:n]) {
			t.Fatalf("peer read bytes=%d want=%d err=%v", len(got.value), n, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer read did not terminate after partial write failure")
	}
}

func TestRecordStreamV3BoundsContainNoPayloadQueue(t *testing.T) {
	viewType := reflect.TypeOf(RecordStreamV3{})
	for index := 0; index < viewType.NumField(); index++ {
		field := viewType.Field(index)
		if field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.String {
			t.Fatalf("selected view retains variable payload field %s %s", field.Name, field.Type)
		}
	}
	connBytes := uint64(unsafe.Sizeof(Conn{}))
	viewBytes := uint64(unsafe.Sizeof(RecordStreamV3{}))
	want := connBytes + viewBytes + 2*recordStreamDirectionAllowanceBytesV3
	if got := RecordStreamOwnedBytesV3(); got != want {
		t.Fatalf("owned bytes=%d want=%d", got, want)
	}
	if allocs := testing.AllocsPerRun(1000, func() { _ = RecordStreamOwnedBytesV3() }); allocs != 0 {
		t.Fatalf("static estimator allocations=%f", allocs)
	}
	t.Logf("Conn=%d RecordStreamV3=%d direction-callback-allowance=%d total=%d", connBytes, viewBytes, recordStreamDirectionAllowanceBytesV3, want)
}

func TestRecordStreamV3CancellationAfterIOClosesBeforeReturning(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	serverBoundary := newResetGateConnV3(serverRaw)
	client, server, clientErr, serverErr := pairRaw(
		t, clientRaw, serverBoundary, clientConfig, serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	clientStream, err := client.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	serverStream, err := server.SelectRecordStreamV3(parent, time.Second)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	serverBoundary.enabled.Store(true)
	readDone := make(chan error, 1)
	go func() {
		_, err := serverStream.Read(make([]byte, 1))
		readDone <- err
	}()
	if _, err := clientStream.Write([]byte{0x44}); err != nil {
		cancel()
		close(serverBoundary.releaseReset)
		t.Fatal(err)
	}
	waitSignalV3(t, serverBoundary.resetEntered, "read deadline reset")
	cancel()
	close(serverBoundary.releaseReset)
	if err := <-readDone; !errors.Is(err, ErrCarrier) {
		t.Fatalf("cancelled completed read: %v", err)
	}
	if _, err := server.CarrierBinding(); !errors.Is(err, ErrCarrier) {
		t.Fatalf("post-I/O cancellation left carrier live: %v", err)
	}
}

func TestRecordStreamV3UsesEarlierParentDeadline(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	clientBoundary := &deadlineTraceConnV3{Conn: clientRaw}
	client, server, clientErr, serverErr := pairRaw(
		t, clientBoundary, serverRaw, clientConfig, serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	parentDeadline := time.Now().Add(500 * time.Millisecond)
	parent, cancel := context.WithDeadline(context.Background(), parentDeadline)
	defer cancel()
	clientStream, err := client.SelectRecordStreamV3(parent, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientBoundary.resetTrace()
	readDone := make(chan error, 1)
	go func() {
		value := make([]byte, 1)
		_, err := io.ReadFull(serverStream, value)
		readDone <- err
	}()
	if _, err := clientStream.Write([]byte{0x51}); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	_, writes := clientBoundary.trace()
	if len(writes) != 2 || !writes[0].Equal(parentDeadline) || !writes[1].IsZero() {
		t.Fatalf("write deadlines=%v parent=%v", writes, parentDeadline)
	}
}

func TestRecordStreamV3RejectsUnavailableDirectionDeadline(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	clientBoundary := &deadlineCountConnV3{Conn: clientRaw}
	client, server, clientErr, serverErr := pairRaw(
		t, clientBoundary, serverRaw, clientConfig, serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	stream, err := client.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientBoundary.readCalls.Store(0)
	clientBoundary.writeCalls.Store(0)
	if n, err := stream.Read(make([]byte, 1)); n != 0 || !errors.Is(err, ErrCarrier) {
		t.Fatalf("read with rejected deadline n=%d err=%v", n, err)
	}
	if n, err := stream.Write([]byte{1}); n != 0 || !errors.Is(err, ErrCarrier) {
		t.Fatalf("write with rejected deadline n=%d err=%v", n, err)
	}
	if clientBoundary.readCalls.Load() != 1 || clientBoundary.writeCalls.Load() != 1 {
		t.Fatalf("deadline calls read=%d write=%d", clientBoundary.readCalls.Load(), clientBoundary.writeCalls.Load())
	}
	if _, err := client.CarrierBinding(); err != nil {
		t.Fatalf("deadline refusal unexpectedly closed carrier: %v", err)
	}
}

func TestRecordStreamV3PreservesZeroLengthNetConnBehavior(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	client, server, clientErr, serverErr := pair(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	stream, err := client.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := stream.Read(nil); n != 0 || err != nil {
		t.Fatalf("zero read n=%d err=%v", n, err)
	}
	if n, err := stream.Write(nil); n != 0 || err != nil {
		t.Fatalf("zero write n=%d err=%v", n, err)
	}
}

func BenchmarkRecordStreamV3CallerBufferRoundTrip(b *testing.B) {
	clientConfig, serverConfig := benchmarkTLSConfigsV3(b)
	clientRaw, serverRaw := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type outcome struct {
		conn *Conn
		err  error
	}
	serverDone := make(chan outcome, 1)
	go func() {
		conn, err := Server(ctx, serverRaw, serverConfig, planDigest(), 128<<10)
		serverDone <- outcome{conn: conn, err: err}
	}()
	client, clientErr := Client(ctx, clientRaw, clientConfig, planDigest(), 128<<10)
	serverResult := <-serverDone
	if clientErr != nil || serverResult.err != nil {
		b.Fatalf("handshake client=%v server=%v", clientErr, serverResult.err)
	}
	defer client.Close()
	defer serverResult.conn.Close()
	clientStream, err := client.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		b.Fatal(err)
	}
	serverStream, err := serverResult.conn.SelectRecordStreamV3(context.Background(), time.Second)
	if err != nil {
		b.Fatal(err)
	}
	input := bytes.Repeat([]byte{0xa5}, 32<<10)
	output := make([]byte, len(input))
	writeDone := make(chan error, 1)
	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	b.ResetTimer()
	go func() {
		for index := 0; index < b.N; index++ {
			if err := writeAllV3(clientStream, input); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()
	for index := 0; index < b.N; index++ {
		if _, err := io.ReadFull(serverStream, output); err != nil {
			b.Fatal(err)
		}
	}
	if err := <-writeDone; err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
	if !bytes.Equal(output, input) {
		b.Fatal("caller buffer bytes changed")
	}
}

func benchmarkTLSConfigsV3(b *testing.B) (*tls.Config, *tls.Config) {
	b.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "phase18.record-stream.test"},
		DNSNames: []string{"phase18.record-stream.test"}, NotBefore: time.Unix(1_700_000_000, 0),
		NotAfter: time.Unix(2_000_000_000, 0), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		b.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		b.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &tls.Config{ServerName: "phase18.record-stream.test", RootCAs: roots},
		&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
}

func waitSignalV3(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func waitMutexHeldV3(t *testing.T, mutex *sync.Mutex, name string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !mutex.TryLock() {
			return
		}
		mutex.Unlock()
		runtime.Gosched()
	}
	t.Fatalf("timed out waiting for %s", name)
}

func testRecordBytesV3(t *testing.T, payload []byte) []byte {
	t.Helper()
	encoded, err := wirev1.Encode(wirev1.Frame{
		Type: wirev1.TypeReliableData, Flags: wirev1.FlagCritical,
		StreamID: 19, PlanDigest: planDigest(), Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	record := make([]byte, 4+len(encoded))
	binary.BigEndian.PutUint32(record[:4], uint32(len(encoded)))
	copy(record[4:], encoded)
	return record
}

func writeFragmentsV3(writer io.Writer, value []byte, fragments []int) error {
	offset := 0
	for _, size := range fragments {
		if offset >= len(value) {
			break
		}
		end := min(offset+size, len(value))
		if err := writeAllV3(writer, value[offset:end]); err != nil {
			return err
		}
		offset = end
	}
	return writeAllV3(writer, value[offset:])
}

func writeAllV3(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		n, err := writer.Write(value)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(value) {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}
