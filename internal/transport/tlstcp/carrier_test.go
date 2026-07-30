// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package tlstcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"kurdistan/internal/protocol/wirev1"
)

func testConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "phase11.test"},
		DNSNames: []string{"phase11.test"}, NotBefore: time.Unix(1_700_000_000, 0),
		NotAfter: time.Unix(2_000_000_000, 0), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return &tls.Config{ServerName: "phase11.test", RootCAs: pool}, &tls.Config{Certificates: []tls.Certificate{certificate}}
}

func planDigest() [32]byte {
	var value [32]byte
	for index := range value {
		value[index] = byte(index + 1)
	}
	return value
}

func pair(t *testing.T, clientConfig, serverConfig *tls.Config) (*Conn, *Conn, error, error) {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	return pairRaw(t, clientRaw, serverRaw, clientConfig, serverConfig)
}

func pairRaw(t *testing.T, clientRaw, serverRaw net.Conn, clientConfig, serverConfig *tls.Config) (*Conn, *Conn, error, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	type outcome struct {
		conn *Conn
		err  error
	}
	serverDone := make(chan outcome, 1)
	go func() {
		conn, err := Server(ctx, serverRaw, serverConfig, planDigest(), 128<<10)
		serverDone <- outcome{conn, err}
	}()
	client, clientErr := Client(ctx, clientRaw, clientConfig, planDigest(), 128<<10)
	serverResult := <-serverDone
	return client, serverResult.conn, clientErr, serverResult.err
}

type fragmentConn struct {
	net.Conn
	limit int
}

func (conn fragmentConn) Read(value []byte) (int, error) {
	if len(value) > conn.limit {
		value = value[:conn.limit]
	}
	return conn.Conn.Read(value)
}

func (conn fragmentConn) Write(value []byte) (int, error) {
	return conn.Conn.Write(value)
}

type deadlineRejectConn struct {
	net.Conn
	rejectRead  atomic.Bool
	rejectWrite atomic.Bool
}

func (conn *deadlineRejectConn) SetReadDeadline(deadline time.Time) error {
	if conn.rejectRead.Load() {
		return errors.New("test read deadline rejected")
	}
	return conn.Conn.SetReadDeadline(deadline)
}

func (conn *deadlineRejectConn) SetWriteDeadline(deadline time.Time) error {
	if conn.rejectWrite.Load() {
		return errors.New("test write deadline rejected")
	}
	return conn.Conn.SetWriteDeadline(deadline)
}

type partialWriter struct {
	value []byte
	limit int
}

func (writer *partialWriter) Write(value []byte) (int, error) {
	if len(value) > writer.limit {
		value = value[:writer.limit]
	}
	writer.value = append(writer.value, value...)
	return len(value), nil
}

func TestTLS13CarrierTransfersCanonicalFrame(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	client, server, clientErr, serverErr := pair(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	clientBinding, err := client.CarrierBinding()
	if err != nil {
		t.Fatal(err)
	}
	serverBinding, err := server.CarrierBinding()
	if err != nil || clientBinding != serverBinding {
		t.Fatalf("exporter mismatch: err=%v", err)
	}
	frame := wirev1.Frame{
		Type: wirev1.TypeReliableData, StreamID: 1, PlanDigest: planDigest(),
		Payload: []byte("public deterministic phase11 bytes"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sendDone := make(chan error, 1)
	go func() { sendDone <- client.Send(ctx, frame) }()
	received, err := server.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-sendDone; err != nil {
		t.Fatal(err)
	}
	if string(received.Payload) != string(frame.Payload) || received.PlanDigest != frame.PlanDigest {
		t.Fatalf("received mismatch: %+v", received)
	}
}

func TestTLSCarrierFailsClosedOnTrustAndPlanMismatch(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientConfig.RootCAs = x509.NewCertPool()
	client, server, clientErr, serverErr := pair(t, clientConfig, serverConfig)
	if client != nil || server != nil || !errors.Is(clientErr, ErrCarrier) || !errors.Is(serverErr, ErrCarrier) {
		t.Fatalf("untrusted certificate accepted: client=%v server=%v clientErr=%v serverErr=%v", client, server, clientErr, serverErr)
	}

	clientConfig, serverConfig = testConfigs(t)
	client, server, clientErr, serverErr = pair(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	wrong := planDigest()
	wrong[0] ^= 0xff
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Send(ctx, wirev1.Frame{
		Type: wirev1.TypeReliableData, StreamID: 1, PlanDigest: wrong, Payload: []byte{1},
	}); !errors.Is(err, ErrCarrier) {
		t.Fatalf("mixed plan accepted: %v", err)
	}
}

func TestTLSCarrierRequiresBoundedIOContext(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	client, server, clientErr, serverErr := pair(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	frame := wirev1.Frame{
		Type: wirev1.TypeReliableData, StreamID: 1, PlanDigest: planDigest(), Payload: []byte{1},
	}
	if err := client.Send(context.Background(), frame); !errors.Is(err, ErrCarrier) {
		t.Fatalf("unbounded send accepted: %v", err)
	}
	if _, err := server.Receive(context.Background()); !errors.Is(err, ErrCarrier) {
		t.Fatalf("unbounded receive accepted: %v", err)
	}
}

func TestTLSCarrierRejectsConnectionsThatCannotEnforceDeadlines(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	clientBoundary := &deadlineRejectConn{Conn: clientRaw}
	serverBoundary := &deadlineRejectConn{Conn: serverRaw}
	client, server, clientErr, serverErr := pairRaw(
		t,
		clientBoundary,
		serverBoundary,
		clientConfig,
		serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	frame := wirev1.Frame{
		Type: wirev1.TypeReliableData, StreamID: 1, PlanDigest: planDigest(), Payload: []byte{1},
	}

	clientBoundary.rejectWrite.Store(true)
	if err := client.Send(ctx, frame); !errors.Is(err, ErrCarrier) {
		t.Fatalf("deadline-rejecting send accepted: %v", err)
	}
	serverBoundary.rejectRead.Store(true)
	if _, err := server.Receive(ctx); !errors.Is(err, ErrCarrier) {
		t.Fatalf("deadline-rejecting receive accepted: %v", err)
	}
}

func TestClientRejectsUnsafeTLSConfigurationBeforeHandshake(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := Client(ctx, clientRaw, &tls.Config{InsecureSkipVerify: true}, planDigest(), 64<<10); conn != nil || !errors.Is(err, ErrCarrier) {
		t.Fatalf("unsafe client config accepted: conn=%v err=%v", conn, err)
	}
}

func TestTLSCarrierSurvivesPartialReadsAndWrites(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	clientRaw, serverRaw := net.Pipe()
	client, server, clientErr, serverErr := pairRaw(
		t,
		fragmentConn{Conn: clientRaw, limit: 3},
		fragmentConn{Conn: serverRaw, limit: 5},
		clientConfig,
		serverConfig,
	)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("fragmented handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()
	frame := wirev1.Frame{
		Type: wirev1.TypeReliableData, StreamID: 9, PlanDigest: planDigest(),
		Payload: []byte("fragmented public phase11 record"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sendDone := make(chan error, 1)
	go func() { sendDone <- client.Send(ctx, frame) }()
	received, err := server.Receive(ctx)
	if err != nil || <-sendDone != nil || string(received.Payload) != string(frame.Payload) {
		t.Fatalf("fragmented transport failed: received=%q err=%v", received.Payload, err)
	}
	writer := &partialWriter{limit: 2}
	if err := writeFull(writer, []byte("partial-write")); err != nil ||
		string(writer.value) != "partial-write" {
		t.Fatalf("partial writer failed: value=%q err=%v", writer.value, err)
	}
}

func TestTLSCarrierCloseIsIdempotentAndUnblocksReceive(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	client, server, clientErr, serverErr := pair(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	receiveDone := make(chan error, 1)
	go func() {
		_, err := server.Receive(ctx)
		receiveDone <- err
	}()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	select {
	case err := <-receiveDone:
		if !errors.Is(err, ErrCarrier) {
			t.Fatalf("receive after peer close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer close did not unblock receive")
	}
	_ = server.Close()
}

func TestTLSCarrierCancellationAndOversizedPrefixFailClosed(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	client, server, clientErr, serverErr := pair(t, clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("handshake client=%v server=%v", clientErr, serverErr)
	}
	defer client.Close()
	defer server.Close()

	expired, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := server.Receive(expired); !errors.Is(err, ErrCarrier) {
		t.Fatalf("cancelled receive: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("cancelled receive exceeded bound")
	}

	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], (128<<10)+1)
	writeCtx, writeCancel := context.WithTimeout(context.Background(), time.Second)
	defer writeCancel()
	deadline, _ := writeCtx.Deadline()
	client.stateMu.RLock()
	secured := client.conn
	client.stateMu.RUnlock()
	if secured == nil {
		t.Fatal("client unexpectedly closed")
	}
	_ = secured.SetWriteDeadline(deadline)
	writeDone := make(chan error, 1)
	go func() { writeDone <- writeFull(secured, prefix[:]) }()
	if _, err := server.Receive(writeCtx); !errors.Is(err, ErrCarrier) {
		t.Fatalf("oversized prefix accepted: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write oversized prefix: %v", err)
	}
}

func TestTLSCarrierRejectsPeerHalfClose(t *testing.T) {
	clientConfig, serverConfig := testConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type serverOutcome struct {
		conn *Conn
		err  error
	}
	serverDone := make(chan serverOutcome, 1)
	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- serverOutcome{err: acceptErr}
			return
		}
		conn, establishErr := Server(ctx, raw, serverConfig, planDigest(), 128<<10)
		serverDone <- serverOutcome{conn: conn, err: establishErr}
	}()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := Client(ctx, raw, clientConfig, planDigest(), 128<<10)
	serverResult := <-serverDone
	if err != nil || serverResult.err != nil {
		t.Fatalf("handshake client=%v server=%v", err, serverResult.err)
	}
	defer client.Close()
	defer serverResult.conn.Close()
	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		t.Fatalf("unexpected client connection %T", raw)
	}
	if err := tcp.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := serverResult.conn.Receive(ctx); !errors.Is(err, ErrCarrier) {
		t.Fatalf("half-closed peer accepted: %v", err)
	}
}
