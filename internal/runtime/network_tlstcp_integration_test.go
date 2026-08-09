// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/lab/hardening/loopbackharness"
	"kurdistan/internal/lab/hardening/loopbackresolver"
	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/protocol/wirev1"
	"kurdistan/internal/transport/tlstcp"
)

type phase11RuntimeSinkV1 struct {
	payload []byte
	err     error
}

type phase11RelayAdapterV1 struct {
	relay *NetworkProtectedRelayV1
}

func (adapter phase11RelayAdapterV1) Open(record []byte) ([]byte, loopbackharness.Delivery, error) {
	payload, delivery, err := adapter.relay.Open(record)
	return payload, delivery, err
}

func (adapter phase11RelayAdapterV1) Abort() {
	adapter.relay.Abort()
}

func (sink *phase11RuntimeSinkV1) Deliver(_ context.Context, payload []byte) error {
	if sink.err != nil {
		return sink.err
	}
	sink.payload = append([]byte(nil), payload...)
	return nil
}

func phase11TLSConfigsV1(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "phase11.runtime.test"},
		DNSNames: []string{"phase11.runtime.test"}, NotBefore: time.Unix(1_700_000_000, 0),
		NotAfter: time.Unix(2_000_000_000, 0), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return &tls.Config{ServerName: "phase11.runtime.test", RootCAs: roots},
		&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
}

func phase11TLSPairV1(t *testing.T, digest [32]byte) (*tlstcp.Conn, *tlstcp.Conn) {
	t.Helper()
	clientConfig, serverConfig := phase11TLSConfigsV1(t)
	clientRaw, serverRaw := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	type result struct {
		conn *tlstcp.Conn
		err  error
	}
	serverDone := make(chan result, 1)
	go func() {
		conn, err := tlstcp.Server(ctx, serverRaw, serverConfig, digest, 128<<10)
		serverDone <- result{conn: conn, err: err}
	}()
	client, clientErr := tlstcp.Client(ctx, clientRaw, clientConfig, digest, 128<<10)
	serverResult := <-serverDone
	if clientErr != nil || serverResult.err != nil {
		t.Fatalf("TLS carrier establishment client=%v server=%v", clientErr, serverResult.err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = serverResult.conn.Close()
	})
	return client, serverResult.conn
}

func TestAuthenticatedKurdRecordAcrossTLSCarrierV1(t *testing.T) {
	networkClient, networkRelay, _, _ := newNetworkProtectedPairV1(t, 9110)
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index + 11)
	}
	carrierClient, carrierRelay := phase11TLSPairV1(t, digest)
	clientBinding, err := carrierClient.CarrierBinding()
	if err != nil {
		t.Fatal(err)
	}
	relayBinding, err := carrierRelay.CarrierBinding()
	if err != nil || clientBinding != relayBinding {
		t.Fatalf("carrier binding mismatch: %v", err)
	}
	statement := make([]byte, 72)
	copy(statement[:8], []byte("KRDBND01"))
	copy(statement[8:40], clientBinding[:])
	copy(statement[40:72], digest[:])
	bindRecord, err := networkClient.Seal(1, statement)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	bindSend := make(chan error, 1)
	go func() {
		bindSend <- carrierClient.Send(ctx, wirev1.Frame{
			Type: wirev1.TypeProfileBind, PlanDigest: digest, Payload: bindRecord,
		})
	}()
	bindFrame, err := carrierRelay.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-bindSend; err != nil {
		t.Fatal(err)
	}
	openedStatement, bindingDelivery, err := networkRelay.Open(bindFrame.Payload)
	clear(bindFrame.Payload)
	if err != nil || !bytes.Equal(openedStatement, statement) {
		t.Fatalf("binding statement=%x err=%v", openedStatement, err)
	}
	clear(openedStatement)
	readyAck, err := bindingDelivery.Commit()
	if err != nil {
		t.Fatal(err)
	}
	readySend := make(chan error, 1)
	go func() {
		readySend <- carrierRelay.Send(ctx, wirev1.Frame{
			Type: wirev1.TypeEngineReady, PlanDigest: digest, Payload: readyAck,
		})
	}()
	readyFrame, err := carrierClient.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-readySend; err != nil {
		t.Fatal(err)
	}
	if err := networkClient.AcceptAck(readyFrame.Payload); err != nil {
		t.Fatal(err)
	}
	clear(readyFrame.Payload)

	plaintext := []byte("inner-authenticated-kurd-session")
	protected, err := networkClient.Seal(3, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(protected, plaintext) {
		t.Fatal("inner record exposed plaintext before carrier")
	}

	clientSend := make(chan error, 1)
	go func() {
		clientSend <- carrierClient.Send(ctx, wirev1.Frame{
			Type: wirev1.TypeReliableData, StreamID: 3, PlanDigest: digest, Payload: protected,
		})
	}()
	inbound, err := carrierRelay.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-clientSend; err != nil {
		t.Fatal(err)
	}
	delivered, delivery, err := networkRelay.Open(inbound.Payload)
	clear(inbound.Payload)
	if err != nil || !bytes.Equal(delivered, plaintext) {
		t.Fatalf("relay delivery=%q err=%v", delivered, err)
	}
	acknowledgement, err := delivery.Commit()
	if err != nil {
		t.Fatal(err)
	}

	relaySend := make(chan error, 1)
	go func() {
		relaySend <- carrierRelay.Send(ctx, wirev1.Frame{
			Type: wirev1.TypeReliableData, StreamID: 3, PlanDigest: digest, Payload: acknowledgement,
		})
	}()
	ackFrame, err := carrierClient.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-relaySend; err != nil {
		t.Fatal(err)
	}
	if err := networkClient.AcceptAck(ackFrame.Payload); err != nil {
		t.Fatal(err)
	}
	clear(ackFrame.Payload)
}

func TestProcessTLSTCPDuplexCarrierV1PreservesExactWireRecords(t *testing.T) {
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index + 41)
	}
	client, relay := phase11TLSPairV1(t, digest)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	clientAdapter, err := NewProcessTLSTCPDuplexCarrierV1(ctx, client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	relayAdapter, err := NewProcessTLSTCPDuplexCarrierV1(ctx, relay, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := wirev1.Encode(wirev1.Frame{Type: wirev1.TypeReliableData, Flags: wirev1.FlagCritical, StreamID: 9, PlanDigest: digest, Payload: []byte("duplex-adapter")})
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() { writeDone <- writeBoundedRecordV1(clientAdapter, encoded) }()
	got, err := readBoundedCarrierRecordV1(relayAdapter, len(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, encoded) {
		t.Fatal("TLS adapter changed the wire record")
	}
	clear(got)
	clear(encoded)
}

func TestProcessTLSTCPDuplexCarrierV1BoundsIOWithDeadlineFreeParent(t *testing.T) {
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index + 91)
	}
	client, relay := phase11TLSPairV1(t, digest)
	clientAdapter, err := NewProcessTLSTCPDuplexCarrierV1(context.Background(), client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	relayAdapter, err := NewProcessTLSTCPDuplexCarrierV1(context.Background(), relay, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := wirev1.Encode(wirev1.Frame{Type: wirev1.TypeReliableData, StreamID: 11, PlanDigest: digest, Payload: []byte("deadline-free-parent")})
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() { writeDone <- writeBoundedRecordV1(clientAdapter, encoded) }()
	got, err := readBoundedCarrierRecordV1(relayAdapter, len(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, encoded) {
		t.Fatal("TLS adapter changed the wire record")
	}
	clear(got)
	clear(encoded)
}

func TestProcessTLSTCPDuplexCarrierV1RejectsInvalidIdleTimeout(t *testing.T) {
	var digest [32]byte
	digest[0] = 1
	client, _ := phase11TLSPairV1(t, digest)
	for _, idleTimeout := range []time.Duration{0, -time.Second, maxProcessTLSTCPIdleTimeoutV1 + time.Nanosecond} {
		if _, err := NewProcessTLSTCPDuplexCarrierV1(context.Background(), client, idleTimeout); !errors.Is(err, ErrProcessSessionV1) {
			t.Fatalf("idle timeout %s: expected rejection, got %v", idleTimeout, err)
		}
	}
}

func TestProcessTLSTCPDuplexCarrierV1DeadlineFreeReadTimesOut(t *testing.T) {
	var digest [32]byte
	digest[0] = 2
	client, _ := phase11TLSPairV1(t, digest)
	adapter, err := NewProcessTLSTCPDuplexCarrierV1(context.Background(), client, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := adapter.Read(make([]byte, 128)); err == nil {
		t.Fatal("deadline-free read unexpectedly remained valid without peer data")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded read exceeded its fail-closed deadline: %s", elapsed)
	}
}

func TestProcessDuplexOperationAcrossTLSCarrierV1(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	config, err := auth.NewProcessHandshakeConfigV1(fixture.input.Client, fixture.input.Server, fixture.input.SelectedPolicy, fixture.input.SelectedCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index + 71)
	}
	clientCarrier, relayCarrier := phase11TLSPairV1(t, digest)
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	clientHandshake, err := NewProcessWireClientHandshakeV1(config, fixture.input.ClientDependencies, digest)
	if err != nil {
		t.Fatal(err)
	}
	relayHandshake, err := NewProcessWireRelayHandshakeV1(config, fixture.input.ServerDependencies, replay, digest)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sink := &phase11RuntimeSinkV1{}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- RunProcessRelayDuplexOperationV1(ctx, relayCarrier, relayHandshake, digest, testDuplexProgramV1(), sink)
	}()
	payload := []byte("profile-shaped-duplex-tls")
	clientErr := RunProcessClientDuplexOperationV1(ctx, clientCarrier, clientHandshake, digest, testDuplexProgramV1(), framing.Operation{Semantic: "data", StreamID: 17, Sequence: 1, Payload: payload})
	serverErr := <-serverDone
	if clientErr != nil || serverErr != nil {
		t.Fatalf("client=%v relay=%v", clientErr, serverErr)
	}
	if !bytes.Equal(sink.payload, payload) {
		t.Fatalf("sink=%x", sink.payload)
	}
}

func TestRealProtectedPairThroughLoopbackHarnessV1(t *testing.T) {
	networkClient, networkRelay, rawClient, rawRelay := newNetworkProtectedPairV1(t, 9111)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index + 31)
	}
	plan := loopbackharness.NewLocalConformancePlanV1("relayref:runtime-harness", digest, 1_000, 128<<10)
	registry, err := loopbackresolver.New([]loopbackresolver.Entry{{
		Reference: plan.EndpointReference, Address: listener.Addr().String(), ServerName: "phase11.runtime.test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, serverTLS := phase11TLSConfigsV1(t)
	sink := &phase11RuntimeSinkV1{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		serverDone <- loopbackharness.ServeOne(ctx, raw, plan, serverTLS, phase11RelayAdapterV1{relay: networkRelay}, sink)
	}()
	clientErr := loopbackharness.SendOne(ctx, registry, plan, clientTLS, networkClient, []byte("real-protected-loopback"))
	serverErr := <-serverDone
	if clientErr != nil || serverErr != nil {
		t.Fatalf("client=%v server=%v", clientErr, serverErr)
	}
	if !bytes.Equal(sink.payload, []byte("real-protected-loopback")) {
		t.Fatalf("sink payload=%q", sink.payload)
	}
	if rawClient.state.life.sendCompleted != 2 || rawRelay.state.life.receiveCompleted != 2 {
		t.Fatalf("commits=%d/%d", rawClient.state.life.sendCompleted, rawRelay.state.life.receiveCompleted)
	}
}

func TestRealProtectedPairSinkFailureEmitsNoSuccessV1(t *testing.T) {
	networkClient, networkRelay, rawClient, rawRelay := newNetworkProtectedPairV1(t, 9112)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index + 41)
	}
	plan := loopbackharness.NewLocalConformancePlanV1("relayref:runtime-failure", digest, 1_000, 128<<10)
	registry, err := loopbackresolver.New([]loopbackresolver.Entry{{
		Reference: plan.EndpointReference, Address: listener.Addr().String(), ServerName: "phase11.runtime.test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, serverTLS := phase11TLSConfigsV1(t)
	sink := &phase11RuntimeSinkV1{err: errors.New("forced downstream failure")}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		serverDone <- loopbackharness.ServeOne(ctx, raw, plan, serverTLS, phase11RelayAdapterV1{relay: networkRelay}, sink)
	}()
	clientErr := loopbackharness.SendOne(ctx, registry, plan, clientTLS, networkClient, []byte("must-not-ack"))
	serverErr := <-serverDone
	if !errors.Is(clientErr, loopbackharness.ErrHarness) || !errors.Is(serverErr, loopbackharness.ErrHarness) {
		t.Fatalf("client=%v server=%v", clientErr, serverErr)
	}
	if rawClient.State() != auth.StateClosed || rawRelay.State() != auth.StateClosed {
		t.Fatalf("failure states=%s/%s", rawClient.State(), rawRelay.State())
	}
}

func TestProcessSeparatedHandshakeAndRecordsAcrossTLSCarrierV1(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index + 61)
	}
	clientCarrier, relayCarrier := phase11TLSPairV1(t, digest)
	clientHandshake, relayHandshake := phase11ProcessWireHandshakesV1(t, fixture, digest)
	sink := &phase11RuntimeSinkV1{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- RunProcessRelaySessionV1(ctx, relayCarrier, relayHandshake, digest, sink)
	}()
	clientErr := RunProcessClientSessionV1(ctx, clientCarrier, clientHandshake, digest, 9, []byte("process-separated-kurd-session"))
	relayErr := <-relayDone
	if clientErr != nil || relayErr != nil {
		t.Fatalf("client=%v relay=%v", clientErr, relayErr)
	}
	if !bytes.Equal(sink.payload, []byte("process-separated-kurd-session")) {
		t.Fatalf("sink payload=%q", sink.payload)
	}
}

func TestProcessSeparatedTLSDeliveryFailureEmitsNoAckV1(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index + 91)
	}
	clientCarrier, relayCarrier := phase11TLSPairV1(t, digest)
	clientHandshake, relayHandshake := phase11ProcessWireHandshakesV1(t, fixture, digest)
	sink := &phase11RuntimeSinkV1{err: errors.New("forced process sink failure")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- RunProcessRelaySessionV1(ctx, relayCarrier, relayHandshake, digest, sink)
	}()
	clientErr := RunProcessClientSessionV1(ctx, clientCarrier, clientHandshake, digest, 10, []byte("must-not-ack-process"))
	relayErr := <-relayDone
	if !errors.Is(clientErr, ErrProcessSessionV1) || !errors.Is(relayErr, ErrProcessSessionV1) {
		t.Fatalf("client=%v relay=%v", clientErr, relayErr)
	}
}

func phase11ProcessWireHandshakesV1(t *testing.T, fixture strictSupportFixtureV1, digest [32]byte) (*ProcessWireClientHandshakeV1, *ProcessWireRelayHandshakeV1) {
	t.Helper()
	config, err := auth.NewProcessHandshakeConfigV1(
		fixture.input.Client,
		fixture.input.Server,
		fixture.input.SelectedPolicy,
		fixture.input.SelectedCapabilities,
	)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewProcessWireClientHandshakeV1(config, fixture.input.ClientDependencies, digest)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewProcessWireRelayHandshakeV1(config, fixture.input.ServerDependencies, replay, digest)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	return client, relay
}
