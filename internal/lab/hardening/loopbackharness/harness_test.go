// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package loopbackharness

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
	"sync"
	"testing"
	"time"

	"kurdistan/internal/lab/hardening/loopbackresolver"
	"kurdistan/internal/product/livecarrier"
	"kurdistan/internal/product/sessionplan"
)

type testProtectionV1 struct {
	mu      sync.Mutex
	aborted bool
}

type testClientProtectionV1 struct{ owner *testProtectionV1 }
type testRelayProtectionV1 struct{ owner *testProtectionV1 }
type testDeliveryV1 struct {
	owner  *testProtectionV1
	closed bool
}

func (value *testClientProtectionV1) Seal(_ uint16, plaintext []byte) ([]byte, error) {
	value.owner.mu.Lock()
	defer value.owner.mu.Unlock()
	if value.owner.aborted || len(plaintext) == 0 {
		return nil, ErrHarness
	}
	return append([]byte("protected:"), plaintext...), nil
}

func (value *testClientProtectionV1) AcceptAck(record []byte) error {
	value.owner.mu.Lock()
	defer value.owner.mu.Unlock()
	if value.owner.aborted || !bytes.Equal(record, []byte("authenticated-ack")) {
		return ErrHarness
	}
	return nil
}

func (value *testClientProtectionV1) Abort() {
	value.owner.mu.Lock()
	value.owner.aborted = true
	value.owner.mu.Unlock()
}

func (value *testRelayProtectionV1) Open(record []byte) ([]byte, Delivery, error) {
	value.owner.mu.Lock()
	defer value.owner.mu.Unlock()
	prefix := []byte("protected:")
	if value.owner.aborted || !bytes.HasPrefix(record, prefix) || len(record) == len(prefix) {
		return nil, nil, ErrHarness
	}
	return append([]byte(nil), record[len(prefix):]...), &testDeliveryV1{owner: value.owner}, nil
}

func (value *testRelayProtectionV1) Abort() {
	value.owner.mu.Lock()
	value.owner.aborted = true
	value.owner.mu.Unlock()
}

func (delivery *testDeliveryV1) Commit() ([]byte, error) {
	delivery.owner.mu.Lock()
	defer delivery.owner.mu.Unlock()
	if delivery.closed || delivery.owner.aborted {
		return nil, ErrHarness
	}
	delivery.closed = true
	return []byte("authenticated-ack"), nil
}

func (delivery *testDeliveryV1) Reject() {
	delivery.owner.mu.Lock()
	if !delivery.closed {
		delivery.closed = true
		delivery.owner.aborted = true
	}
	delivery.owner.mu.Unlock()
}

type memorySinkV1 struct {
	mu      sync.Mutex
	payload []byte
	err     error
}

func (sink *memorySinkV1) Deliver(_ context.Context, payload []byte) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.err != nil {
		return sink.err
	}
	sink.payload = append([]byte(nil), payload...)
	return nil
}

func harnessTLSConfigsV1(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "phase11.harness.test"},
		DNSNames: []string{"phase11.harness.test"}, NotBefore: time.Unix(1_700_000_000, 0),
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
	return &tls.Config{RootCAs: roots},
		&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
}

func harnessPlanV1() sessionplan.Plan {
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index + 21)
	}
	return sessionplan.Plan{
		Version: sessionplan.Version, StrategyFamily: "https_like_tcp",
		CarrierFamily: livecarrier.FamilyKurdTLS13TCP, LoopbackOnly: true,
		EndpointReference: "relayref:harness", DialTimeoutMs: 1_000,
		MaxFrameBytes: 128 << 10, Digest: digest,
	}
}

func runHarnessV1(t *testing.T, sink *memorySinkV1) (*testProtectionV1, error, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	plan := harnessPlanV1()
	registry, err := loopbackresolver.New([]loopbackresolver.Entry{{
		Reference: plan.EndpointReference, Address: listener.Addr().String(), ServerName: "phase11.harness.test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, serverTLS := harnessTLSConfigsV1(t)
	protection := &testProtectionV1{}
	clientProtection := &testClientProtectionV1{owner: protection}
	relayProtection := &testRelayProtectionV1{owner: protection}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		serverDone <- ServeOne(ctx, raw, plan, serverTLS, relayProtection, sink)
	}()
	clientErr := SendOne(ctx, registry, plan, clientTLS, clientProtection, []byte("owned-loopback-message"))
	return protection, clientErr, <-serverDone
}

func TestLoopbackHarnessBindsCarrierBeforeDeliveryV1(t *testing.T) {
	sink := &memorySinkV1{}
	protection, clientErr, serverErr := runHarnessV1(t, sink)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("client=%v server=%v", clientErr, serverErr)
	}
	protection.mu.Lock()
	aborted := protection.aborted
	protection.mu.Unlock()
	sink.mu.Lock()
	payload := append([]byte(nil), sink.payload...)
	sink.mu.Unlock()
	if aborted || !bytes.Equal(payload, []byte("owned-loopback-message")) {
		t.Fatalf("aborted=%v payload=%q", aborted, payload)
	}
}

func TestLoopbackHarnessSinkFailureAbortsWithoutSuccessV1(t *testing.T) {
	sink := &memorySinkV1{err: errors.New("forced sink failure")}
	protection, clientErr, serverErr := runHarnessV1(t, sink)
	if !errors.Is(clientErr, ErrHarness) || !errors.Is(serverErr, ErrHarness) {
		t.Fatalf("client=%v server=%v", clientErr, serverErr)
	}
	protection.mu.Lock()
	aborted := protection.aborted
	protection.mu.Unlock()
	if !aborted {
		t.Fatal("sink failure did not terminally abort pair")
	}
}
