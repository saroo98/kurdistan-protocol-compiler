// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"kurdistan/internal/selfhost"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestMaintenanceHTTPSCertificateInputsAndChainConstraints(t *testing.T) {
	now := time.Now()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	rootKey, issuerKey, leafKey := key(), key(), key()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	sign := func(template, parent *x509.Certificate, public *ecdsa.PublicKey, private *ecdsa.PrivateKey) ([]byte, *x509.Certificate) {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, public, private)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return der, cert
	}
	_, root = sign(root, root, &rootKey.PublicKey, rootKey)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	for _, name := range []string{"valid-chain", "excluded-name", "malformed-leaf", "oversized-certificate-message"} {
		t.Run(name, func(t *testing.T) {
			issuer := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: root.NotBefore, NotAfter: root.NotAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"example.com"}}
			if name == "excluded-name" {
				issuer.ExcludedDNSDomains = []string{"example.com"}
			}
			issuerDER, issuer := sign(issuer, root, &issuerKey.PublicKey, rootKey)
			leaf := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: root.NotBefore, NotAfter: root.NotAfter, DNSNames: []string{"example.com"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			leafDER, _ := sign(leaf, issuer, &leafKey.PublicKey, issuerKey)
			chain := [][]byte{leafDER, issuerDER}
			if name == "malformed-leaf" {
				chain[0] = []byte{0x30, 0x01, 0xff}
			}
			if name == "oversized-certificate-message" {
				// A standard TLS server emits the bounded oversized chain. The
				// product still uses Go's parser and unchanged certificate checks.
				for size := len(leafDER) + len(issuerDER); size <= 256<<10; size += len(issuerDER) {
					chain = append(chain, issuerDER)
				}
			}
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write([]byte("ok"))
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			peer := &tls.Certificate{Certificate: chain, PrivateKey: leafKey}
			server.TLS = &tls.Config{
				Certificates:   []tls.Certificate{{Certificate: [][]byte{leafDER, issuerDER}, PrivateKey: leafKey}},
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return peer, nil },
				MinVersion:     tls.VersionTLS12,
			}
			server.StartTLS()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			raw, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			n, result := maintenanceHTTPSV1(ctx, raw, "https://example.com/", "example.com", pool, func() time.Time { return now }, make([]byte, 2), func() MaintenanceResultV1 { return MaintenanceSuccess })
			if name == "valid-chain" {
				if result != MaintenanceSuccess || n != 2 || requests.Load() != 1 {
					t.Fatalf("valid chain: %d/%d/%d", result, n, requests.Load())
				}
			} else if result != MaintenanceTLSRejected || n != 0 || requests.Load() != 0 || ctx.Err() != nil {
				t.Fatalf("rejection must precede HTTP and timeout: result=%d bytes=%d requests=%d expired=%t", result, n, requests.Load(), ctx.Err() != nil)
			}
		})
	}
}

func TestMaintenanceHTTPSUsesExplicitRootsAndHostname(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/exact?q=1" || r.Header.Get("Accept-Encoding") != "identity" || r.UserAgent() != "" {
			t.Error("request not exact")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("abc"))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	for _, c := range []struct {
		name  string
		roots *x509.CertPool
		want  MaintenanceResultV1
	}{{"example.com", pool, MaintenanceSuccess}, {"wrong.example", pool, MaintenanceTLSRejected}, {"example.com", x509.NewCertPool(), MaintenanceTLSRejected}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		raw, err := net.Dial("tcp", server.Listener.Addr().String())
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		dst := make([]byte, 3)
		n, r := maintenanceHTTPSV1(ctx, raw, "https://"+c.name+"/exact?q=1", c.name, c.roots, time.Now, dst, func() MaintenanceResultV1 { return MaintenanceSuccess })
		cancel()
		if r != c.want || r == MaintenanceSuccess && n != 3 {
			t.Fatalf("%s: n=%d result=%d", c.name, n, r)
		}
	}
}
func TestMaintenanceHTTPSBlockedHandshakeCancelled(t *testing.T) {
	a, b := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan MaintenanceResultV1, 1)
	joined := make(chan struct{})
	peerDone := make(chan struct{})
	observed := make(chan error, 1)
	go func() {
		defer close(peerDone)
		var record [5]byte
		_, err := io.ReadFull(b, record[:])
		observed <- err
		// Do not send ServerHello. Reading the rest proves the client socket
		// closes when the entered handshake is cancelled.
		_, _ = io.Copy(io.Discard, b)
	}()
	go func() {
		defer close(joined)
		_, r := maintenanceHTTPSV1(ctx, a, "https://example.com/", "example.com", x509.NewCertPool(), time.Now, make([]byte, 3), func() MaintenanceResultV1 { return MaintenanceSuccess })
		done <- r
	}()
	t.Cleanup(func() { cancel(); a.Close(); b.Close(); <-joined; <-peerDone })
	select {
	case err := <-observed:
		if err != nil {
			t.Fatal("no handshake I/O", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer never observed handshake")
	}
	cancel()
	select {
	case r := <-done:
		if r != MaintenanceCancelled {
			t.Fatal(r)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake not joined")
	}
	select {
	case <-peerDone:
	case <-time.After(time.Second):
		t.Fatal("cancelled handshake socket stayed open")
	}
}
func TestMaintenanceDestinationFilteringCountsBeforeFilter(t *testing.T) {
	values := [16]netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("2001:4860:4860::8888")}
	n, r := maintenanceFilterAddressesV1(&values, 4, 1)
	if r != MaintenanceSuccess || n != 2 || values[0].String() != "1.1.1.1" || values[1].String() != "8.8.8.8" {
		t.Fatal(n, r)
	}
	if _, r := maintenanceFilterAddressesV1(&values, 17, 3); r != MaintenanceSizeLimit {
		t.Fatal(r)
	}
}
func TestMaintenanceFetchAbsentProviderAndCompetingCandidate(t *testing.T) {
	p := newMaintenanceStateFixture(t)
	var registry HandleRegistry
	p.registry = &registry
	h, code := registry.Open(HandleMaintenance, p)
	if code != CodeOK {
		t.Fatal(code)
	}
	p.handle = h
	got := CheckSameDeploymentUpdateV1(&registry, h, 1000)
	if got.Result != MaintenanceNetworkUnavailable || got.Candidate != 0 {
		t.Fatal(got.Result)
	}
	p.candidate = new(selfhost.LiveMaintenanceCandidate)
	p.candidateID = 1
	n := newMaintenanceTestNetwork()
	e := &maintenanceTestEnvironment{network: n}
	p.transport = e
	got = CheckSameDeploymentUpdateV1(&registry, h, 1000)
	if got.Result != MaintenanceInvalidState || got.Candidate != 0 || got.Preview != (selfhost.LiveMaintenancePreviewV1{}) || e.acquisitions != 0 || n.binds.Load() != 0 {
		t.Fatal("competing candidate reached transport", got)
	}
}

func TestMaintenanceCompletionDeadlineFailureDiscardsUnpublishedChild(t *testing.T) {
	p := newMaintenanceStateFixture(t)
	op, r := p.beginOperation()
	if r != MaintenanceSuccess {
		t.Fatal(r)
	}
	p.candidate = new(selfhost.LiveMaintenanceCandidate)
	p.candidateID = 1
	retired := false
	p.destroyCandidate = func(*selfhost.LiveMaintenanceCandidate) { retired = true }
	op.completionGuard = func() MaintenanceResultV1 { return MaintenanceTimeout }
	got := p.completeCandidatePublication(op, &maintenanceHeldLease{held: new(bool)}, p.candidate, 1, selfhost.LiveMaintenancePreviewV1{})
	p.finishOperation(op)
	if got.Result != MaintenanceTimeout || got.Candidate != 0 || !retired || p.candidate != nil {
		t.Fatal("timed-out publication retained a child")
	}
}

func TestMaintenanceNumericConnectTriesAtMostTwoAndClosesLateSuccess(t *testing.T) {
	values := [16]netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	dial := func(context.Context, netip.AddrPort) (net.Conn, error) { calls++; return nil, io.EOF }
	if c, r := maintenanceConnectV1(ctx, &values, 3, 443, dial, func() MaintenanceResultV1 { return MaintenanceSuccess }); c != nil || r != MaintenanceNetworkUnavailable || calls != 2 {
		t.Fatal(r, calls)
	}
	a, b := net.Pipe()
	defer b.Close()
	dial = func(context.Context, netip.AddrPort) (net.Conn, error) { cancel(); return a, nil }
	if c, r := maintenanceConnectV1(ctx, &values, 3, 443, dial, func() MaintenanceResultV1 { return maintenanceContextResultV1(ctx) }); c != nil || r != MaintenanceCancelled {
		t.Fatal(r)
	}
	if _, err := a.Write([]byte{1}); err == nil {
		t.Fatal("late socket not closed")
	}
}

func TestMaintenanceCompletionChecksParentMonotonicExpiryBeforeTimerScheduling(t *testing.T) {
	p := newMaintenanceStateFixture(t)
	op, _ := p.beginOperation()
	defer p.finishOperation(op)
	p.mu.Lock()
	p.parentTimerAt = time.Now().Add(-time.Second)
	p.mu.Unlock()
	if r := p.checkCompletion(op); r != MaintenanceExpired {
		t.Fatal("elapsed parent admitted completion", r)
	}
	if parentStatusForTest(p) != MaintenanceExpired {
		t.Fatal("parent expiry was not terminal")
	}
}

var _ = tls.VersionTLS12
