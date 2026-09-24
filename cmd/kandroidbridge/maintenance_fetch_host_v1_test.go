//go:build phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/selfhost"
)

func maintenanceFetchDNSHostV1(t *testing.T) netip.AddrPort {
	t.Helper()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var input [4096]byte
		for {
			n, peer, err := socket.ReadFromUDP(input[:])
			if err != nil {
				return
			}
			var parser dnsmessage.Parser
			header, err := parser.Start(input[:n])
			if err != nil {
				t.Error(err)
				return
			}
			q, err := parser.Question()
			if err != nil || q.Name.String() != "updates.example." || q.Type != dnsmessage.TypeA {
				t.Error("unexpected signed DNS question", q, err)
				return
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true})
			if err = builder.StartQuestions(); err != nil {
				t.Error(err)
				return
			}
			if err = builder.Question(q); err != nil {
				t.Error(err)
				return
			}
			if err = builder.StartAnswers(); err != nil {
				t.Error(err)
				return
			}
			if err = builder.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}); err != nil {
				t.Error(err)
				return
			}
			output, err := builder.Finish()
			if err != nil {
				t.Error(err)
				return
			}
			if _, err = socket.WriteToUDP(output, peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { socket.Close(); <-done })
	return socket.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestMaintenanceFacadeV1GenuineFetchCandidate38(t *testing.T) {
	maintenanceGenuineFetchCandidateHostV1(t, testMaintenanceCanonicalUpdateCallV1, false)
}

func TestMaintenanceFacadeV1GenuineDisconnectedProbe(t *testing.T) {
	maintenanceGenuineProbeHostV1(t, testMaintenanceCanonicalProbeCallV1)
}

func maintenanceGenuineProbeHostV1(t *testing.T, run func(uint64, []byte, []byte) (int, int32)) {
	for _, scenario := range []string{"complete", "partial-rate", "bind-failure", "current-failure"} {
		t.Run(scenario, func(t *testing.T) {
			policy := &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 1, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1}, TimeoutMillis: 1000}},
				MaxConcurrentOperations: 1, MaxSamplesPerOperation: 2, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 1, MaxOperationMillis: 30000}
			opening, _ := maintenanceFacadeOpeningWithProbesV1(t, 80, policy)
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			var accepts atomic.Int32
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					c, err := listener.AcceptTCP()
					if err != nil {
						return
					}
					accepts.Add(1)
					if err := c.Close(); err != nil {
						t.Error(err)
					}
				}
			}()
			t.Cleanup(func() { listener.Close(); <-done })
			routes := 0
			maintenanceDecisionHostRouteV1 = func(network string, destination netip.AddrPort) netip.AddrPort {
				routes++
				if network != "tcp" || destination != netip.MustParseAddrPort("8.8.8.8:443") {
					t.Error("unexpected signed probe destination", network, destination)
					return netip.AddrPort{}
				}
				if scenario == "current-failure" {
					testMaintenanceNetworkLostV1()
				}
				return listener.Addr().(*net.TCPAddr).AddrPort()
			}
			t.Cleanup(func() { maintenanceDecisionHostRouteV1 = nil })
			parent := testMaintenanceCanonicalParentV1(t, opening)
			if scenario == "bind-failure" {
				testAndroidResultV1(15, int32(androidbridge.MaintenanceNetworkUnavailable))
			}
			request := []byte{1, 0, 1, 1, 3, 232, 3, 232, 1}
			if scenario == "partial-rate" {
				request[8] = 2
			}
			output := bytes.Repeat([]byte{0xa5}, 21)
			n, status := run(parent, request, output)
			if scenario == "bind-failure" || scenario == "current-failure" {
				wantBinds := uint32(1)
				if scenario == "current-failure" {
					wantBinds = 0
				}
				if status != 9 || n != 0 || !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, 21)) || testMaintenanceBindCountV1() != wantBinds || accepts.Load() != 0 {
					t.Fatal("pre-connect failure", n, status, output, testMaintenanceBindCountV1(), accepts.Load())
				}
				return
			}
			completion := uint16(0)
			if scenario == "partial-rate" {
				completion = 6
			}
			if status != 0 || n != 21 || output[1] != 1 || output[3] != 1 || output[4] != 1 || output[5] != 0 || output[6] != request[8]-1 || binary.BigEndian.Uint16(output[19:]) != completion || routes != 1 || testMaintenanceBindCountV1() != 1 {
				t.Fatal("actual disconnected aggregate", n, status, output, routes, testMaintenanceBindCountV1())
			}
			copy(output, bytes.Repeat([]byte{0xa5}, 21))
			n, status = run(parent, request, output)
			if n != 0 || status != 6 || routes != 1 || !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, 21)) {
				t.Fatal("fresh rate denial", n, status, routes, output)
			}
		})
	}
}

func maintenanceGenuineProbeTerminalHostV1(t *testing.T, run func(uint64, []byte, []byte) (int, int32)) {
	for _, scenario := range []string{"partial-timeout", "cancel", "expiry"} {
		t.Run(scenario, func(t *testing.T) {
			policy := &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 1, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1}, TimeoutMillis: 1000}},
				MaxConcurrentOperations: 1, MaxSamplesPerOperation: 2, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 60, MaxOperationMillis: 30000}
			setup := time.Now().UTC().Add(-2 * time.Second)
			if scenario == "expiry" {
				setup = setup.Add(-12*time.Hour + 3*time.Second)
			}
			opening, _ := maintenanceFacadeOpeningWithProbesAtV1(t, 80, policy, setup)
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					c, err := listener.AcceptTCP()
					if err != nil {
						return
					}
					if err = c.Close(); err != nil {
						t.Error(err)
					}
				}
			}()
			t.Cleanup(func() { listener.Close(); <-done })
			entered, release := make(chan struct{}), make(chan struct{})
			routes := 0
			maintenanceDecisionHostRouteV1 = func(network string, destination netip.AddrPort) netip.AddrPort {
				routes++
				if network != "tcp" || destination != netip.MustParseAddrPort("8.8.8.8:443") {
					t.Error("unexpected signed target")
					return netip.AddrPort{}
				}
				if scenario != "partial-timeout" || routes == 2 {
					close(entered)
					<-release
				}
				return listener.Addr().(*net.TCPAddr).AddrPort()
			}
			t.Cleanup(func() { maintenanceDecisionHostRouteV1 = nil })
			parent := testMaintenanceCanonicalParentV1(t, opening)
			request := []byte{1, 0, 1, 1, 3, 232, 11, 184, 2}
			output := bytes.Repeat([]byte{0xa5}, 21)
			type result struct {
				n      int
				status int32
			}
			completed := make(chan result, 1)
			go func() { n, s := run(parent, request, output); completed <- result{n, s} }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("probe did not reach below-policy caller barrier")
			}
			var cancellation chan int32
			if scenario == "cancel" {
				cancellation = make(chan int32, 1)
				go func() { cancellation <- testMaintenanceCanonicalCancelCallV1(parent) }()
				deadline := time.NewTimer(time.Second)
				tick := time.NewTicker(time.Millisecond)
				for androidbridge.MaintenanceStatusV1(&registry, androidbridge.Handle(parent)) != androidbridge.MaintenanceCancelled {
					select {
					case <-tick.C:
					case <-deadline.C:
						tick.Stop()
						close(release)
						t.Fatal("native cancellation fence not reached")
					}
				}
				tick.Stop()
				deadline.Stop()
				select {
				case <-cancellation:
					close(release)
					t.Fatal("cancellation acknowledged before retained native caller returned")
				default:
				}
			} else {
				// Delay is fixture workload, not a proof of timeout: only the actual
				// native completed aggregate/authority refusal below proves its result.
				<-time.NewTimer(4 * time.Second).C
			}
			close(release)
			var got result
			select {
			case got = <-completed:
			case <-time.After(5 * time.Second):
				t.Fatal("probe did not release caller")
			}
			if scenario == "partial-timeout" {
				if got.status != 0 || got.n != 21 || output[3] != 1 || output[4] != 1 || output[6] != 1 || binary.BigEndian.Uint16(output[19:]) != 8 {
					t.Fatal("actual partial timeout", got, output)
				}
			} else {
				want := int32(7)
				if scenario == "expiry" {
					want = 12
				}
				if got.status != want || got.n != 0 || !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, 21)) {
					t.Fatal("actual terminal suppression", got, output)
				}
			}
			if cancellation != nil {
				select {
				case status := <-cancellation:
					if status != 0 {
						t.Fatal("joined cancellation", status)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("cancellation did not join")
				}
			}
		})
	}
}

func TestMaintenanceFacadeV1GenuineProbeTerminal(t *testing.T) {
	maintenanceGenuineProbeTerminalHostV1(t, testMaintenanceCanonicalProbeCallV1)
}

func maintenanceGenuineFetchCandidateHostV1(t *testing.T, check func(uint64, []byte) (int, int32), undelivered bool) {
	t.Helper()
	request, fixture := maintenanceFacadeOpeningWithFixtureV1(t)
	next, err := selfhost.RotateProfile(fixture.dataDir, selfhost.RotateProfileOptions{ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase, Now: time.Now().UTC(), ValidFor: 12 * time.Hour, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: fixture.registryDir})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(next.Artifact)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"updates.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != "updates.example" || r.URL.RequestURI() != "/profile" {
			t.Error("signed URL changed", r.Host, r.URL.RequestURI())
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(next.Artifact)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := make([]byte, 7+len(der))
	roots[0] = 1
	binary.BigEndian.PutUint16(roots[1:], 1)
	binary.BigEndian.PutUint32(roots[3:], uint32(len(der)))
	copy(roots[7:], der)
	testMaintenanceHostRootsV1(t, roots)
	dns, tcp := maintenanceFetchDNSHostV1(t), server.Listener.Addr().(*net.TCPAddr).AddrPort()
	maintenanceDecisionHostRouteV1 = func(kind string, dst netip.AddrPort) netip.AddrPort {
		if kind == "udp" && dst == netip.MustParseAddrPort("1.1.1.1:53") {
			return dns
		}
		if kind == "tcp" && dst == netip.MustParseAddrPort("8.8.8.8:443") {
			return tcp
		}
		t.Error("unexpected validated destination", kind, dst)
		return netip.AddrPort{}
	}
	// Registered before parent cleanup, so LIFO resets only after actual close.
	t.Cleanup(func() { maintenanceDecisionHostRouteV1 = nil; testMaintenanceHostRootsV1(t, nil) })
	parent := testMaintenanceCanonicalParentV1(t, request)
	output := bytes.Repeat([]byte{0xa5}, 38)
	n, status := check(parent, output)
	if undelivered {
		if status != 18 || n != 0 || !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, 38)) || requests.Load() != 1 {
			t.Fatal("genuine candidate publication failure", n, status, requests.Load())
		}
		return
	}
	if status != 0 || n != 38 || output[0] != 1 || binary.BigEndian.Uint16(output[1:3]) != 0 || output[11] != 1 || binary.BigEndian.Uint64(output[12:20]) != 2 || int(binary.BigEndian.Uint32(output[34:])) != len(next.Artifact) {
		t.Fatal("genuine canonical candidate", n, status, output)
	}
	child := binary.BigEndian.Uint64(output[3:11])
	if child == 0 {
		t.Fatal("no acquired candidate")
	}
	materialized := make([]byte, len(next.Artifact))
	defer clear(materialized)
	n, status = testMaintenanceCanonicalMaterializeCallV1(parent, child, materialized)
	if status != 0 || n != len(next.Artifact) || !bytes.Equal(materialized, next.Artifact) || requests.Load() != 1 {
		t.Fatal("genuine fetched artifact", n, status, requests.Load())
	}
}
