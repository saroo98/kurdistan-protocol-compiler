// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"errors"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/selfhost"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
)

type maintenanceFailingCloseV1 struct{ net.Conn }

func (c *maintenanceFailingCloseV1) Close() error {
	_ = c.Conn.Close()
	return errors.New("injected close uncertainty")
}

func TestMaintenanceCompletedDecisionRawCloseProofV1(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		a, b := net.Pipe()
		socket := newMaintenanceSocketV1(ctx)
		if rejected {
			cancel()
		}
		if socket.install(&maintenanceFailingCloseV1{a}) == rejected {
			t.Fatal("installation state")
		}
		if code := socket.finish(); code != CodeStateCorrupt {
			t.Fatal("close failure lost", code)
		}
		cancel()
		b.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	closeEntered, release := make(chan struct{}), make(chan struct{})
	connection := &maintenanceGatedClose{Conn: &maintenanceFailingCloseV1{a}, entered: closeEntered, release: release}
	socket := newMaintenanceSocketV1(ctx)
	if !socket.install(connection) {
		t.Fatal("install")
	}
	cancel()
	<-closeEntered
	done := make(chan ErrorCode, 1)
	go func() { done <- socket.finish() }()
	select {
	case <-done:
		t.Fatal("close result escaped before hook joined")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case code := <-done:
		if code != CodeStateCorrupt {
			t.Fatal("joined close failure lost", code)
		}
	case <-time.After(time.Second):
		t.Fatal("finish blocked")
	}
}

func TestMaintenanceCompletedDecisionFailedAndStaleDialCleanupV1(t *testing.T) {
	for _, stale := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		a, b := net.Pipe()
		defer b.Close()
		values := [16]netip.Addr{netip.MustParseAddr("8.8.8.8")}
		dial := func(context.Context, netip.AddrPort) (net.Conn, error) {
			if stale {
				cancel()
				return &maintenanceFailingCloseV1{a}, nil
			}
			return &maintenanceFailingCloseV1{a}, errors.New("dial failed with owned socket")
		}
		var cleanup ErrorCode
		conn, result := maintenanceConnectOwnedV1(ctx, &values, 1, 443, dial, func() MaintenanceResultV1 { return maintenanceContextResultV1(ctx) }, &cleanup)
		cancel()
		if conn != nil || cleanup != CodeStateCorrupt || result == MaintenanceSuccess {
			t.Fatal("failed dial cleanup lost", result, cleanup)
		}
	}
}

func TestMaintenanceCompletedDecisionGenuineFetchRejectPreparesV1(t *testing.T) {
	maintenanceGenuineDecisionV1(t, "fetch")
}

func TestMaintenanceCompletedDecisionGenuineSignatureRejectPreparesV1(t *testing.T) {
	maintenanceGenuineDecisionV1(t, "signature")
}

func TestMaintenanceCompletedDecisionGenuineExpiredCandidatePreparesV1(t *testing.T) {
	maintenanceGenuineDecisionV1(t, "expired_candidate")
}

func maintenanceGenuineDecisionV1(t *testing.T, mode string) {
	t.Helper()
	lifetime := 12 * time.Hour
	if mode == "expired_candidate" {
		lifetime = time.Hour
	}
	fixture := newMaintenanceSignedFixtureWithCandidateLifetime(t, lifetime)
	now := fixture.now
	var body []byte
	want := MaintenanceFetchRejected
	if mode == "signature" {
		// The actual bundle's tenth field is its delegation signature. Preserve
		// every other raw canonical field and corrupt only this signature byte.
		var fields []cbor.RawMessage
		if err := cbor.Unmarshal(fixture.replacement, &fields); err != nil || len(fields) != 14 {
			t.Fatal("fixture bundle", err, len(fields))
		}
		var signature []byte
		if err := cbor.Unmarshal(fields[9], &signature); err != nil || len(signature) == 0 {
			t.Fatal("signature", err)
		}
		defer clear(signature)
		signature[0] ^= 1
		encoder, err := cbor.CoreDetEncOptions().EncMode()
		if err != nil {
			t.Fatal(err)
		}
		fields[9], err = encoder.Marshal(signature)
		if err != nil {
			t.Fatal(err)
		}
		body, err = encoder.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(body)
		want = MaintenanceSignatureInvalid
	}
	if mode == "expired_candidate" {
		body, want = fixture.replacement, MaintenanceExpired
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == "fetch" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	dns, _ := maintenanceLocalDNS(t, nil, []netip.Addr{netip.MustParseAddr("8.8.8.8")})
	network := newMaintenanceTestNetwork()
	registry := new(HandleRegistry)
	observer := new(maintenanceOutputTestV1)
	platform := new(maintenanceIntegrationPlatform)
	inv, s := NewMaintenanceOutputInvocationV1(registry, observer, 1, 1, 0)
	if s != 0 {
		t.Fatal(s)
	}
	rates, s := NewMaintenanceUpdateRateRegistryV1(1)
	if s != 0 {
		t.Fatal(s)
	}
	parent, s := OpenMaintenanceV1Scoped(registry, fixture.current, maintenanceRealVerifier{}, platform, MaintenanceConfigV1{
		Now: func() time.Time { return now }, OwnedBudgetBytes: 128 << 20, OutputMetadataBytes: uint64(unsafe.Sizeof(*observer)),
		Limits:    selfhost.LiveMaintenanceLimits{MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20},
		Transport: &maintenanceTestEnvironment{network: network, roots: maintenanceIntegrationRoots(server)}, UpdateRates: rates}, inv)
	if s != 0 {
		t.Fatal("open", s)
	}
	t.Cleanup(func() { registry.Free(parent) })
	if mode == "expired_candidate" {
		now = now.Add(2 * time.Hour)
	}
	p, s := maintenanceParentV1(registry, parent)
	if s != 0 {
		t.Fatal(s)
	}
	observer.mu.Lock()
	observer.lanes[0] = 0
	observer.ended[1] = true
	before := observer.preparedCalls
	observer.mu.Unlock()
	inv, s = NewMaintenanceOutputInvocationV1(registry, observer, 1, 2, p.parentEpoch)
	if s != 0 {
		t.Fatal(s)
	}
	tcp := server.Listener.Addr().(*net.TCPAddr).AddrPort()
	route := func(kind string, dst netip.AddrPort) netip.AddrPort {
		if kind == "udp" && dst == netip.MustParseAddrPort("127.0.0.1:53") {
			return dns
		}
		if kind == "tcp" && dst == netip.MustParseAddrPort("8.8.8.8:443") {
			return tcp
		}
		t.Errorf("unexpected destination %s %v", kind, dst)
		return netip.AddrPort{}
	}
	result, prepared := checkSameDeploymentUpdateDecisionV1(registry, parent, 10000, route, inv)
	if result.Result != want || result.Candidate != 0 || !prepared {
		t.Fatal("actual completed rejection", result.Result, want, result.Candidate, prepared)
	}
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if observer.preparedCalls != before+1 || !observer.preparedFrames[2] || observer.candidate != 0 {
		t.Fatal("completed rejection lacks exact admitted preparation", before, observer.preparedCalls, observer.preparedFrames[2], observer.candidate)
	}
}

func TestMaintenanceCompletedDecisionFreshFenceV1(t *testing.T) {
	for _, mode := range []string{"work_timeout", "cancel", "revoked", "expired_current", "network", "revision", "cleanup", "refused", "repeat"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _, p, observer, inv := maintenanceOutputOpenFixtureV1(t)
			op, result := p.beginOperationOutputV1(inv, false)
			if result != MaintenanceSuccess {
				t.Fatal(result)
			}
			defer p.finishOperation(op)
			network := newMaintenanceTestNetwork()
			if result = p.installTransport(op, &maintenanceTestEnvironment{network: network}); result != MaintenanceSuccess {
				t.Fatal(result)
			}
			original := op.ctx
			if result = p.boundOperation(op, f.now, time.Now().Add(-2*time.Second), f.now.Add(time.Second)); result != MaintenanceSuccess {
				t.Fatal(result)
			}
			before := observer.preparedCalls
			want := MaintenanceSuccess
			switch mode {
			case "cancel":
				op.cancel()
				want = MaintenanceCancelled
			case "revoked":
				p.failOperation(op, MaintenanceRevoked)
				want = MaintenanceRevoked
			case "expired_current":
				p.parentTimerAt = time.Now().Add(-time.Second)
				want = MaintenanceExpired
			case "network":
				network.current.Store(false)
				want = MaintenanceNetworkUnavailable
			case "revision":
				p.registration.(*maintenanceIntegrationPlatform).afterAcquire = func() { p.failOperation(op, MaintenanceCancelled) }
				want = MaintenanceCancelled
			case "cleanup":
				p.publicationCleanupFailure(op, CodeStateCorrupt)
				want = MaintenanceInternalFailure
			case "refused":
				observer.prepareRefuse = MaintenanceResourceLimit
				want = MaintenanceResourceLimit
			}
			if got := p.prepareUpdateDecisionV1(op); got != want {
				t.Fatal("fresh fence", got, want)
			}
			if want == MaintenanceSuccess {
				if observer.preparedCalls != before+1 || !observer.preparedDeadline.Equal(p.parentTimerAt) {
					t.Fatal("missing remaining authority preparation")
				}
			} else if observer.preparedCalls != before {
				t.Fatal("failed fence prepared output")
			}
			if mode == "repeat" || mode == "refused" {
				observer.prepareRefuse = MaintenanceSuccess
				if got := p.prepareUpdateDecisionV1(op); got != MaintenanceInternalFailure {
					t.Fatal("second preparation admitted", got)
				}
			}
			if op.ctx.Err() != context.DeadlineExceeded {
				t.Fatal("work deadline reset", op.ctx.Err())
			}
			if mode == "work_timeout" && original.Err() != nil {
				t.Fatal("result context cancelled", original.Err())
			}
		})
	}
}
