//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTask7MaintenanceObservationClassifiesActualWrappedCauseAndKeepsFirst(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int64
	}{
		{x509.UnknownAuthorityError{}, 1}, {&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, 1},
		{x509.HostnameError{}, 2}, {x509.CertificateInvalidError{}, 3}, {context.DeadlineExceeded, 4},
		{context.Canceled, 5}, {errors.New("fixed unrelated error"), 6},
	} {
		o := &task7HandshakeObservationV1{category: -1}
		ctx := context.WithValue(context.Background(), task7HandshakeKeyV1{}, o)
		maintenanceObserveHandshakeFailureV1(ctx, tc.err)
		maintenanceObserveHandshakeFailureV1(ctx, context.Canceled)
		if !o.observed || o.category != tc.want {
			t.Fatalf("category=%d want=%d", o.category, tc.want)
		}
	}
	maintenanceObserveHandshakeFailureV1(context.Background(), x509.UnknownAuthorityError{})
}

func task7MaintenanceOpenTestV1(t *testing.T) (*HandleRegistry, Handle, *maintenanceAuthorityV1, *maintenanceOutputTestV1, MaintenanceOutputInvocationV1, *task7RootsEnvironmentTestV1) {
	_, r, h, p, o, inv := maintenanceOutputOpenFixtureV1(t)
	e := &task7RootsEnvironmentTestV1{maintenanceTestEnvironment: maintenanceTestEnvironment{network: newMaintenanceTestNetwork(), roots: maintenanceRootFixture(t)}}
	op, s := p.beginOperationOutputV1(inv, false)
	if s != 0 {
		t.Fatal(s)
	}
	if s = p.installTransport(op, e); s != 0 {
		t.Fatal(s)
	}
	p.finishOperation(op)
	o.mu.Lock()
	o.lanes[0] = 0
	o.mu.Unlock()
	inv.call++
	return r, h, p, o, inv, e
}

type task7RootsEnvironmentTestV1 struct {
	maintenanceTestEnvironment
	calls      int
	refusal    MaintenanceResultV1
	afterRoots func(context.Context)
}

func (e *task7RootsEnvironmentTestV1) SystemRootsInto(ctx context.Context, dst []byte) (int, MaintenanceResultV1) {
	e.calls++
	if e.refusal != 0 {
		return 0, e.refusal
	}
	n, result := e.maintenanceTestEnvironment.SystemRootsInto(ctx, dst)
	if e.afterRoots != nil {
		e.afterRoots(ctx)
	}
	return n, result
}

func TestTask7MaintenanceCancellationDuringOwnedRootsAndActualTLS(t *testing.T) {
	for _, stage := range []string{"roots", "tls-verification"} {
		t.Run(stage, func(t *testing.T) {
			r, h, p, observer, inv, environment := task7MaintenanceOpenTestV1(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseGate()
			var rootsReturned atomic.Bool
			var gateTimedOut atomic.Bool
			var postRootsClock atomic.Int32
			gate := func() {
				close(entered)
				select {
				case <-release:
				case <-time.After(3 * time.Second):
					gateTimedOut.Store(true)
				}
			}
			environment.afterRoots = func(context.Context) {
				if stage == "roots" {
					gate()
				}
				rootsReturned.Store(true)
			}
			originalNow := p.now
			p.now = func() time.Time {
				// Fixed entry: first post-roots call is trustedNow before certificate
				// construction; second is crypto/tls Config.Time during verification.
				// Keep the real configured time unchanged. Actual TLS counters below
				// independently prove this is not an early platform/roots gate.
				if stage == "tls-verification" && rootsReturned.Load() && postRootsClock.Add(1) == 2 {
					gate()
				}
				return originalNow()
			}
			type measured struct {
				values [24]int64
				result MaintenanceResultV1
			}
			finished := make(chan measured, 1)
			go func() {
				values, result := Task7MaintenanceFixtureRunV1(r, h, 2, inv)
				finished <- measured{values, result}
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("actual requested stage not entered")
			}
			p.mu.Lock()
			operation := p.operation
			p.mu.Unlock()
			if operation == nil {
				t.Fatal("stage has no admitted operation")
			}
			cancelled := make(chan ErrorCode, 1)
			go func() { cancelled <- r.Cancel(h) }()
			select {
			case <-operation.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("real parent did not cancel operation")
			}
			select {
			case <-operation.done:
				t.Fatal("operation completed while actual stage blocked")
			default:
			}
			select {
			case <-finished:
				t.Fatal("entry returned before actual stage joined")
			default:
			}
			releaseGate()
			var got measured
			select {
			case got = <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("entry did not join cancelled stage")
			}
			select {
			case code := <-cancelled:
				if code != CodeOK {
					t.Fatal("parent cancellation cleanup", code)
				}
			case <-time.After(time.Second):
				t.Fatal("parent cancellation did not join")
			}
			if got.result != MaintenanceCancelled || got.values[18] != 1 || got.values[19] != 0 || got.values[20] != 0 || got.values[21] != 0 || got.values[22] != -1 || got.values[23] != -1 {
				t.Fatal("cancelled operation outcome", got.result, got.values)
			}
			select {
			case <-operation.done:
			default:
				t.Fatal("op.done not joined")
			}
			p.mu.Lock()
			retained := p.operation != nil || p.pendingCandidate != nil || p.candidate != nil
			p.mu.Unlock()
			observer.mu.Lock()
			prepares := observer.preparedCalls
			observer.mu.Unlock()
			if gateTimedOut.Load() {
				t.Fatal("stage watchdog expired; not cancellation evidence")
			}
			if retained || prepares != 1 {
				t.Fatal("cancelled operation retained state or prepared late output", prepares)
			}
			if stage == "roots" {
				if got.values[10] != -1 || got.values[11] != -1 {
					t.Fatal("cancelled roots started TLS")
				}
			} else if got.values[8] != int64(MaintenanceCancelled) || got.values[10] != 1 || got.values[11] != 1 || got.values[13] != 0 || got.values[14] != 0 || got.values[15] != 0 || got.values[16] != 1 {
				t.Fatal("actual TLS workers/socket not joined", got.values)
			}
		})
	}
}

func TestTask7MaintenanceOwnedCasesPrepareAndReleaseRealOperation(t *testing.T) {
	for _, caseID := range []uint32{1, 2, 3} {
		t.Run(string(rune('0'+caseID)), func(t *testing.T) {
			r, h, p, o, inv, e := task7MaintenanceOpenTestV1(t)
			out, s := Task7MaintenanceFixtureRunV1(r, h, caseID, inv)
			if s != 0 {
				t.Fatal("entry", s)
			}
			if out[0] != 1 || out[1] != int64(caseID) || out[2] != 1 || out[3] != 0 || out[7] != 0 || out[17] != 0 || out[18] != 1 || out[19] != 0 || out[20] != 0 || out[21] != 0 || out[22] != -1 || out[23] != -1 {
				t.Fatal("measurement", out)
			}
			if p.operation != nil || o.preparedCalls != 2 || o.candidate != 0 || !o.preparedDeadline.After(time.Now()) {
				t.Fatal("operation/output lifetime")
			}
			if caseID == 3 {
				if e.calls != 0 || out[4] != -1 || out[8] != -1 {
					t.Fatal("ownership case invoked transport")
				}
			} else if e.calls != 1 || out[4] != 0 || out[5] != 1 || out[6] != int64(len(e.roots)) {
				t.Fatal("actual roots", out[4:7], e.calls)
			}
			if caseID == 2 && (out[8] != 13 || out[9] != 1 || out[10] != 1 || out[11] != 1 || out[12] != 1 || out[13] != 0 || out[14] != 0 || out[15] != 0 || out[16] != 1) {
				t.Fatal("actual negative TLS", out[8:17])
			}
		})
	}
}

func TestTask7SignedHTTPSAndBlockedHandshakeJoin(t *testing.T) {
	for _, id := range []uint32{301, 302} {
		r, h, p, _, inv, _ := task7MaintenanceOpenTestV1(t)
		out, status := Task7MaintenanceFixtureRunV1(r, h, id, inv)
		if status != 0 {
			t.Fatalf("case %d: status %d", id, status)
		}
		if out[10] != 1 || out[15] != 0 || out[16] != 1 || out[18] != 1 || out[19] != 0 || out[20] != 0 || out[21] != 0 || p.operation != nil {
			t.Fatalf("case %d lifetime: %v", id, out)
		}
		if id == 301 && (out[8] != 0 || out[9] != 1 || out[13] != 1 || out[14] <= 0 || out[14] > 65536) {
			t.Fatal("signed HTTPS", out)
		}
		if id == 302 && (out[8] != int64(MaintenanceCancelled) || out[9] != 1 || out[13] != 0 || out[14] != 0) {
			t.Fatal("blocked handshake", out)
		}
	}
}

func TestTask7MaintenanceRejectsInvalidAdmissionBeforeRoots(t *testing.T) {
	for _, mode := range []string{"legacy", "wrong-epoch", "wrong-owner", "stale-handle", "wrong-kind", "overlap", "cancelled", "lane", "bad-case", "prepare", "roots"} {
		t.Run(mode, func(t *testing.T) {
			r, h, p, o, inv, e := task7MaintenanceOpenTestV1(t)
			caseID := uint32(2)
			switch mode {
			case "legacy":
				inv = MaintenanceOutputInvocationV1{}
			case "wrong-epoch":
				inv.epoch++
			case "wrong-owner":
				inv.owner++
			case "stale-handle":
				h++
			case "wrong-kind":
				h = Handle(1)
			case "overlap":
				op, s := p.beginOperationOutputV1(inv, false)
				if s != 0 {
					t.Fatal(s)
				}
				defer p.finishOperation(op)
			case "cancelled":
				r.Cancel(h)
			case "lane":
				o.refuse = MaintenanceResourceLimit
			case "bad-case":
				caseID = 4
			case "prepare":
				o.prepareRefuse = MaintenanceResourceLimit
			case "roots":
				e.refusal = MaintenanceTLSTrustUnavailable
			}
			out, s := Task7MaintenanceFixtureRunV1(r, h, caseID, inv)
			if s == 0 {
				t.Fatal("rejected case passed", mode, out)
			}
			if mode != "prepare" && mode != "roots" && e.calls != 0 {
				t.Fatal("roots before admission")
			}
			if mode == "roots" && (out[10] != -1 || out[18] != 1) {
				t.Fatal("roots failure dialled or failed to join", out)
			}
			if mode != "overlap" && p.operation != nil {
				t.Fatal("operation retained")
			}
		})
	}
}
