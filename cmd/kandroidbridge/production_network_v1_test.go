// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestProductionNetworkV1PureWorkspace(t *testing.T) {
	policy, seed, now := releasePolicyFixture(t)
	defer clear(seed)
	program, err := liveprogram.DecodeV1(policy.LiveProgram)
	if err != nil {
		t.Fatal(err)
	}
	// This numerical test claims no admission; use the actual bounded fields.
	plan := sessionplan.PlanV2{ProfileContentID: "fixture", StrategyID: "strategy.kurd-tls13-tcp", Endpoints: policy.Endpoints, Routes: policy.Routes, IPMode: policy.AllowedIPModes[0], PayloadProtocols: policy.AllowedProtocols, MTU: 1280, ProfileGeneration: 1}
	_ = now
	n, err := productionNetworkWorkspaceV1(plan, policy, program)
	if err != nil || n == 0 {
		t.Fatalf("workspace %d %v", n, err)
	}
	if a := testing.AllocsPerRun(20, func() { _, _ = productionNetworkWorkspaceV1(plan, policy, program) }); a != 0 {
		t.Fatal(a)
	}
}

type productionBlockedCloseV1 struct {
	entered, release chan struct{}
	calls            atomic.Int32
}

func (c *productionBlockedCloseV1) Read([]byte) (int, error)  { return 0, net.ErrClosed }
func (c *productionBlockedCloseV1) Write([]byte) (int, error) { return 0, net.ErrClosed }
func (c *productionBlockedCloseV1) Close() error {
	if c.calls.Add(1) == 1 {
		close(c.entered)
	}
	<-c.release
	return net.ErrClosed
}
func (c *productionBlockedCloseV1) LocalAddr() net.Addr              { return nil }
func (c *productionBlockedCloseV1) RemoteAddr() net.Addr             { return nil }
func (c *productionBlockedCloseV1) SetDeadline(time.Time) error      { return nil }
func (c *productionBlockedCloseV1) SetReadDeadline(time.Time) error  { return nil }
func (c *productionBlockedCloseV1) SetWriteDeadline(time.Time) error { return nil }

func TestProductionNetworkV1RawCloseAllCallersJoin(t *testing.T) {
	n := newProductionTransportRootV1(nil, make(chan struct{}), time.Now().Add(time.Minute))
	raw := &productionBlockedCloseV1{entered: make(chan struct{}), release: make(chan struct{})}
	n.mu.Lock()
	n.raw = raw
	n.connectorSettled = true
	close(n.connectorDone)
	n.mu.Unlock()
	done := make(chan error, 2)
	go func() { done <- n.facade.Close() }()
	<-raw.entered
	go func() { done <- n.facade.Close() }()
	select {
	case <-done:
		t.Fatal("returned before actual Close")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-n.closerDone:
		t.Fatal("worker retired before Close")
	default:
	}
	close(raw.release)
	for range 2 {
		if e := <-done; !errors.Is(e, net.ErrClosed) {
			t.Fatal(e)
		}
	}
	<-n.closerDone
	if raw.calls.Load() != 1 {
		t.Fatal("multiple close owners")
	}
}

func TestProductionNetworkV1StageContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deadline := time.Now().Add(-time.Second)
	v := productionStageContextV1{leaf: ctx, deadline: deadline}
	if v.Err() != nil || v.Value("caller") != nil {
		t.Fatal("view invented cancellation or values")
	}
	if d, ok := v.Deadline(); !ok || !d.Equal(deadline) {
		t.Fatal("deadline")
	}
	cancel()
	if !errors.Is(v.Err(), context.Canceled) {
		t.Fatal(v.Err())
	}
}

func TestProductionNetworkV1ExpiryObservationCannotCancelReplacement(t *testing.T) {
	for _, replacement := range []string{"serial", "deadline", "disarm"} {
		t.Run(replacement, func(t *testing.T) {
			n := newProductionTransportRootV1(nil, make(chan struct{}), time.Now().Add(time.Minute))
			defer n.FinishV1()
			observed, resume, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				n.mu.Lock()
				serial, deadline := n.serial, n.deadline
				n.mu.Unlock()
				close(observed)
				<-resume
				// Both worker expiry paths use this production decision, with an
				// observation that became expired while its decision was paused.
				n.expireObservedV1(serial, deadline, deadline.Add(time.Nanosecond))
				close(returned)
			}()
			<-observed
			n.mu.Lock()
			switch replacement {
			case "serial":
				n.serial++
			case "deadline":
				n.deadline = n.deadline.Add(time.Minute)
			case "disarm":
				n.deadline = time.Time{}
			}
			n.mu.Unlock()
			close(resume)
			<-returned
			if n.leaf.Err() != nil {
				t.Fatal("stale observation cancelled replacement", n.leaf.Err())
			}
		})
	}
}

func TestProductionNetworkV1TimerCurrentStageAndAuthority(t *testing.T) {
	n := newProductionTransportRootV1(nil, make(chan struct{}), time.Now().Add(time.Second))
	n.mu.Lock()
	n.serial = 1
	n.deadline = time.Now().Add(20 * time.Millisecond)
	n.mu.Unlock()
	n.signalV1()
	n.mu.Lock()
	n.serial = 2
	n.deadline = time.Now().Add(time.Second)
	n.mu.Unlock()
	n.signalV1()
	select {
	case <-n.leaf.Done():
		t.Fatal("stale stage timer cancelled successor")
	case <-time.After(35 * time.Millisecond):
	}
	n.CloseWakeV1()
	if s := n.FinishV1(); s != 0 {
		t.Fatal(s)
	}
	for _, authority := range []bool{false, true} {
		n := newProductionTransportRootV1(nil, make(chan struct{}), time.Now().Add(time.Second))
		n.mu.Lock()
		n.deadline = time.Now().Add(15 * time.Millisecond)
		if authority {
			n.authorityDeadline = n.deadline
		}
		n.mu.Unlock()
		n.signalV1()
		select {
		case <-n.closerDone:
		case <-time.After(time.Second):
			t.Fatal("deadline did not close")
		}
		n.mu.Lock()
		s := n.terminal
		n.mu.Unlock()
		want := int32(8)
		if authority {
			want = 12
		}
		if s != want {
			t.Fatal("timer category", s)
		}
		if s := n.FinishV1(); s != 0 {
			t.Fatal(s)
		}
	}
}

func TestProductionNetworkV1ConfirmationRequiresExactPublishedFD(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		n := newProductionTransportRootV1(nil, make(chan struct{}), time.Now().Add(time.Minute))
		// No real descriptor or network operation is installed in this state test.
		n.mu.Lock()
		n.fd = 123
		n.phase = productionPreparedV1
		n.connectorActive = true
		n.mu.Unlock()
		fd, s := n.SocketFDV1()
		if fd != 123 || s != 0 {
			t.Fatal(fd, s)
		}
		if wrong {
			fd++
		}
		s = n.ConfirmProtectedV1(fd)
		if wrong && s != 16 || !wrong && s != 0 {
			t.Fatal(s)
		}
		if n.ConfirmProtectedV1(fd) == 0 {
			t.Fatal("repeated confirmation")
		}
		n.mu.Lock()
		n.fd = -1
		n.connectorActive = false
		n.connectorSettled = true
		close(n.connectorDone)
		n.mu.Unlock()
		n.CloseWakeV1()
		<-n.closerDone
	}
}
