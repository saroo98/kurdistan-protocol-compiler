// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/transport/tlstcp"
)

const (
	productionPreparedV1 uint8 = iota + 1
	productionPublishedV1
	productionConfirmedV1
	productionConnectedV1
	productionTLSV1
	productionKurdV1
	productionAttachedV1
)

type productionStageContextV1 struct {
	leaf     context.Context
	deadline time.Time
}

func (c productionStageContextV1) Deadline() (time.Time, bool) {
	return c.deadline, !c.deadline.IsZero()
}
func (c productionStageContextV1) Done() <-chan struct{} { return c.leaf.Done() }
func (c productionStageContextV1) Err() error            { return c.leaf.Err() }
func (c productionStageContextV1) Value(any) any         { return nil }

type productionAttemptTransportV1 struct {
	mu                                               sync.Mutex
	self                                             *productionAttemptTransportV1
	borrow                                           *androidbridge.ProductionAttemptBorrowV1
	phase                                            uint8
	terminal                                         int32
	finishStatus                                     int32
	busy, finishing                                  bool
	runStarted, runActive                            bool
	serial                                           uint64
	deadline, authorityDeadline                      time.Time
	dialTimeout                                      time.Duration
	leaf                                             context.Context
	cancel                                           context.CancelFunc
	parentDone                                       <-chan struct{}
	wake, connectorDone, rawClosed, closerDone, done chan struct{}
	timer                                            *time.Timer
	connectorActive, connectorSettled                bool
	fd                                               int
	raw                                              net.Conn
	facade                                           productionJoinedConnV1
	closeError                                       error
	carrier                                          *tlstcp.Conn
	result                                           *auth.ProcessHandshakeResultV1
	service                                          *kruntime.ServicePumpV1
	packet                                           *kruntime.RawPacketPumpV2
	connector                                        productionConnectorOpsV1
}

// Fixed private syscall handoff operations. Release construction always installs
// the concrete platform functions; no bridge/request can supply replacements.
type productionConnectorOpsV1 struct {
	connect   func(context.Context, int, runtimepolicy.EndpointV2) error
	newFile   func(uintptr, string) *os.File
	fileConn  func(*os.File) (net.Conn, error)
	fileClose func(*os.File) error
}

type productionNetworkFactoryV1 struct{}

func (productionNetworkFactoryV1) ReservationV1(b *androidbridge.ProductionAttemptBorrowV1) (androidbridge.ProductionAttemptReservationV1, int32) {
	if !productionPlatformSupportedV1 {
		return androidbridge.ProductionAttemptReservationV1{}, 25
	}
	var bytes uint64
	err := b.WithInputsV1(func(plan sessionplan.PlanV2, policy runtimepolicy.PolicyV2, p liveprogram.ProgramV1, _ []byte, _ uint8, _ time.Time) error {
		var err error
		bytes, err = productionNetworkWorkspaceV1(plan, policy, p)
		return err
	})
	if err != nil {
		return androidbridge.ProductionAttemptReservationV1{}, b.StatusV1(5)
	}
	return androidbridge.ProductionAttemptReservationV1{OwnedBytes: bytes}, 0
}
func (productionNetworkFactoryV1) PrepareV1(b *androidbridge.ProductionAttemptBorrowV1) (androidbridge.ProductionAttemptTransportV1, int32) {
	if !productionPlatformSupportedV1 {
		return nil, 25
	}
	parent, deadline, s := b.LifetimeV1()
	if s != 0 {
		return nil, s
	}
	n := newProductionTransportRootV1(b, parent, deadline)
	err := b.WithInputsV1(func(plan sessionplan.PlanV2, _ runtimepolicy.PolicyV2, _ liveprogram.ProgramV1, _ []byte, index uint8, _ time.Time) error {
		n.mu.Lock()
		n.dialTimeout = plan.DialTimeout
		d := time.Now().Add(plan.DialTimeout)
		if deadline.Before(d) {
			d = deadline
		}
		n.deadline = d
		n.mu.Unlock()
		n.signalV1()
		return productionPrepareSocketV1(n, plan.Endpoints[index])
	})
	if err != nil {
		return n, n.statusV1(err, 9)
	}
	return n, 0
}

// Named native argument holders. Their slice/string fields borrow parent data;
// the corresponding backings remain charged to the parent, not cloned here.
type productionNetworkCallHoldersV1 struct {
	plan     sessionplan.PlanV2
	policy   runtimepolicy.PolicyV2
	program  liveprogram.ProgramV1
	seed     []byte
	endpoint uint8
	now      time.Time
	err      error
}
type productionNetworkWorkerHoldersV1 struct {
	owner            *productionAttemptTransportV1
	raw              net.Conn
	fd               int
	deadline         time.Time
	remaining        time.Duration
	terminal, status int32
	err              error
	timer            <-chan time.Time
	serial           uint64
	expiry           productionExpiryHoldersV1
}
type productionExpiryHoldersV1 struct {
	owner         *productionAttemptTransportV1
	serial        uint64
	deadline, now time.Time
	status        int32
}
type productionNetworkTimeCaptureV1 struct {
	code uintptr
	now  time.Time
}
type productionNetworkCallCaptureV1 struct {
	code  uintptr
	owner *productionAttemptTransportV1
	stage productionStageContextV1
}

func productionNetworkWorkspaceV1(plan sessionplan.PlanV2, policy runtimepolicy.PolicyV2, p liveprogram.ProgramV1) (uint64, error) {
	if runtime.Version() != "go1.26.6" || unsafe.Sizeof(uintptr(0)) != 8 || unsafe.Sizeof(x509.CertPool{}) != 48 || len(policy.TLSLeafDER) == 0 || len(policy.TLSLeafDER) > 4096 {
		return 0, errors.New("unproven transport layout")
	}
	workspace, err := kruntime.ProcessClientHandshakeWorkspaceV1(p, policy.ClientAuthKeyID, policy.RelayAuthKeyID)
	if err != nil {
		return 0, err
	}
	authBounds, err := auth.ProjectedClientWorkspaceV1(p, policy.ClientAuthKeyID, policy.RelayAuthKeyID)
	if err != nil {
		return 0, err
	}
	preface, err := sessionplan.RelayAdmissionPrefaceWorkspaceV1(plan)
	if err != nil {
		return 0, err
	}
	overflow := false
	add := func(values ...uint64) uint64 {
		var n uint64
		for _, v := range values {
			if v > math.MaxUint64-n {
				overflow = true
				return 0
			}
			n += v
		}
		return n
	}
	clone := func(n uint64) uint64 {
		if n == 0 {
			return 0
		}
		return add(n, n, 8)
	}
	// Go1.26.6 ordinary64 source: cancelCtx80, cancel closure16; seven
	// hchan112 headers (five owner, leaf, timer), timer112 including time's
	// prefix, one timer time.Time24 slot, worker entry16. No child map/AfterFunc.
	metadata := uint64(80 + 16 + 7*112 + 112 + 24 + 16)
	fixed := add(uint64(unsafe.Sizeof(productionAttemptTransportV1{})), metadata,
		2*uint64(unsafe.Sizeof(productionStageContextV1{})), uint64(unsafe.Sizeof(productionNetworkWorkerHoldersV1{})),
		uint64(unsafe.Sizeof(productionNetworkCallHoldersV1{})), uint64(unsafe.Sizeof(productionNetworkCallCaptureV1{})))
	// Exact one-root pool registration expression from the accepted source
	// worksheet. Subject string and []byte may each be as large as DER D.
	d := uint64(len(policy.TLSLeafDER))
	pool := add(uint64(unsafe.Sizeof(x509.CertPool{})), 48+8+8*40, 48+8+8*32, clone(40), clone(8), d, clone(d), 16)
	tlsNative := add(1572864, pool, 2*uint64(unsafe.Sizeof(tls.Config{})), 2*16, uint64(unsafe.Sizeof(productionNetworkTimeCaptureV1{})), 32)
	conn := uint64(unsafe.Sizeof(tlstcp.Conn{}))
	// Parent Plan/Policy/Program/seed are the exact covered subset and omitted.
	// Preface's second decoder is sequential with ValidateV2At, not cumulative.
	decode := max(uint64(2423424), uint64(1399424+1572864)) + 131072
	prefaceStage := max(decode, add(141840, preface))
	tlsStage := max(max(uint64(1125240), uint64(101240+1572864))+131072, tlsNative)
	// Additional cmd by-value arguments coexist with runtime/auth construction.
	handshakeStage := add(tlsNative, conn, workspace, uint64(unsafe.Sizeof(productionNetworkCallHoldersV1{})))
	// The accepted installation already owns its 3MiB constructor and selected
	// RecordStream (including shared Conn), but not this fresh result/TLS graph.
	attachStage := add(tlsNative, authBounds.Stages[5])
	n := add(fixed, max(productionConnectorBytesV1(), prefaceStage, tlsStage, handshakeStage, attachStage))
	if overflow {
		return 0, errors.New("transport workspace overflow")
	}
	return n, nil
}

func newProductionTransportRootV1(b *androidbridge.ProductionAttemptBorrowV1, parent <-chan struct{}, deadline time.Time) *productionAttemptTransportV1 {
	leaf, cancel := context.WithCancel(context.Background())
	n := &productionAttemptTransportV1{borrow: b, phase: productionPreparedV1, fd: -1, leaf: leaf, cancel: cancel, parentDone: parent, authorityDeadline: deadline, deadline: deadline,
		wake: make(chan struct{}, 1), connectorDone: make(chan struct{}), rawClosed: make(chan struct{}), closerDone: make(chan struct{}), done: make(chan struct{})}
	n.self = n
	n.facade.owner = n
	n.timer = time.NewTimer(time.Hour)
	if !n.timer.Stop() {
		<-n.timer.C
	}
	go n.closeWorkerV1()
	return n
}
func (n *productionAttemptTransportV1) signalV1() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}
func (n *productionAttemptTransportV1) failV1(status int32) {
	n.mu.Lock()
	if n.terminal == 0 {
		n.terminal = status
	}
	n.cancel()
	n.mu.Unlock()
	n.signalV1()
}
func (n *productionAttemptTransportV1) CloseWakeV1() {
	if n != nil && n.self == n {
		n.failV1(7)
	}
}
func (n *productionAttemptTransportV1) DoneV1() <-chan struct{} {
	if n == nil || n.self != n {
		return nil
	}
	return n.done
}

func (n *productionAttemptTransportV1) expireObservedV1(serial uint64, deadline, now time.Time) {
	n.mu.Lock()
	// Observe and commit under one lock. An old immediate-expiry decision or
	// timer delivery cannot terminate a replacement or successfully disarmed stage.
	if n.terminal != 0 || n.serial != serial || n.deadline != deadline || deadline.IsZero() || now.Before(deadline) {
		n.mu.Unlock()
		return
	}
	n.terminal = 8
	if !now.Before(n.authorityDeadline) {
		n.terminal = 12
	}
	n.cancel()
	n.mu.Unlock()
	n.signalV1()
}

// One worker owns timer reconfiguration and every physical raw Close. It never
// calls its facade, carrier, installation or pump, and never holds mu over I/O.
func (n *productionAttemptTransportV1) closeWorkerV1() {
	for {
		n.mu.Lock()
		terminal, serial, deadline := n.terminal, n.serial, n.deadline
		if terminal != 0 && !n.connectorActive && !n.connectorSettled {
			n.connectorSettled = true
			close(n.connectorDone)
		}
		n.mu.Unlock()
		if terminal != 0 {
			break
		}
		if !n.timer.Stop() {
			select {
			case <-n.timer.C:
			default:
			}
		}
		var timer <-chan time.Time
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				n.expireObservedV1(serial, deadline, time.Now())
				continue
			}
			n.timer.Reset(remaining)
			timer = n.timer.C
		}
		select {
		case <-n.parentDone:
			n.failV1(7)
		case <-n.wake:
		case <-timer:
			n.expireObservedV1(serial, deadline, time.Now())
		}
	}
	if !n.timer.Stop() {
		select {
		case <-n.timer.C:
		default:
		}
	}
	<-n.connectorDone
	n.mu.Lock()
	fd, raw := n.fd, n.raw
	n.fd = -1
	n.mu.Unlock()
	var err error
	if fd >= 0 {
		err = productionCloseFDV1(fd)
	}
	if raw != nil {
		_ = raw.SetDeadline(time.Now().Add(-time.Second))
		if e := raw.Close(); err == nil {
			err = e
		}
	}
	raw = nil
	n.mu.Lock()
	n.raw = nil
	if n.closeError == nil {
		n.closeError = err
	}
	n.mu.Unlock()
	close(n.rawClosed)
	close(n.closerDone)
}

type productionJoinedConnV1 struct{ owner *productionAttemptTransportV1 }

func (c *productionJoinedConnV1) rawV1() net.Conn {
	n := c.owner
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.raw
}
func (c *productionJoinedConnV1) Read(p []byte) (int, error) {
	r := c.rawV1()
	if r == nil {
		return 0, net.ErrClosed
	}
	return r.Read(p)
}
func (c *productionJoinedConnV1) Write(p []byte) (int, error) {
	r := c.rawV1()
	if r == nil {
		return 0, net.ErrClosed
	}
	return r.Write(p)
}
func (c *productionJoinedConnV1) LocalAddr() net.Addr {
	r := c.rawV1()
	if r == nil {
		return nil
	}
	return r.LocalAddr()
}
func (c *productionJoinedConnV1) RemoteAddr() net.Addr {
	r := c.rawV1()
	if r == nil {
		return nil
	}
	return r.RemoteAddr()
}
func (c *productionJoinedConnV1) SetDeadline(t time.Time) error {
	r := c.rawV1()
	if r == nil {
		return net.ErrClosed
	}
	return r.SetDeadline(t)
}
func (c *productionJoinedConnV1) SetReadDeadline(t time.Time) error {
	r := c.rawV1()
	if r == nil {
		return net.ErrClosed
	}
	return r.SetReadDeadline(t)
}
func (c *productionJoinedConnV1) SetWriteDeadline(t time.Time) error {
	r := c.rawV1()
	if r == nil {
		return net.ErrClosed
	}
	return r.SetWriteDeadline(t)
}
func (c *productionJoinedConnV1) Close() error {
	n := c.owner
	n.failV1(9)
	<-n.rawClosed
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closeError
}

func (n *productionAttemptTransportV1) SocketFDV1() (int, int32) {
	if n == nil || n.self != n {
		return -1, 3
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.deadline.IsZero() && !time.Now().Before(n.deadline) && n.terminal == 0 {
		n.terminal = 8
		if !time.Now().Before(n.authorityDeadline) {
			n.terminal = 12
		}
		n.cancel()
		n.signalV1()
	}
	if n.terminal != 0 {
		return -1, n.terminal
	}
	if n.phase != productionPreparedV1 || n.fd < 0 {
		return -1, 3
	}
	n.phase = productionPublishedV1
	return n.fd, 0
}

// Confirmation consumes this opaque attempt's exact published protection
// handle. Later5b4 must validate the platform token before invoking it. Local
// fixture confirmation proves ordering, never Android OS socket protection.
func (n *productionAttemptTransportV1) ConfirmProtectedV1(fd int) int32 {
	if n == nil || n.self != n {
		return 3
	}
	n.mu.Lock()
	if !n.deadline.IsZero() && !time.Now().Before(n.deadline) && n.terminal == 0 {
		n.terminal = 8
		if !time.Now().Before(n.authorityDeadline) {
			n.terminal = 12
		}
		n.cancel()
		n.signalV1()
	}
	if n.terminal != 0 {
		s := n.terminal
		n.mu.Unlock()
		return s
	}
	if n.phase != productionPublishedV1 || fd < 0 || fd != n.fd {
		n.mu.Unlock()
		n.failV1(16)
		return 16
	}
	n.phase = productionConfirmedV1
	n.mu.Unlock()
	return 0
}

func (n *productionAttemptTransportV1) enterV1(ctx context.Context, phase uint8) (productionStageContextV1, int32) {
	if n == nil || n.self != n || n.borrow == nil {
		return productionStageContextV1{}, 3
	}
	if ctx == nil {
		return productionStageContextV1{}, 2
	}
	if e := ctx.Err(); e != nil {
		return productionStageContextV1{}, n.statusV1(e, 7)
	}
	n.mu.Lock()
	if n.terminal != 0 {
		s := n.terminal
		n.mu.Unlock()
		return productionStageContextV1{}, n.borrow.StatusV1(s)
	}
	if n.busy || n.finishing || n.phase != phase || n.serial == math.MaxUint64 {
		n.mu.Unlock()
		n.failV1(3)
		return productionStageContextV1{}, 3
	}
	n.busy = true
	n.serial++
	deadline := time.Now().Add(n.dialTimeout)
	if n.authorityDeadline.Before(deadline) {
		deadline = n.authorityDeadline
	}
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	n.deadline = deadline
	stage := productionStageContextV1{n.leaf, deadline}
	n.mu.Unlock()
	n.signalV1()
	if !time.Now().Before(deadline) {
		n.leaveV1(0, 8)
		return productionStageContextV1{}, 8
	}
	if _, s := n.borrow.RevalidateV1(stage); s != 0 {
		n.leaveV1(0, s)
		return productionStageContextV1{}, s
	}
	return stage, 0
}
func (n *productionAttemptTransportV1) leaveV1(phase uint8, status int32) int32 {
	status = n.borrow.StatusV1(status)
	n.mu.Lock()
	// Authority wins over local I/O outcomes. Explicit cancellation/deadline
	// wins over the resulting TLS/auth error; an internal facade Close's generic
	// network cause is refined by the genuine failing stage when it returns.
	if status != 12 && status != 13 && n.terminal != 0 && n.terminal != 9 {
		status = n.terminal
	}
	if status == 0 && n.terminal != 0 {
		status = n.terminal
	}
	if status == 0 {
		n.phase = phase
		if phase == productionAttachedV1 {
			n.deadline = time.Time{}
		}
	} else if n.terminal == 0 || n.terminal == 9 {
		n.terminal = status
		n.cancel()
	}
	n.busy = false
	n.mu.Unlock()
	n.signalV1()
	return status
}
func (n *productionAttemptTransportV1) statusV1(err error, fallback int32) int32 {
	if errors.Is(err, context.DeadlineExceeded) {
		fallback = 8
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, kruntime.ServiceCancelledV1) {
		fallback = 7
	}
	if errors.Is(err, kruntime.ServiceAuthorityExpiredV1) {
		fallback = 12
	}
	if errors.Is(err, kruntime.ServiceAuthorityRevokedV1) {
		// A runtime/peer category is not native verified revocation proof.
		// StatusV1 below preserves an actual native terminal13 winner.
		fallback = 7
	}
	if errors.Is(err, kruntime.ServiceResourceLimitV1) {
		fallback = 5
	}
	if err == nil {
		fallback = 0
	}
	if n.borrow != nil {
		return n.borrow.StatusV1(fallback)
	}
	return fallback
}

func (n *productionAttemptTransportV1) ConnectProtectedV1(ctx context.Context) int32 {
	stage, s := n.enterV1(ctx, productionConfirmedV1)
	if s != 0 {
		return s
	}
	err := n.borrow.WithInputsV1(func(plan sessionplan.PlanV2, _ runtimepolicy.PolicyV2, _ liveprogram.ProgramV1, _ []byte, index uint8, now time.Time) error {
		if err := n.connectV1(stage, plan.Endpoints[index]); err != nil {
			return err
		}
		preface, err := sessionplan.NewRelayAdmissionPrefaceV1At(plan, now)
		if err != nil {
			return err
		}
		if stage.Err() != nil {
			return stage.Err()
		}
		if err := n.facade.SetDeadline(stage.deadline); err != nil {
			return err
		}
		if err := sessionplan.WriteRelayAdmissionPrefaceV1(&n.facade, preface); err != nil {
			return err
		}
		return n.facade.SetDeadline(time.Time{})
	})
	return n.leaveV1(productionConnectedV1, n.statusV1(err, 9))
}
func (n *productionAttemptTransportV1) AuthenticateTLSV1(ctx context.Context) int32 {
	stage, s := n.enterV1(ctx, productionConnectedV1)
	if s != 0 {
		return s
	}
	err := n.borrow.WithInputsV1(func(plan sessionplan.PlanV2, policy runtimepolicy.PolicyV2, program liveprogram.ProgramV1, _ []byte, _ uint8, now time.Time) error {
		config, err := productionTLSClientConfigV1(policy, now)
		if err != nil {
			return err
		}
		carrier, err := tlstcp.Client(stage, &n.facade, config, plan.Digest, uint32(program.Limits.MaxFrameBytes))
		// Retain a late successful carrier even when the enclosing borrow's final
		// authority fence rejects; Finish owns its cleanup through the facade.
		n.carrier = carrier
		return err
	})
	return n.leaveV1(productionTLSV1, n.statusV1(err, 14))
}
func (n *productionAttemptTransportV1) AuthenticateKurdV1(ctx context.Context) int32 {
	stage, s := n.enterV1(ctx, productionTLSV1)
	if s != 0 {
		return s
	}
	err := n.borrow.WithInputsV1(func(plan sessionplan.PlanV2, policy runtimepolicy.PolicyV2, program liveprogram.ProgramV1, seed []byte, _ uint8, _ time.Time) error {
		handshake, err := productionClientHandshakeV1(plan, policy, program, seed)
		if err != nil {
			return err
		}
		result, err := kruntime.CompleteProcessClientHandshakeV1(stage, n.carrier, handshake)
		n.result = result
		return err
	})
	return n.leaveV1(productionKurdV1, n.statusV1(err, 15))
}
func (n *productionAttemptTransportV1) AttachInstalledV1(ctx context.Context) int32 {
	stage, s := n.enterV1(ctx, productionKurdV1)
	if s != 0 {
		return s
	}
	var schema uint64
	err := n.borrow.WithInputsV1(func(_ sessionplan.PlanV2, p runtimepolicy.PolicyV2, _ liveprogram.ProgramV1, _ []byte, _ uint8, _ time.Time) error {
		schema = p.SchemaVersion
		return nil
	})
	if err == nil {
		_, s = n.borrow.RevalidateV1(stage)
		if s != 0 {
			return n.leaveV1(0, s)
		}
		// The installed TLS stream retains this context after attachment. Keep
		// authority expiry and cancellation, not the completed startup deadline.
		// The stage timer and the surrounding revalidations still bound startup.
		lifetime := productionStageContextV1{leaf: n.leaf, deadline: n.authorityDeadline}
		switch schema {
		case runtimepolicy.SchemaVersionV2:
			n.packet, err = n.borrow.AttachRawV2(lifetime, n.result, n.carrier)
		case runtimepolicy.SchemaVersionV3:
			n.service, err = n.borrow.AttachServiceV1(lifetime, n.result, n.carrier)
		default:
			err = kruntime.ServiceNotAdmittedV1
		}
	}
	if n.result != nil {
		n.result.Close()
		n.result = nil
	}
	if err == nil {
		var exporter [32]byte
		exporter, err = n.carrier.CarrierBinding()
		if err == nil {
			if n.service != nil {
				err = n.service.BindV1(stage, exporter)
			} else {
				err = n.packet.BindV1(stage, exporter)
			}
		}
		clear(exporter[:])
	}
	if err == nil {
		_, s = n.borrow.RevalidateV1(stage)
		if s != 0 {
			return n.leaveV1(0, s)
		}
	}
	s = n.leaveV1(productionAttachedV1, n.statusV1(err, 15))
	return s
}

// Coordinator-only retirement, never invoked by the close worker. Any active
// serial method must return first; failure leaves all ownership and Done live.
func (n *productionAttemptTransportV1) FinishV1() int32 {
	if n == nil || n.self != n {
		return 3
	}
	n.mu.Lock()
	if n.busy || n.runActive {
		n.mu.Unlock()
		return 3
	}
	if n.finishing {
		n.mu.Unlock()
		<-n.done
		n.mu.Lock()
		s := n.finishStatus
		n.mu.Unlock()
		return s
	}
	n.finishing = true
	n.mu.Unlock()
	n.CloseWakeV1()
	if n.service != nil {
		n.service.Close()
		<-n.service.Done()
		n.service = nil
	}
	if n.packet != nil {
		n.packet.Close()
		<-n.packet.Done()
		n.packet = nil
	}
	if n.carrier != nil {
		n.carrier.Close()
		n.carrier = nil
	}
	if n.result != nil {
		n.result.Close()
		n.result = nil
	}
	<-n.connectorDone
	<-n.closerDone
	status := int32(0)
	if n.borrow != nil {
		status = n.borrow.FinishOwnedV1()
	}
	if status != 0 {
		return status
	}
	n.mu.Lock()
	if n.closeError != nil {
		status = 9
	}
	n.finishStatus = status
	n.mu.Unlock()
	close(n.done)
	return status
}

func (n *productionAttemptTransportV1) ServicePumpV1() (*kruntime.ServicePumpV1, int32) {
	if n == nil || n.self != n {
		return nil, 3
	}
	if s := n.borrow.StatusV1(0); s != 0 {
		return nil, s
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.phase != productionAttachedV1 || n.finishing || n.terminal != 0 {
		return nil, 3
	}
	if n.service == nil {
		return nil, 1
	}
	return n.service, 0
}

func (n *productionAttemptTransportV1) RunV1(ctx context.Context, ready func(*kruntime.ServiceRunPublicationV1) int32) int32 {
	if n == nil || n.self != n || ctx == nil || ready == nil {
		return 2
	}
	n.mu.Lock()
	if n.phase != productionAttachedV1 || n.finishing || n.busy || n.runStarted || n.terminal != 0 {
		n.mu.Unlock()
		return 3
	}
	n.runStarted, n.runActive = true, true
	service, packet := n.service, n.packet
	n.mu.Unlock()
	defer func() { n.mu.Lock(); n.runActive = false; n.mu.Unlock() }()
	status := int32(0)
	callback := func(publication *kruntime.ServiceRunPublicationV1) error {
		status = n.borrow.StatusV1(0)
		n.mu.Lock()
		if status == 0 && n.terminal != 0 {
			status = n.terminal
		}
		n.mu.Unlock()
		if status == 0 {
			status = ready(publication)
		}
		if status != 0 {
			return kruntime.ServiceCancelledV1
		}
		return nil
	}
	var err error
	if service != nil {
		err = service.RunWithPublicationV1(ctx, callback)
	} else if packet != nil {
		err = packet.RunWithPublicationV1(ctx, callback)
	} else {
		return 3
	}
	if status != 0 {
		return n.borrow.StatusV1(status)
	}
	return n.statusV1(err, 9)
}
