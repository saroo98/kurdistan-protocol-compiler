// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Exact bytes observed from AndroidSystemTrustRootsV1Test's real Kotlin encoder.
// The deterministic public fixture is not installed or used by any production trust source.
func TestMaintenanceAndroidKotlinRootsVector(t *testing.T) {
	const encoded = "AQABAAABOTCCATUwgeigAwIBAgICAqwwBQYDK2VwMCIxIDAeBgNVBAMTF1Rhc2s2YjRiIHB1YmxpYyBmaXh0dXJlMB4XDTI2MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFowIjEgMB4GA1UEAxMXVGFzazZiNGIgcHVibGljIGZpeHR1cmUwKjAFBgMrZXADIQA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKaNCMEAwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFBOeOUDmS1SRciCI2aDXQWKPyCbgMAUGAytlcANBAGIcWWbgHLJLIvV1sxw2aHRKBiOlGamSVyz87cEbQQGhq7xBTxG2zNsh8mXI8VETr0zf74pkRI1dQcAllhtyMAo="
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 320 {
		t.Fatalf("vector length %d", len(raw))
	}
	pool, result := maintenanceParseRootsV1(raw)
	if result != MaintenanceSuccess || pool == nil {
		t.Fatalf("actual parser: %v", result)
	}
	// DER Name: SEQUENCE { SET { SEQUENCE { commonName, PrintableString } } }.
	wantSubject := append([]byte{0x30, 0x22, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x17}, []byte("Task6b4b public fixture")...)
	subjects := pool.Subjects()
	if len(subjects) != 1 || !bytes.Equal(subjects[0], wantSubject) {
		t.Fatalf("wrong decoded certificate subject: %x", subjects)
	}
	for _, broken := range [][]byte{append(append([]byte(nil), raw...), 0), append([]byte(nil), raw...)} {
		if len(broken) == len(raw) {
			broken[7] = 0xff
		}
		if pool, result := maintenanceParseRootsV1(broken); result != MaintenanceTLSTrustUnavailable || pool != nil {
			t.Fatalf("malformed certificate/frame accepted: %v", result)
		}
	}
}

type maintenanceTestNetwork struct {
	lost    chan struct{}
	current atomic.Bool
	closed  atomic.Int32
	binds   atomic.Int32
	mode    runtime.ProbeModeV1
}

func newMaintenanceTestNetwork() *maintenanceTestNetwork {
	n := &maintenanceTestNetwork{lost: make(chan struct{}), mode: runtime.ProbeDisconnectedDefaultV1}
	n.current.Store(true)
	return n
}
func (n *maintenanceTestNetwork) Mode() runtime.ProbeModeV1 { return n.mode }
func (n *maintenanceTestNetwork) IPFamilies() uint8         { return 3 }
func (n *maintenanceTestNetwork) DNSServersInto(dst *[4]netip.AddrPort) (int, MaintenanceResultV1) {
	dst[0] = netip.MustParseAddrPort("127.0.0.1:53")
	return 1, MaintenanceSuccess
}
func (n *maintenanceTestNetwork) BindSocket(uintptr) MaintenanceResultV1 {
	n.binds.Add(1)
	return MaintenanceSuccess
}
func (n *maintenanceTestNetwork) IsCurrent() bool       { return n.current.Load() }
func (n *maintenanceTestNetwork) Done() <-chan struct{} { return n.lost }
func (n *maintenanceTestNetwork) Close() ErrorCode      { n.closed.Add(1); return CodeOK }

type maintenanceTestEnvironment struct {
	network      *maintenanceTestNetwork
	roots        []byte
	acquisitions int
}

func (e *maintenanceTestEnvironment) AcquireNetwork(context.Context) (MaintenanceNetworkLeaseV1, MaintenanceResultV1) {
	e.acquisitions++
	return e.network, MaintenanceSuccess
}
func (e *maintenanceTestEnvironment) SystemRootsInto(_ context.Context, dst []byte) (int, MaintenanceResultV1) {
	if len(dst) < len(e.roots) {
		return 0, MaintenanceTLSTrustUnavailable
	}
	return copy(dst, e.roots), MaintenanceSuccess
}
func maintenanceRootFixture(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 7+len(der))
	frame[0] = 1
	binary.BigEndian.PutUint16(frame[1:], 1)
	binary.BigEndian.PutUint32(frame[3:], uint32(len(der)))
	copy(frame[7:], der)
	return frame
}
func TestMaintenanceSystemRootsStrictFrameAndNoAmbientFallback(t *testing.T) {
	good := maintenanceRootFixture(t)
	for _, raw := range [][]byte{nil, {1, 0, 0}, append(append([]byte{}, good...), 0), {1, 0, 1, 0, 0, 0, 1, 0}} {
		if pool, r := maintenanceParseRootsV1(raw); pool != nil || r != MaintenanceTLSTrustUnavailable {
			t.Fatal(r)
		}
	}
	t.Setenv("SSL_CERT_FILE", "untrusted-and-unused")
	t.Setenv("SSL_CERT_DIR", "untrusted-and-unused")
	pool, r := maintenanceParseRootsV1(good)
	if r != MaintenanceSuccess || pool == nil || len(pool.Subjects()) != 1 {
		t.Fatal(r)
	}
}
func TestMaintenanceSocketCancellationJoinsAndLateInstallCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := newMaintenanceSocketV1(ctx)
	a, b := net.Pipe()
	defer b.Close()
	cancel()
	if s.install(a) {
		t.Fatal("late install succeeded")
	}
	s.finish()
	if _, err := a.Write([]byte{1}); err == nil {
		t.Fatal("socket still open")
	}
}
func TestMaintenanceCapturedLeaseLossCancelsAndJoins(t *testing.T) {
	p := newMaintenanceStateFixture(t)
	n := newMaintenanceTestNetwork()
	e := &maintenanceTestEnvironment{network: n}
	op, r := p.beginOperation()
	if r != MaintenanceSuccess {
		t.Fatal(r)
	}
	if r = p.installTransport(op, e); r != MaintenanceSuccess {
		t.Fatal(r)
	}
	p.finishOperation(op)
	next, r := p.beginOperation()
	if r != MaintenanceSuccess {
		t.Fatal(r)
	}
	finished := make(chan struct{})
	go func() { <-next.ctx.Done(); p.finishOperation(next); close(finished) }()
	n.current.Store(false)
	close(n.lost)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("loss failed to cancel")
	}
	p.DestroyResult()
	if e.acquisitions != 1 || n.closed.Load() != 1 || parentStatusForTest(p) != MaintenanceNetworkUnavailable {
		t.Fatal("lease lifecycle")
	}
}

func TestMaintenanceCapturedModeCannotChangeWithoutRecreation(t *testing.T) {
	p := newMaintenanceStateFixture(t)
	n := newMaintenanceTestNetwork()
	e := &maintenanceTestEnvironment{network: n}
	op, _ := p.beginOperation()
	defer p.finishOperation(op)
	if r := p.installTransport(op, e); r != MaintenanceSuccess {
		t.Fatal(r)
	}
	n.mode = runtime.ProbeActiveRelayV1
	if r := p.networkStatus(op); r != MaintenanceNetworkUnavailable {
		t.Fatal("changed mode accepted", r)
	}
}

func TestMaintenanceNumericSocketBindingIsPerCreation(t *testing.T) {
	for range 2 {
		p := newMaintenanceStateFixture(t)
		n := newMaintenanceTestNetwork()
		op, _ := p.beginOperation()
		if r := p.installTransport(op, &maintenanceTestEnvironment{network: n}); r != MaintenanceSuccess {
			t.Fatal(r)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			p.finishOperation(op)
			t.Fatal(err)
		}
		addr, err := netip.ParseAddrPort(listener.Addr().String())
		if err != nil {
			listener.Close()
			p.finishOperation(op)
			t.Fatal(err)
		}
		d := (maintenanceDNSOwnerV1{parent: p, op: op}).dialer()
		ctx, cancel := context.WithTimeout(op.ctx, time.Second)
		c, err := d.DialTCP(ctx, "tcp", netip.AddrPort{}, addr)
		cancel()
		listener.Close()
		if c != nil {
			c.Close()
		}
		p.finishOperation(op)
		if err != nil || n.binds.Load() != 1 {
			t.Fatal("wrong binding behavior", n.binds.Load())
		}
	}
}

func TestMaintenanceSocketCreationRechecksTrustedTimeBetweenAttempts(t *testing.T) {
	for _, change := range []time.Duration{2 * time.Second, -time.Second} {
		t.Run(change.String(), func(t *testing.T) {
			p := newMaintenanceStateFixture(t)
			now := p.lastNow
			p.now = func() time.Time { return now }
			op, _ := p.beginOperation()
			defer p.finishOperation(op)
			n := newMaintenanceTestNetwork()
			if r := p.installTransport(op, &maintenanceTestEnvironment{network: n}); r != MaintenanceSuccess {
				t.Fatal(r)
			}
			deadline := now.Add(time.Second)
			op.completionGuard = func() MaintenanceResultV1 {
				if r := p.networkStatus(op); r != MaintenanceSuccess {
					return r
				}
				at, r := p.trustedNow(op)
				if r != MaintenanceSuccess {
					return r
				}
				if !at.Before(deadline) {
					return MaintenanceTimeout
				}
				return MaintenanceSuccess
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			address := listener.Addr().(*net.TCPAddr).AddrPort()
			d := (maintenanceDNSOwnerV1{parent: p, op: op}).dialer()
			ctx, cancel := context.WithTimeout(op.ctx, 5*time.Second)
			defer cancel()
			first, err := d.DialTCP(ctx, "tcp", netip.AddrPort{}, address)
			if err != nil {
				t.Fatal(err)
			}
			first.Close()
			now = now.Add(change)
			second, err := d.DialTCP(ctx, "tcp", netip.AddrPort{}, address)
			if second != nil {
				second.Close()
			}
			if err == nil || n.binds.Load() != 1 {
				t.Fatalf("stale authority reached socket bind: err=%v binds=%d", err, n.binds.Load())
			}
		})
	}
}

func TestMaintenanceTransportBackingReservationAndLimits(t *testing.T) {
	base, ok := maintenanceTransportReservationV1(1)
	if !ok {
		t.Fatal("one byte cap refused")
	}
	large, ok := maintenanceTransportReservationV1(envelope.MaxTotalInputBytes)
	if !ok || large-base != uint64(envelope.MaxTotalInputBytes-1) {
		t.Fatal("body reservation not exact")
	}
	if _, ok := maintenanceTransportReservationV1(0); ok {
		t.Fatal("zero body accepted")
	}
	if _, ok := maintenanceTransportReservationV1(envelope.MaxTotalInputBytes + 1); ok {
		t.Fatal("unbounded body accepted")
	}
	t.Logf("transport product reservation cap1=%d capMax=%d; root=%d", base, large, maintenanceRootBlobBytesV1)
}

type maintenanceGatedClose struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (c *maintenanceGatedClose) Close() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Conn.Close()
}
func TestMaintenanceSocketFinishJoinsStartedCloseCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	a, b := net.Pipe()
	defer b.Close()
	c := &maintenanceGatedClose{Conn: a, entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(c.release) }) }
	s := newMaintenanceSocketV1(ctx)
	done := make(chan struct{})
	started := false
	t.Cleanup(func() {
		unblock()
		cancel()
		if started {
			<-done
		} else {
			s.finish()
		}
	})
	if !s.install(c) {
		t.Fatal("install")
	}
	cancel()
	select {
	case <-c.entered:
	case <-time.After(time.Second):
		t.Fatal("close callback absent")
	}
	started = true
	go func() { s.finish(); close(done) }()
	select {
	case <-done:
		t.Fatal("finish failed to join close actor")
	default:
	}
	unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("finish not completed")
	}
}

type maintenanceNeverVerify struct{}

func (maintenanceNeverVerify) VerifyWithRecipientAt([]byte, envelope.ArtifactClass, RecipientCredentials, time.Time, selfhost.LiveMaintenanceLimits) (profile.OfflineVerifiedArtifact, selfhost.LiveMaintenanceBounds, error) {
	panic("verification entered before capacity admission")
}

type maintenanceNeverPlatform struct{}

func (maintenanceNeverPlatform) Register(uint64, func() ErrorCode) (MaintenanceRevisionRegistrationV1, ErrorCode) {
	panic("platform entered before capacity admission")
}
func TestMaintenanceTransportOneUnderConstructorBudgetBeforeInputWork(t *testing.T) {
	current := MaintenanceCurrentInputV1{VerifyRequest: []byte{1}, ActivationRecord: []byte{1}, RecipientRequest: []byte{1}, RecipientPrivate: []byte{1}}
	bridge, r := maintenanceBridgeReservation(current)
	if r != MaintenanceSuccess {
		t.Fatal(r)
	}
	transport, ok := maintenanceTransportReservationV1(envelope.MaxTotalInputBytes)
	if !ok {
		t.Fatal("reservation")
	}
	for _, budget := range []uint64{bridge + transport - 1, bridge + transport} {
		var registry HandleRegistry
		config := MaintenanceConfigV1{Now: time.Now, OwnedBudgetBytes: budget, Limits: selfhost.LiveMaintenanceLimits{MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20}, Transport: &maintenanceTestEnvironment{network: newMaintenanceTestNetwork()}}
		h, r := OpenMaintenanceV1(&registry, current, maintenanceNeverVerify{}, maintenanceNeverPlatform{}, config)
		if h != 0 || r != MaintenanceResourceLimit {
			t.Fatal("constructor exceeded reserved budget", r)
		}
	}
}
