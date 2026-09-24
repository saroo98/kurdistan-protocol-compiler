// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"kurdistan/internal/net/boundeddns"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/runtime"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Trusted constructor-only capabilities. Task5/6 must supply actual Android
// network/TUN/runtime-epoch and system-only root provenance. No release input
// or ambient environment may supply either capability.
type MaintenanceTransportEnvironmentV1 interface {
	AcquireNetwork(context.Context) (MaintenanceNetworkLeaseV1, MaintenanceResultV1)
	SystemRootsInto(context.Context, []byte) (int, MaintenanceResultV1)
}
type MaintenanceNetworkLeaseV1 interface {
	Mode() runtime.ProbeModeV1
	IPFamilies() uint8
	DNSServersInto(*[4]netip.AddrPort) (int, MaintenanceResultV1)
	BindSocket(uintptr) MaintenanceResultV1
	IsCurrent() bool
	Done() <-chan struct{}
	Close() ErrorCode
}

// CurrentPump must prove this exact native parent, authenticated scope, fresh
// runtime-start epoch and ready same-pump identity. It transfers no pump
// ownership. The pump retains its workers/charges until its own Done.
type MaintenanceActiveProbeOwnerV1 interface {
	CurrentPump(uint64, runtime.AuthenticatedProbeScopeV1) (*runtime.ServicePumpV1, bool)
}

const maintenanceRootBlobBytesV1 = 1048576

// HTTPS library-internal HTTP/TLS/X509 allocations are explicitly outside the
// deterministic backing ceiling by owner approval. Their empirical emulator
// qualification is separate. These are product buffers/control reservations.
func maintenanceTransportReservationV1(maxBody uint32) (uint64, bool) {
	if maxBody == 0 || maxBody > envelope.MaxTotalInputBytes {
		return 0, false
	}
	return maintenanceAddV1(maintenanceRootBlobBytesV1, uint64(maxBody), 82480, 480, 8192, 1,
		uint64(unsafe.Sizeof(tls.Config{})), uint64(unsafe.Sizeof(http.Request{})), uint64(unsafe.Sizeof("")),
		4*2048, uint64(unsafe.Sizeof(maintenanceSocketV1{})),
		uint64(unsafe.Sizeof([16]netip.Addr{})), uint64(unsafe.Sizeof([4]netip.AddrPort{})),
		uint64(unsafe.Sizeof([10]runtime.ProbeSampleV1{})),
		// network watcher, stop/done, socket callback/done, deadline context/timer,
		// target-copy and selected native operation/config holders.
		8*maintenanceControlBackingPerObject)
}

func (p *maintenanceAuthorityV1) installTransport(op *maintenanceOperationV1, e MaintenanceTransportEnvironmentV1) MaintenanceResultV1 {
	if e == nil {
		return MaintenanceSuccess
	}
	p.mu.Lock()
	op.inPlatform = true
	p.mu.Unlock()
	defer func() { p.mu.Lock(); op.inPlatform = false; p.mu.Unlock() }()
	lease, result := e.AcquireNetwork(op.ctx)
	if result != MaintenanceSuccess || lease == nil {
		if lease != nil {
			p.noteCleanup(lease.Close())
		}
		if result == MaintenanceSuccess {
			return MaintenanceNetworkUnavailable
		}
		return maintenanceTransportProviderResultV1(result)
	}
	mode, families := lease.Mode(), lease.IPFamilies()
	var servers [4]netip.AddrPort
	count, dnsResult := lease.DNSServersInto(&servers)
	if !lease.IsCurrent() || lease.Done() == nil || (mode != runtime.ProbeDisconnectedDefaultV1 && mode != runtime.ProbeActiveRelayV1) || families < 1 || families > 3 || dnsResult != MaintenanceSuccess || !maintenanceValidDNSServersV1(&servers, count) {
		p.noteCleanup(lease.Close())
		return MaintenanceNetworkUnavailable
	}
	p.mu.Lock()
	if !p.operationCanPublishLocked(op) {
		p.mu.Unlock()
		p.noteCleanup(lease.Close())
		return MaintenanceCancelled
	}
	p.network = lease
	p.networkMode = mode
	p.networkFamilies = families
	p.networkServers = servers
	p.networkServerCount = count
	p.transport = e
	p.transportStop = make(chan struct{})
	p.transportDone = make(chan struct{})
	p.mu.Unlock()
	op.completionGuard = func() MaintenanceResultV1 { return p.networkStatus(op) }
	go func() {
		defer close(p.transportDone)
		select {
		case <-lease.Done():
			p.shutdown(MaintenanceNetworkUnavailable, true)
		case <-p.transportStop:
		}
	}()
	return MaintenanceSuccess
}
func maintenanceTransportProviderResultV1(r MaintenanceResultV1) MaintenanceResultV1 {
	switch r {
	case MaintenanceNetworkUnavailable, MaintenanceTLSTrustUnavailable, MaintenanceResourceLimit, MaintenanceCancelled, MaintenanceTimeout:
		return r
	default:
		return MaintenanceInternalFailure
	}
}
func (p *maintenanceAuthorityV1) closeTransport() {
	p.transportClose.Do(func() {
		if p.transportStop != nil {
			close(p.transportStop)
			<-p.transportDone
		}
		if p.network != nil {
			p.noteCleanup(p.network.Close())
		}
		p.roots = nil
		clear(p.rootBlob)
		p.rootBlob = nil
	})
}
func (p *maintenanceAuthorityV1) networkStatus(op *maintenanceOperationV1) MaintenanceResultV1 {
	p.mu.Lock()
	if p.terminalSet {
		r := p.terminal
		p.mu.Unlock()
		return r
	}
	if !p.operationCanPublishLocked(op) {
		p.mu.Unlock()
		if r := maintenanceContextResultV1(op.ctx); r != MaintenanceSuccess {
			return r
		}
		return MaintenanceCancelled
	}
	lease := p.network
	op.inPlatform = true
	p.mu.Unlock()
	current := lease != nil && lease.IsCurrent()
	if current {
		current = lease.Mode() == p.networkMode && lease.IPFamilies() == p.networkFamilies
	}
	if current {
		var servers [4]netip.AddrPort
		count, result := lease.DNSServersInto(&servers)
		current = result == MaintenanceSuccess && count == p.networkServerCount && servers == p.networkServers
	}
	if current {
		select {
		case <-lease.Done():
			current = false
		default:
		}
	}
	p.mu.Lock()
	op.inPlatform = false
	terminal, r := p.terminalSet, p.terminal
	p.mu.Unlock()
	if terminal {
		return r
	}
	if !current {
		return p.failOperation(op, MaintenanceNetworkUnavailable)
	}
	return maintenanceContextResultV1(op.ctx)
}

func maintenanceValidDNSServersV1(servers *[4]netip.AddrPort, count int) bool {
	if count < 1 || count > len(servers) {
		return false
	}
	for i, s := range servers[:count] {
		a := s.Addr()
		if !s.IsValid() || s.Port() != 53 || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() || a.Zone() != "" {
			return false
		}
		for _, prior := range servers[:i] {
			if prior == s {
				return false
			}
		}
	}
	for _, s := range servers[count:] {
		if s.IsValid() {
			return false
		}
	}
	return true
}
func (p *maintenanceAuthorityV1) loadRoots(op *maintenanceOperationV1) MaintenanceResultV1 {
	if p.roots != nil {
		return p.networkStatus(op)
	}
	if p.transport == nil {
		return MaintenanceTLSTrustUnavailable
	}
	raw := make([]byte, maintenanceRootBlobBytesV1)
	p.mu.Lock()
	op.inPlatform = true
	p.mu.Unlock()
	n, r := p.transport.SystemRootsInto(op.ctx, raw)
	p.mu.Lock()
	op.inPlatform = false
	p.mu.Unlock()
	if r != MaintenanceSuccess || n < 1 || n > len(raw) {
		clear(raw)
		if r == MaintenanceResourceLimit {
			return r
		}
		return MaintenanceTLSTrustUnavailable
	}
	pool, r := maintenanceParseRootsV1(raw[:n])
	if r != MaintenanceSuccess {
		clear(raw)
		return r
	}
	if r = p.networkStatus(op); r != MaintenanceSuccess {
		clear(raw)
		return r
	}
	// Parsed certificates alias raw DER. Retain the full reserved backing for
	// this parent's lifetime, and clear only after all operation users join.
	p.rootBlob = raw
	p.roots = pool
	return MaintenanceSuccess
}
func maintenanceParseRootsV1(raw []byte) (*x509.CertPool, MaintenanceResultV1) {
	if len(raw) < 3 || len(raw) > maintenanceRootBlobBytesV1 || raw[0] != 1 {
		return nil, MaintenanceTLSTrustUnavailable
	}
	count := int(binary.BigEndian.Uint16(raw[1:3]))
	if count < 1 || count > 512 {
		return nil, MaintenanceTLSTrustUnavailable
	}
	pos := 3
	for i := 0; i < count; i++ {
		if len(raw)-pos < 4 {
			return nil, MaintenanceTLSTrustUnavailable
		}
		n := int(binary.BigEndian.Uint32(raw[pos : pos+4]))
		pos += 4
		if n < 1 || n > 16384 || n > len(raw)-pos {
			return nil, MaintenanceTLSTrustUnavailable
		}
		pos += n
	}
	if pos != len(raw) {
		return nil, MaintenanceTLSTrustUnavailable
	}
	pool := x509.NewCertPool()
	pos = 3
	for i := 0; i < count; i++ {
		n := int(binary.BigEndian.Uint32(raw[pos : pos+4]))
		pos += 4
		cert, err := x509.ParseCertificate(raw[pos : pos+n])
		if err != nil {
			return nil, MaintenanceTLSTrustUnavailable
		}
		pool.AddCert(cert)
		pos += n
	}
	return pool, MaintenanceSuccess
}

type maintenanceSocketV1 struct {
	mu         sync.Mutex
	ctx        context.Context
	connection net.Conn
	stop       func() bool
	done       chan struct{}
	cleanup    ErrorCode
}

func newMaintenanceSocketV1(ctx context.Context) *maintenanceSocketV1 {
	s := &maintenanceSocketV1{ctx: ctx, done: make(chan struct{})}
	s.stop = context.AfterFunc(ctx, func() { defer close(s.done); s.close() })
	return s
}
func (s *maintenanceSocketV1) install(c net.Conn) bool {
	s.mu.Lock()
	if s.ctx.Err() != nil || s.connection != nil {
		s.mu.Unlock()
		s.closeOwned(c)
		return false
	}
	s.connection = c
	s.mu.Unlock()
	return true
}
func (s *maintenanceSocketV1) close() {
	s.mu.Lock()
	c := s.connection
	s.connection = nil
	s.mu.Unlock()
	if c != nil {
		s.closeOwned(c)
	}
}
func (s *maintenanceSocketV1) closeOwned(c net.Conn) {
	if err := c.Close(); err != nil {
		s.mu.Lock()
		s.cleanup = CodeStateCorrupt
		s.mu.Unlock()
	}
}
func (s *maintenanceSocketV1) finish() ErrorCode {
	s.close()
	if !s.stop() {
		<-s.done
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleanup
}

type maintenanceDNSOwnerV1 struct {
	parent *maintenanceAuthorityV1
	op     *maintenanceOperationV1
	route  maintenanceNumericRouteV1
}

type maintenanceNumericRouteV1 func(string, netip.AddrPort) netip.AddrPort

func (o maintenanceDNSOwnerV1) DialUDP(ctx context.Context, dst netip.AddrPort) (*net.UDPConn, error) {
	d := o.dialer()
	if o.route != nil {
		dst = o.route("udp", dst)
	}
	return d.DialUDP(ctx, "udp", netip.AddrPort{}, dst)
}
func (o maintenanceDNSOwnerV1) DialTCP(ctx context.Context, dst netip.AddrPort) (*net.TCPConn, error) {
	d := o.dialer()
	if o.route != nil {
		dst = o.route("tcp", dst)
	}
	return d.DialTCP(ctx, "tcp", netip.AddrPort{}, dst)
}

var errMaintenanceNetworkV1 = errors.New("maintenance_network_unavailable")

func (o maintenanceDNSOwnerV1) dialer() net.Dialer {
	return net.Dialer{ControlContext: func(ctx context.Context, _, _ string, raw syscall.RawConn) error {
		// Resolution can open several sockets without returning to fetchBody.
		// Revalidate the original admitted operation and trusted clock here too.
		if ctx.Err() != nil || o.parent.checkCompletion(o.op) != MaintenanceSuccess || o.parent.networkStatus(o.op) != MaintenanceSuccess {
			return errMaintenanceNetworkV1
		}
		result := MaintenanceInternalFailure
		err := raw.Control(func(fd uintptr) {
			o.parent.mu.Lock()
			o.op.inPlatform = true
			o.parent.mu.Unlock()
			result = o.parent.network.BindSocket(fd)
			o.parent.mu.Lock()
			o.op.inPlatform = false
			o.parent.mu.Unlock()
		})
		if err != nil || result != MaintenanceSuccess || o.parent.networkStatus(o.op) != MaintenanceSuccess {
			o.parent.failOperation(o.op, MaintenanceNetworkUnavailable)
			return errMaintenanceNetworkV1
		}
		return nil
	}}
}
func maintenanceContextResultV1(ctx context.Context) MaintenanceResultV1 {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return MaintenanceTimeout
	}
	if ctx.Err() != nil {
		return MaintenanceCancelled
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return MaintenanceTimeout
	}
	return MaintenanceSuccess
}
func maintenanceDNSResultV1(err error) MaintenanceResultV1 {
	switch err {
	case nil:
		return MaintenanceSuccess
	case boundeddns.ErrInvalidRequest:
		return MaintenanceInvalidRequest
	case boundeddns.ErrInvalidState:
		return MaintenanceInvalidState
	case boundeddns.ErrResourceLimit:
		return MaintenanceResourceLimit
	case boundeddns.ErrCancelled:
		return MaintenanceCancelled
	case boundeddns.ErrTimeout:
		return MaintenanceTimeout
	case boundeddns.ErrNetwork:
		return MaintenanceNetworkUnavailable
	case boundeddns.ErrResponse:
		return MaintenanceFetchRejected
	case boundeddns.ErrSizeLimit:
		return MaintenanceSizeLimit
	case boundeddns.ErrNoData:
		return MaintenanceDestinationDenied
	default:
		return MaintenanceInternalFailure
	}
}
