// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
	"unsafe"

	"kurdistan/internal/net/boundeddns"
	"kurdistan/internal/product/runtimepolicy"
	kruntime "kurdistan/internal/runtime"
)

// Constructor-only seam below numeric source binding. No request or production
// configuration can supply a dial override or nominate another DNS endpoint.
type relayNumericDialV3 func(context.Context, string, string, net.Addr) (net.Conn, error)
type relaySocketOwnerV3 struct{ dial relayNumericDialV3 }

func (s *relaySocketOwnerV3) numeric(ctx context.Context, target netip.AddrPort, tcp bool) (net.Conn, error) {
	if ctx == nil || !target.IsValid() || target.Port() == 0 || target.Addr().Is4In6() || target.Addr().Zone() != "" {
		return nil, kruntime.ServiceInvalidRequestV1
	}
	if err := networkContextErrorV3(ctx); err != nil {
		return nil, err
	}
	family := 0
	network := "udp4"
	if target.Addr().Is6() {
		family = 1
		network = "udp6"
	}
	source := netip.AddrPortFrom(ownedDNSEndpointsV3[family].Addr(), 0)
	var local net.Addr = net.UDPAddrFromAddrPort(source)
	if tcp {
		local = net.TCPAddrFromAddrPort(source)
		network = "tcp4"
		if family == 1 {
			network = "tcp6"
		}
	}
	var conn net.Conn
	var err error
	if s.dial != nil {
		conn, err = s.dial(ctx, network, target.String(), local)
	} else {
		dialer := net.Dialer{LocalAddr: local}
		conn, err = dialer.DialContext(ctx, network, target.String())
	}
	if cancelled := networkContextErrorV3(ctx); cancelled != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, cancelled
	}
	if err != nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, kruntime.ServiceUnreachableV1
	}
	return conn, nil
}

func ownedDNSServerV3(server netip.AddrPort) bool {
	return server == ownedDNSEndpointsV3[0] || server == ownedDNSEndpointsV3[1]
}
func (s *relaySocketOwnerV3) DialUDP(ctx context.Context, server netip.AddrPort) (*net.UDPConn, error) {
	if !ownedDNSServerV3(server) {
		return nil, kruntime.ServiceDestinationDeniedV1
	}
	conn, err := s.numeric(ctx, server, false)
	if err != nil {
		return nil, err
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, kruntime.ServiceInternalFailureV1
	}
	return udp, nil
}
func (s *relaySocketOwnerV3) DialTCP(ctx context.Context, server netip.AddrPort) (*net.TCPConn, error) {
	if !ownedDNSServerV3(server) {
		return nil, kruntime.ServiceDestinationDeniedV1
	}
	conn, err := s.numeric(ctx, server, true)
	if err != nil {
		return nil, err
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, kruntime.ServiceInternalFailureV1
	}
	return tcp, nil
}

type relayServiceNetworkV3 struct {
	device   *SessionDeviceV3
	families boundeddns.FamilyMask
	resolver *boundeddns.Resolver
	owner    *relaySocketOwnerV3
	now      func() time.Time
}

func networkContextErrorV3(ctx context.Context) error {
	if ctx == nil {
		return kruntime.ServiceInvalidRequestV1
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return kruntime.ServiceInvalidRequestV1
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || !deadline.After(time.Now()) {
		return kruntime.ServiceTimeoutV1
	}
	if ctx.Err() != nil {
		return kruntime.ServiceCancelledV1
	}
	return nil
}

func (n *relayServiceNetworkV3) begin(ctx context.Context) (context.Context, func(), error) {
	if n == nil || n.device == nil || n.now == nil || n.owner == nil {
		return nil, nil, kruntime.ServiceNotAdmittedV1
	}
	if err := networkContextErrorV3(ctx); err != nil {
		return nil, nil, err
	}
	d := n.device
	r := d.registry
	r.mu.Lock()
	if err := d.authorityLockedV3(n.now()); err != nil {
		r.mu.Unlock()
		return nil, nil, err
	}
	d.refs++ // Borrowed call and its joined bridge remain live through cleanup.
	parent := d.ctx
	deadline := d.deadline
	r.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, deadline)
	done := make(chan struct{})
	stop := context.AfterFunc(parent, func() { defer close(done); cancel() })
	finish := func() {
		if !stop() {
			<-done
		}
		cancel()
	}
	if err := networkContextErrorV3(call); err != nil {
		finish()
		d.releaseV3()
		return nil, nil, err
	}
	return call, finish, nil
}

func (n *relayServiceNetworkV3) ResolveProxy(ctx context.Context, domain []byte, out *[16]netip.Addr) (int, error) {
	if out != nil {
		clear(out[:])
	}
	if n == nil || n.resolver == nil || out == nil || len(domain) < 1 || len(domain) > 253 {
		return 0, kruntime.ServiceInvalidRequestV1
	}
	call, finish, err := n.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer n.device.releaseV3()
	count, resolveErr := n.resolver.ResolveInto(call, string(domain), n.families, out)
	callErr := networkContextErrorV3(call)
	finish()
	if err = n.device.checkAuthorityV3(n.now()); err == nil {
		err = callErr
	}
	if err == nil {
		err = networkContextErrorV3(ctx)
	}
	if err == nil {
		err = dnsServiceErrorV3(resolveErr)
	}
	if err != nil {
		clear(out[:])
		return 0, err
	}
	return count, nil
}

func (n *relayServiceNetworkV3) DialTCP(ctx context.Context, target netip.AddrPort) (kruntime.ServiceTCPConnV1, error) {
	if n == nil || !target.IsValid() || target.Port() == 0 || !runtimepolicy.IsPublicServiceAddress(target.Addr()) || target.Addr().Is4() && n.families&boundeddns.IPv4 == 0 || target.Addr().Is6() && n.families&boundeddns.IPv6 == 0 {
		return nil, kruntime.ServiceDestinationDeniedV1
	}
	call, finish, err := n.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer n.device.releaseV3()
	conn, dialErr := n.owner.numeric(call, target, true)
	callErr := networkContextErrorV3(call)
	finish()
	if err = n.device.checkAuthorityV3(n.now()); err == nil {
		err = callErr
	}
	if err == nil {
		err = networkContextErrorV3(ctx)
	}
	if err == nil {
		err = dialErr
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, kruntime.ServiceInternalFailureV1
	}
	return tcp, nil // Real CloseWrite, now exclusively owned by the pump.
}

func dnsServiceErrorV3(err error) error {
	switch err {
	case nil:
		return nil
	case boundeddns.ErrCancelled:
		return kruntime.ServiceCancelledV1
	case boundeddns.ErrTimeout:
		return kruntime.ServiceTimeoutV1
	case boundeddns.ErrResourceLimit, boundeddns.ErrSizeLimit:
		return kruntime.ServiceResourceLimitV1
	case boundeddns.ErrInvalidRequest:
		return kruntime.ServiceInvalidRequestV1
	case boundeddns.ErrInvalidState:
		return kruntime.ServiceCancelledV1
	default:
		return kruntime.ServiceUnreachableV1
	}
}

func (n *relayServiceNetworkV3) operationOwnedBytesV3() uint64 {
	var dns uint64
	if n.resolver != nil {
		dns = n.resolver.OperationOwnedBytes()
	}
	// Resolver workspace plus the exact facade (amortized into every S+H
	// reservation), numeric dial/address/wrapper holders, bounded domain/address
	// string bytes and the pinned context/net-call source inventory. The four
	// timer cells and three callback cells dominate the joined session bridge,
	// finite dial contexts and platform connect cancellation. Two 1KiB cells
	// dominate the concrete netFD/poll.FD plus sockaddr/OpError holders on the
	// qualified Windows/Linux amd64 targets; eight channel cells cover scalar
	// address-list/sysDialer/closure holders. No socket payload or TLS estimate.
	const callMetadata = 4*adapterTimerCellBytesV3 + 3*adapterCallbackCellBytesV3 + 2*1024 + 8*adapterChannelCellBytesV3
	return dns + uint64(unsafe.Sizeof(*n)) + uint64(unsafe.Sizeof(net.Dialer{})) + uint64(unsafe.Sizeof(net.TCPAddr{})) + uint64(unsafe.Sizeof(net.UDPAddr{})) + uint64(unsafe.Sizeof(net.TCPConn{})) + uint64(unsafe.Sizeof(net.UDPConn{})) + 253 + 256 + callMetadata
}

var _ boundeddns.SocketOwner = (*relaySocketOwnerV3)(nil)
var _ kruntime.RelayServiceNetworkV1 = (*relayServiceNetworkV3)(nil)
