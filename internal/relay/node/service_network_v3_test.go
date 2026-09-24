// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"kurdistan/internal/net/boundeddns"
	"kurdistan/internal/product/runtimepolicy"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
)

func TestServiceNetworkV3NumericSourceBindingAndRefusal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var calls int
	owner := &relaySocketOwnerV3{dial: func(_ context.Context, network, address string, local net.Addr) (net.Conn, error) {
		calls++
		endpoint, e := netip.ParseAddrPort(address)
		if e != nil {
			t.Fatal("hostname passed to dialer")
		}
		wantNetwork := "udp4"
		wantLocal := "10.77.0.1:0"
		if endpoint.Addr().Is6() {
			wantNetwork = "udp6"
			wantLocal = "[fd4b:7572:6400::1]:0"
		}
		if network != wantNetwork || local.String() != wantLocal {
			t.Errorf("wrong DNS source/network %s %s", network, local.String())
		}
		return nil, errors.New("test local refusal")
	}}
	for _, server := range ownedDNSEndpointsV3 {
		if _, e := owner.DialUDP(ctx, server); e == nil {
			t.Fatal("failed dial succeeded")
		}
	}
	if calls != 2 {
		t.Fatal("owned server families not attempted")
	}
	if _, e := owner.DialUDP(ctx, netip.MustParseAddrPort("8.8.8.8:53")); e == nil || calls != 2 {
		t.Fatal("foreign DNS endpoint escaped owner")
	}
}

func TestServiceNetworkV3TargetLateCancellationClosesRealSocket(t *testing.T) {
	r, _, spec, c := deviceFixtureV3(t, 1)
	d, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() { conn, _ := listener.AcceptTCP(); accepted <- conn }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var late *net.TCPConn
	var calls int
	owner := &relaySocketOwnerV3{dial: func(call context.Context, network, address string, local net.Addr) (net.Conn, error) {
		calls++
		if network != "tcp4" || address != "8.8.8.8:443" || local.String() != "10.77.0.1:0" {
			t.Error("target not source-bound numeric")
		}
		conn, e := new(net.Dialer).DialContext(call, "tcp4", listener.Addr().String())
		if e != nil {
			return nil, e
		}
		late = conn.(*net.TCPConn)
		cancel()
		return late, nil
	}}
	facade := &relayServiceNetworkV3{device: d, families: boundeddns.IPv4, owner: owner, now: time.Now}
	if conn, e := facade.DialTCP(ctx, netip.MustParseAddrPort("8.8.8.8:443")); conn != nil || !errors.Is(e, kruntime.ServiceCancelledV1) {
		t.Fatalf("late target published %v", e)
	}
	peer := <-accepted
	if peer != nil {
		defer peer.Close()
	}
	if late == nil {
		t.Fatal("real dial not exercised")
	}
	if _, e := late.Write([]byte{1}); e == nil {
		t.Fatal("late socket retained")
	}
	current, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	for _, target := range []string{"127.0.0.1:443", "[2001:4860::1]:443"} {
		if _, e := facade.DialTCP(current, netip.MustParseAddrPort(target)); !errors.Is(e, kruntime.ServiceDestinationDeniedV1) {
			t.Fatal("private/disabled target admitted")
		}
	}
	if calls != 1 {
		t.Fatal("rejected targets reached dialer")
	}
}

func TestServiceNetworkV3OwnedDNSFamiliesAndEffectiveAnswerMask(t *testing.T) {
	for _, family := range []int{0, 1} {
		t.Run([]string{"udp4", "udp6"}[family], func(t *testing.T) {
			network := "udp4"
			local := "127.0.0.1:0"
			if family == 1 {
				network = "udp6"
				local = "[::1]:0"
			}
			listener, err := net.ListenPacket(network, local)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			tcpNetwork := []string{"tcp4", "tcp6"}[family]
			tcp, err := net.Listen(tcpNetwork, listener.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			tcpDone := make(chan struct{})
			go func() {
				defer close(tcpDone)
				conn, e := tcp.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				var prefix [2]byte
				if _, e = io.ReadFull(conn, prefix[:]); e != nil {
					return
				}
				body := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
				if _, e = io.ReadFull(conn, body); e != nil {
					return
				}
				var query dnsmessage.Message
				if query.Unpack(body) != nil || len(query.Questions) != 1 || query.Questions[0].Type != dnsmessage.TypeAAAA {
					t.Error("TCP DNS answer-family request changed")
					return
				}
				response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88}}}}}
				body, e = response.Pack()
				if e != nil {
					t.Error(e)
					return
				}
				binary.BigEndian.PutUint16(prefix[:], uint16(len(body)))
				conn.Write(prefix[:])
				conn.Write(body)
			}()
			t.Cleanup(func() { tcp.Close(); waitDeviceV3(t, tcpDone) })
			done := make(chan struct{})
			received := make(chan struct{}, 1)
			go func() {
				defer close(done)
				var raw [2048]byte
				for i := 0; i < 2; i++ {
					listener.SetReadDeadline(time.Now().Add(3 * time.Second))
					n, peer, e := listener.ReadFrom(raw[:])
					if e != nil {
						return
					}
					var query dnsmessage.Message
					if query.Unpack(raw[:n]) != nil || len(query.Questions) != 1 {
						t.Error("invalid DNS test query")
						return
					}
					if query.Questions[0].Type != dnsmessage.TypeAAAA {
						t.Error("effective IPv6 answer mask widened to A")
					}
					if i == 1 {
						received <- struct{}{}
						continue
					} // blocked exchange is canceled by the device
					response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, Truncated: true}, Questions: query.Questions}
					body, e := response.Pack()
					if e != nil {
						t.Error(e)
						return
					}
					listener.WriteTo(body, peer)
				}
			}()
			t.Cleanup(func() { listener.Close(); waitDeviceV3(t, done) })
			owner := &relaySocketOwnerV3{dial: func(ctx context.Context, gotNetwork, address string, source net.Addr) (net.Conn, error) {
				if gotNetwork != network && gotNetwork != tcpNetwork || address != ownedDNSEndpointsV3[family].String() {
					t.Error("DNS transport family changed")
				}
				want := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ownedDNSEndpointsV3[family].Addr(), 0))
				if source.String() != want.String() {
					t.Error("DNS source is not relay owned")
				}
				return new(net.Dialer).DialContext(ctx, gotNetwork, listener.LocalAddr().String())
			}}
			resolver, err := boundeddns.NewResolver(ownedDNSEndpointsV3[family:family+1], owner, 1)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { resolver.Close(); waitDeviceV3(t, resolver.Done()) }()
			r, _, spec, c := deviceFixtureV3(t, 1)
			d, err := r.RegisterV3(spec, c)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			facade := &relayServiceNetworkV3{device: d, families: boundeddns.IPv6, resolver: resolver, owner: owner, now: time.Now}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var addresses [16]netip.Addr
			n, err := facade.ResolveProxy(ctx, []byte("example.com"), &addresses)
			if err != nil || n != 1 || !addresses[0].Is6() {
				t.Fatalf("AAAA over owned transport failed %d %v", n, err)
			}
			callDone := make(chan error, 1)
			go func() { _, e := facade.ResolveProxy(ctx, []byte("example.com"), &addresses); callDone <- e }()
			waitDeviceV3(t, received)
			d.Close()
			select {
			case e := <-callDone:
				if !errors.Is(e, kruntime.ServiceCancelledV1) {
					t.Errorf("session DNS cancel wrong category %v", e)
				}
			case <-time.After(time.Second):
				t.Fatal("DNS cancellation did not unblock exchange")
			}
			waitDeviceV3(t, d.Done())
			for _, address := range addresses {
				if address.IsValid() {
					t.Fatal("canceled DNS retained partial answers")
				}
			}
			select {
			case <-resolver.Done():
				t.Fatal("session stop closed shared resolver")
			default:
			}
		})
	}
}

func TestServiceAdapterV3OwnedResourceInventory(t *testing.T) {
	r, _, spec, c := deviceFixtureV3(t, 1)
	d, e := r.RegisterV3(spec, c)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	owner := &relaySocketOwnerV3{}
	resolver, e := boundeddns.NewResolver(ownedDNSEndpointsV3[:], owner, 16)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { resolver.Close(); <-resolver.Done() }()
	facade := relayServiceNetworkV3{device: d, resolver: resolver, owner: owner, families: boundeddns.IPv4, now: time.Now}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()
	timerContext := reflect.TypeOf(ctx).Elem().Size()
	connType := reflect.TypeOf(net.TCPConn{}).Field(0).Type
	fdType := connType.Field(0).Type.Elem()
	if fdType.Size() > 1024 {
		t.Fatal("pinned netFD exceeds source envelope")
	}
	if timerContext > 128 {
		t.Fatal("pinned timerCtx exceeds source envelope")
	}
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Fatal("resource inventory requires qualified 64-bit target")
	}
	type rateState struct {
		starts    [60]time.Time
		count     int
		lastStart time.Time
	}
	rateEntry := uint64(32 + unsafe.Sizeof(rateState{}))
	if d.BoundsV3().QueuedPayloadBytes != 0 || facade.operationOwnedBytesV3() > 1<<20 {
		t.Fatal("invalid adapter reservation")
	}
	t.Logf("device=%d record=%d identity=%d subjectStringsMax=%d contextInventory=%d deviceOwned=%d queued=0", unsafe.Sizeof(*d), unsafe.Sizeof(sessionRecord{}), len(spec.ID)+len(spec.ProfileID)+len(spec.ClientKeyID), 7*128, deviceContextBytesV3, d.BoundsV3().OwnedBytes)
	t.Logf("facade=%d dialer=%d tcpaddr=%d udpaddr=%d tcpconn=%d udpconn=%d netFD=%d timerCtx=%d networkOperation=%d resolverOperation=%d resolverFixed16=%d", unsafe.Sizeof(facade), unsafe.Sizeof(net.Dialer{}), unsafe.Sizeof(net.TCPAddr{}), unsafe.Sizeof(net.UDPAddr{}), unsafe.Sizeof(net.TCPConn{}), unsafe.Sizeof(net.UDPConn{}), fdType.Size(), timerContext, facade.operationOwnedBytesV3(), resolver.OperationOwnedBytes(), resolver.FixedOwnedBytes())
	t.Logf("server=%d registry=%d action=%d endpointTable=%d probeRegistry=%d probeEntryPayload=%d probe4096Payload=%d globalTUNScratch=65535 errorFanin=5", unsafe.Sizeof(ServerV1{}), unsafe.Sizeof(SessionRegistry{}), unsafe.Sizeof(serviceStopActionV3{}), unsafe.Sizeof(ownedDNSEndpointsV3), unsafe.Sizeof(kruntime.ProbeRateRegistryV1{}), rateEntry, 4096*rateEntry)
	t.Logf("negativeViewStruct=%d subjectStruct=%d negativeViewMaxIdentityBacking=%d", unsafe.Sizeof(selfhost.RelayRevocationViewV3{}), unsafe.Sizeof(selfhost.RelayRevocationSubjectV3{}), (4+512)*128)
}

func BenchmarkServiceAdapterV3RegisterClose(b *testing.B) {
	tunnel := &healthTunnelV3{memoryTunnelV1: newMemoryTunnelV1(), failure: make(chan struct{})}
	r, e := NewSessionRegistry(tunnel, 1, 1)
	if e != nil {
		b.Fatal(e)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	spec := SessionSpec{ID: "bench", ProfileID: "profile", ClientKeyID: "client", AssignedIPv4: [4]byte{10, 89, 0, 2}, DNSIPv4: testRelayDNSIPv4V1}
	cfg := SessionDeviceConfigV3{Context: ctx, AuthorityDeadline: time.Now().Add(time.Hour), MaxPacketBytes: 1280, BudgetBytes: 1 << 20, PayloadProtocols: []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolUDP}}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		d, e := r.RegisterV3(spec, cfg)
		if e != nil {
			b.Fatal(e)
		}
		if e = d.holdAttemptV3(); e != nil {
			b.Fatal(e)
		}
		d.Close()
		d.releaseAttemptV3()
		<-d.Done()
	}
}
