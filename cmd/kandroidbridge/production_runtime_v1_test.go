//go:build phase18productiontest && (android || linux)

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"kurdistan/internal/androidbridge"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type productionOwnerFixturePlatformV1 struct {
	*productionFixturePlatformV1
	settings              []byte
	leaseFailure          bool
	socketCloseStatus     int32
	socketCloseEntered    chan struct{}
	socketCloseRelease    chan struct{}
	socketRegisterEntered chan uint64
	socketRegisterRelease chan struct{}
	socketRegisterDone    <-chan struct{}
}

func TestProductionRuntimeV1SuccessorSnapshotUsesActualAttemptCount(t *testing.T) {
	for _, raw := range []bool{true, false} {
		t.Run(map[bool]string{true: "schema2", false: "schema3"}[raw], func(t *testing.T) {
			second, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer second.Close()
			_, old, first, snapshot, now := productionSignedNetworkEndpointsFixtureV1(t, raw, false, second.Addr().String())
			platform := &productionOwnerFixturePlatformV1{productionFixturePlatformV1: &productionFixturePlatformV1{input: old.input}, settings: productionFixtureSettingsV1()}
			config := productionRuntimeConfigV1(platform)
			config.Now = func() time.Time { return now }
			var registry androidbridge.HandleRegistry
			opening := make([]byte, 32768)
			h, n, s := androidbridge.OpenProductionV1(&registry, productionOwnerRequestV1(platform), opening, config)
			if s != 0 {
				t.Fatal(s)
			}
			defer androidbridge.CloseProductionV1(&registry, h)
			opening = opening[:n]
			original := bytes.Clone(opening)
			// KPN1's fixed tail after fallbackAttemptsUsed is exactly 76 bytes.
			countOffset := len(opening) - 77
			if opening[countOffset] != 0 || opening[countOffset-1] != 2 {
				t.Fatal("opening attempt bounds", opening[countOffset-1:countOffset+1])
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ready := make(chan productionOwnerRelayV1, 2)
			peers := make(chan error, 2)
			for _, listener := range []net.Listener{first, second} {
				go func(l net.Listener) {
					peers <- productionOwnerPeerV1(ctx, l, snapshot, now, raw, productionLocalServiceNetworkV1{}, ready)
				}(listener)
			}
			defer func() {
				androidbridge.CloseProductionV1(&registry, h)
				first.Close()
				second.Close()
				cancel()
				<-peers
				<-peers
			}()
			var previousEpoch uint64
			for attempt := byte(1); attempt <= 2; attempt++ {
				for {
					event := productionOwnerControlV1(t, &registry, h)
					kind := event[5]
					if kind == 1 {
						if s = androidbridge.ConfirmProductionSocketV1(&registry, h, binary.BigEndian.Uint64(event[32:40]), 1, 0, 0); s != 0 {
							t.Fatal(s)
						}
					}
					if kind == 10 || kind == 11 || kind == 12 {
						t.Fatal("successor terminal", kind, event[32:])
					}
					if (attempt == 1 && kind == 4) || (attempt == 2 && kind == 6) {
						body := event[32:]
						if body[countOffset] != attempt {
							t.Errorf("authenticated snapshot attempt count=%d want=%d", body[countOffset], attempt)
						}
						expected := bytes.Clone(original)
						expected[countOffset] = attempt
						if !bytes.Equal(body, expected) {
							t.Error("authenticated snapshot differs from opening beyond current count")
						}
						epoch := binary.BigEndian.Uint64(event[12:20])
						if epoch <= previousEpoch {
							t.Fatal("successor epoch", epoch, previousEpoch)
						}
						previousEpoch = epoch
						break
					}
				}
				select {
				case <-ready:
				case <-ctx.Done():
					t.Fatal("actual relay Run not reached")
				}
				if attempt == 1 {
					if s = androidbridge.ReconnectProductionV1(&registry, h, 1); s != 0 {
						t.Fatal("reconnect", s)
					}
				}
			}
			if !bytes.Equal(opening, original) {
				t.Fatal("opening output mutated by attempts")
			}
		})
	}
}

type productionLocalServiceNetworkV1 struct {
	address string
	failure error
}

type productionReadyGateFactoryV1 struct {
	productionNetworkFactoryV1
	transport chan *productionReadyGateTransportV1
}

func (f productionReadyGateFactoryV1) PrepareV1(b *androidbridge.ProductionAttemptBorrowV1) (androidbridge.ProductionAttemptTransportV1, int32) {
	actual, s := f.productionNetworkFactoryV1.PrepareV1(b)
	if s != 0 {
		return actual, s
	}
	n := actual.(*productionAttemptTransportV1)
	v := &productionReadyGateTransportV1{productionAttemptTransportV1: n, entered: make(chan struct{}), release: make(chan struct{}), published: make(chan int32, 1), closeEntered: make(chan struct{}), closeRelease: make(chan struct{})}
	f.transport <- v
	return v, 0
}

type productionReadyGateTransportV1 struct {
	*productionAttemptTransportV1
	entered, release, closeEntered, closeRelease chan struct{}
	published                                    chan int32
}
type productionReadyGateConnV1 struct {
	net.Conn
	entered, release chan struct{}
	once             sync.Once
}

func (c *productionReadyGateConnV1) Close() error {
	c.once.Do(func() { close(c.entered); <-c.release })
	return c.Conn.Close()
}
func (v *productionReadyGateTransportV1) ConnectProtectedV1(ctx context.Context) int32 {
	s := v.productionAttemptTransportV1.ConnectProtectedV1(ctx)
	if s == 0 {
		v.raw = &productionReadyGateConnV1{Conn: v.raw, entered: v.closeEntered, release: v.closeRelease}
	}
	return s
}
func (v *productionReadyGateTransportV1) RunV1(ctx context.Context, ready func(*kruntime.ServiceRunPublicationV1) int32) int32 {
	return v.productionAttemptTransportV1.RunV1(ctx, func(publication *kruntime.ServiceRunPublicationV1) int32 {
		close(v.entered)
		<-v.release
		s := ready(publication)
		v.published <- s
		return s
	})
}

func TestProductionRuntimeV1RuntimeTerminalAndNativePublicationWinners(t *testing.T) {
	for _, raw := range []bool{true, false} {
		for _, terminalFirst := range []bool{true, false} {
			t.Run(map[bool]string{true: "schema2", false: "schema3"}[raw]+map[bool]string{true: "/terminal", false: "/publication"}[terminalFirst], func(t *testing.T) {
				_, old, listener, snapshot, now := productionSignedNetworkFixtureV1(t, raw)
				platform := &productionOwnerFixturePlatformV1{productionFixturePlatformV1: &productionFixturePlatformV1{input: old.input}, settings: productionFixtureSettingsV1()}
				factory := productionReadyGateFactoryV1{transport: make(chan *productionReadyGateTransportV1, 1)}
				config := productionRuntimeConfigV1(platform)
				config.Now = func() time.Time { return now }
				config.Factory = factory
				var registry androidbridge.HandleRegistry
				h, _, s := androidbridge.OpenProductionV1(&registry, productionOwnerRequestV1(platform), make([]byte, 32768), config)
				if s != 0 {
					t.Fatal(s)
				}
				v := <-factory.transport
				var releaseOnce, closeOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(v.release) }) }
				unclog := func() { closeOnce.Do(func() { close(v.closeRelease) }) }
				defer func() { release(); unclog(); androidbridge.CloseProductionV1(&registry, h) }()
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				bound, resume := make(chan struct{}), make(chan struct{})
				peer := make(chan error, 1)
				go func() {
					peer <- productionControlledPeerExchangeV1(ctx, listener, snapshot, now, raw, "run-hold", bound, resume)
				}()
				defer func() { close(resume); <-peer }()
				event := productionOwnerControlV1(t, &registry, h)
				if s = androidbridge.ConfirmProductionSocketV1(&registry, h, binary.BigEndian.Uint64(event[32:40]), 1, 0, 0); s != 0 {
					t.Fatal(s)
				}
				if event = productionOwnerControlV1(t, &registry, h); event[5] != 2 {
					t.Fatal(event[5])
				}
				select {
				case <-v.entered:
				case <-ctx.Done():
					t.Fatal("publication not reached")
				}
				closed := make(chan struct{})
				closePump := func() {
					go func() {
						if raw {
							v.packet.Close()
						} else {
							v.service.CancelWithReason(kruntime.ServiceUnreachableV1)
						}
						close(closed)
					}()
				}
				if terminalFirst {
					closePump()
					select {
					case <-v.closeEntered:
					case <-ctx.Done():
						t.Fatal("terminal close not reached")
					}
				}
				release()
				select {
				case s = <-v.published:
				case <-ctx.Done():
					t.Fatal("publication did not return")
				}
				if terminalFirst && s == 0 {
					t.Error("terminal runtime published native readiness")
				}
				if !terminalFirst {
					if s != 0 {
						t.Fatal("publication winner", s)
					}
					for _, kind := range []byte{3, 4} {
						if event = productionOwnerControlV1(t, &registry, h); event[5] != kind {
							t.Fatal("published batch", event[5], kind)
						}
					}
					closePump()
					<-v.closeEntered
				}
				unclog()
				select {
				case <-closed:
				case <-ctx.Done():
					t.Fatal("pump close did not join")
				}
			})
		}
	}
}

func (n productionLocalServiceNetworkV1) ResolveProxy(context.Context, []byte, *[16]netip.Addr) (int, error) {
	return 0, kruntime.ServiceDestinationDeniedV1
}
func (n productionLocalServiceNetworkV1) DialTCP(ctx context.Context, address netip.AddrPort) (kruntime.ServiceTCPConnV1, error) {
	if address != netip.MustParseAddrPort("8.8.8.8:443") {
		return nil, kruntime.ServiceDestinationDeniedV1
	}
	if n.failure != nil {
		return nil, n.failure
	}
	// The authenticated signed target is mapped only by this host fixture to a
	// real loopback listener. It never dials public DNS or an Internet target.
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", n.address)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

type productionOwnerRelayV1 struct {
	port *kruntime.PacketPortV1
	plan sessionplan.PlanV2
}

func productionOwnerPeerV1(ctx context.Context, listener net.Listener, snapshot *selfhost.RelayRuntimeSnapshotV1, now time.Time, raw bool, network productionLocalServiceNetworkV1, ready chan<- productionOwnerRelayV1) error {
	return productionControlledPeerExchangeV1(ctx, listener, snapshot, now, raw, "", nil, nil, func(result *auth.ProcessHandshakeResultV1, plan sessionplan.PlanV2, program liveprogram.ProgramV1, stream io.ReadWriteCloser, exporter [32]byte) error {
		port, err := kruntime.NewPacketPortV1(int(plan.MTU))
		if err != nil {
			return err
		}
		defer port.Close()
		if raw {
			endpoint, err := kruntime.NewProcessRelayDuplexEndpointV1(result, plan.Digest, program)
			if err != nil {
				return err
			}
			defer endpoint.Abort()
			var prefix [4]byte
			if _, err = io.ReadFull(stream, prefix[:]); err != nil {
				return err
			}
			n := binary.BigEndian.Uint32(prefix[:])
			if n == 0 || n > 1<<20 {
				return errors.New("fixture bound size")
			}
			bind := make([]byte, n)
			if _, err = io.ReadFull(stream, bind); err != nil {
				return err
			}
			response, err := endpoint.AcceptProfileBind(bind, exporter)
			clear(bind)
			if err != nil {
				return err
			}
			defer clear(response)
			binary.BigEndian.PutUint32(prefix[:], uint32(len(response)))
			if _, err = stream.Write(prefix[:]); err != nil {
				return err
			}
			if _, err = stream.Write(response); err != nil {
				return err
			}
			pump, err := kruntime.NewPacketPumpV1(kruntime.PacketPumpConfigV1{TUN: port, Carrier: stream, Endpoint: endpoint, Program: program, Direction: kruntime.DirectionRelayV1, AssignedIPv4: plan.ClientIPv4, DNSIPv4: plan.DNSIPv4, AssignedIPv6: plan.ClientIPv6, DNSIPv6: plan.DNSIPv6, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 1 << 20, IdleTimeout: time.Minute})
			if err != nil {
				return err
			}
			defer pump.Close()
			ready <- productionOwnerRelayV1{port, plan}
			return pump.Run(ctx)
		}
		admission, ok := snapshot.AdmissionByProfileV1(plan.ProfileContentID, plan.ProfileGeneration)
		if !ok {
			return errors.New("fixture missing authority")
		}
		scope, err := kruntime.NewAuthenticatedProbeScopeV1(envelope.CanonicalProfileV1{ProviderID: admission.ProviderID, LineageID: admission.LineageID, ProfileID: admission.ProfileID})
		if err != nil {
			return err
		}
		rates, err := kruntime.NewProbeRateRegistryV1(64)
		if err != nil {
			return err
		}
		start := time.Now()
		config := kruntime.ServicePumpConfigV1{PacketIO: port, Carrier: stream, CarrierOwnedBytes: 1 << 20, PacketOwnedBytes: 65536, PacketQueuedBytes: uint64(2 * plan.MTU), ProbeLimit: 1, BufferBudget: 64 << 20, MaxRecordBytes: uint32(program.Limits.MaxFrameBytes), Generation: 1, AuthorityDeadline: time.Unix(admission.ValidUntil, 0), Now: func() time.Time { return now.Add(time.Since(start)) }, CheckAuthority: func(at time.Time) error {
			if _, ok := snapshot.AdmissionByProfileV1(plan.ProfileContentID, plan.ProfileGeneration); !ok || at.Unix() >= admission.ValidUntil {
				return kruntime.ServiceAuthorityExpiredV1
			}
			return nil
		}, ProbeScope: scope, ProbeRates: rates, RelayNetwork: network, NetworkOperationBytes: 8192}
		if admission.RuntimePolicy.Services.Proxy != nil {
			config.StreamLimit = 4
			config.StreamQueueBytes = 32768
		}
		pump, err := kruntime.NewRelayServicePumpV1(result, plan, config)
		if err != nil {
			return err
		}
		defer pump.Close()
		if err = pump.BindV1(ctx, exporter); err != nil {
			return err
		}
		ready <- productionOwnerRelayV1{port, plan}
		return pump.Run(ctx)
	})
}

func productionOwnerPacketV1(source, destination [4]byte, sourcePort, destinationPort uint16, payload byte) []byte {
	packet := make([]byte, 41)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	checksum := func(input []byte) uint16 {
		var sum uint32
		for i := 0; i < len(input); i += 2 {
			sum += uint32(input[i]) << 8
			if i+1 < len(input) {
				sum += uint32(input[i+1])
			}
		}
		for sum>>16 != 0 {
			sum = sum&65535 + sum>>16
		}
		return ^uint16(sum)
	}
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	packet[32] = 0x50
	packet[33] = 0x10
	packet[34], packet[35] = 0xff, 0xff
	packet[40] = payload
	pseudo := make([]byte, 12+21)
	copy(pseudo[:8], packet[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], 21)
	copy(pseudo[12:], packet[20:])
	binary.BigEndian.PutUint16(packet[36:38], checksum(pseudo))
	return packet
}

func TestProductionRuntimeV1GenuinePacketsStreamsAndProbe(t *testing.T) {
	for _, scenario := range []struct {
		raw   bool
		fault string
	}{{true, ""}, {false, ""}, {true, "packet-wrong"}, {false, "packet-short"}, {false, "packet-reject"}, {false, "packet-repeat"}, {false, "stream-wrong"}, {false, "stream-short"}, {false, "stream-reject"}, {false, "stream-repeat"}, {false, "peer-revoked"}, {false, "invalidation"}, {false, "no-path"}} {
		raw, fault := scenario.raw, scenario.fault
		t.Run(map[bool]string{true: "schema2", false: "schema3"}[raw]+"/"+fault, func(t *testing.T) {
			_, old, listener, snapshot, now := productionSignedNetworkServicesFixtureV1(t, raw, !raw)
			settings := productionFixtureSettingsV1()
			if !raw {
				settings[58] = 2
			}
			p := &productionOwnerFixturePlatformV1{productionFixturePlatformV1: &productionFixturePlatformV1{input: old.input}, settings: settings}
			config := productionRuntimeConfigV1(p)
			config.Now = func() time.Time { return now }
			var registry androidbridge.HandleRegistry
			h, _, s := androidbridge.OpenProductionV1(&registry, productionOwnerRequestV1(p), make([]byte, 32768), config)
			if s != 0 {
				t.Fatal("open", s)
			}
			t.Cleanup(func() {
				if s := androidbridge.CloseProductionV1(&registry, h); s != 0 {
					t.Error("owner close", s)
				}
			})
			target, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			network := productionLocalServiceNetworkV1{address: target.Addr().String()}
			if fault == "peer-revoked" {
				network.failure = kruntime.ServiceAuthorityRevokedV1
			}
			ready := make(chan productionOwnerRelayV1, 1)
			peer := make(chan error, 1)
			go func() { peer <- productionOwnerPeerV1(ctx, listener, snapshot, now, raw, network, ready) }()
			stop := func() {
				if s := androidbridge.CancelProductionV1(&registry, h); s != 0 {
					t.Fatal("joined cancel", s)
				}
				cancel()
				select {
				case <-peer:
				case <-time.After(3 * time.Second):
					t.Fatal("peer failed to join")
				}
			}
			event := productionOwnerControlV1(t, &registry, h)
			if event[5] != 1 {
				t.Fatal("first socket", event[5])
			}
			token := binary.BigEndian.Uint64(event[32:40])
			if s := androidbridge.ConfirmProductionSocketV1(&registry, h, token, 1, 0, 0); s != 0 {
				t.Fatal(s)
			}
			var relay productionOwnerRelayV1
			select {
			case relay = <-ready:
			case err := <-peer:
				t.Fatal("peer setup", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			for _, kind := range []byte{2, 3, 4} {
				if event = productionOwnerControlV1(t, &registry, h); event[5] != kind {
					t.Fatal("event", event[5], kind)
				}
			}
			outbound := productionOwnerPacketV1(relay.plan.ClientIPv4, [4]byte{8, 8, 8, 8}, 12345, 443, 17)
			if s := androidbridge.SubmitProductionPacketV1(&registry, h, outbound); s != 0 {
				t.Fatal("submit", s)
			}
			buf := make([]byte, relay.plan.MTU)
			receipt, n, err := relay.port.Receive(ctx, buf)
			if err != nil || !bytes.Equal(buf[:n], outbound) {
				t.Fatal("authenticated outbound", n, err)
			}
			if err = relay.port.Acknowledge(ctx, receipt, n, nil); err != nil {
				t.Fatal(err)
			}
			inbound := productionOwnerPacketV1([4]byte{8, 8, 8, 8}, relay.plan.ClientIPv4, 443, 12345, 29)
			if err = relay.port.Submit(ctx, inbound); err != nil {
				t.Fatal(err)
			}
			short := bytes.Repeat([]byte{0x5a}, 40)
			if n, tok, s := androidbridge.ReceiveProductionPacketV1(&registry, h, short); n != 0 || tok != 0 || s != 4 || !bytes.Equal(short, bytes.Repeat([]byte{0x5a}, 40)) {
				t.Fatal("short packet consumed", n, tok, s)
			}
			n, token, s = androidbridge.ReceiveProductionPacketV1(&registry, h, buf)
			if s != 0 || token == 0 || !bytes.Equal(buf[:n], inbound) {
				t.Fatal("authenticated inbound", n, s)
			}
			if fault == "invalidation" {
				// The real copied delivery remains a counted owner when revision changes.
				p.mu.Lock()
				invalidate := p.invalidate
				p.mu.Unlock()
				if code := invalidate(); code != androidbridge.CodeOK {
					t.Fatal("synchronous invalidation", code)
				}
				if s := androidbridge.ConfirmProductionPacketV1(&registry, h, token, uint32(n)); s == 0 {
					t.Fatal("stale delivery confirmed")
				}
				event = productionOwnerControlV1(t, &registry, h)
				if event[5] == 10 {
					t.Fatal("revision change fabricated Revoked")
				}
				stop()
				return
			}
			if fault == "packet-wrong" || fault == "packet-short" || fault == "packet-reject" {
				want := int32(3)
				if fault == "packet-wrong" {
					s = androidbridge.ConfirmProductionPacketV1(&registry, h, token+1, uint32(n))
				}
				if fault == "packet-short" {
					s = androidbridge.ConfirmProductionPacketV1(&registry, h, token, uint32(n-1))
				}
				if fault == "packet-reject" {
					want = 7
					s = androidbridge.RejectProductionPacketV1(&registry, h, token)
				}
				if s != want {
					t.Fatal("invalid packet confirmation", s, want)
				}
				stop()
				return
			}
			if s = androidbridge.ConfirmProductionPacketV1(&registry, h, token, uint32(n)); s != 0 {
				t.Fatal("packet confirmation", s)
			}
			if fault == "packet-repeat" {
				if s := androidbridge.ConfirmProductionPacketV1(&registry, h, token, uint32(n)); s != 3 {
					t.Fatal("repeated packet", s)
				}
				stop()
				return
			}
			if fault == "no-path" {
				if s := androidbridge.HandoverProductionV1(&registry, h, 0, 0); s != 0 {
					t.Fatal("null handover admission", s)
				}
				for _, kind := range []byte{8, 9} {
					if event = productionOwnerControlV1(t, &registry, h); event[5] != kind {
						t.Fatal("null path must degrade without ambient default", event[5], kind)
					}
				}
				if s := androidbridge.SubmitProductionPacketV1(&registry, h, outbound); s == 0 {
					t.Fatal("old attempt accepted packets after no-path")
				}
				stop()
				return
			}
			if !raw {
				child, s := androidbridge.OpenProductionStreamV1(&registry, h, []byte{1, 1, 0, 4, 8, 8, 8, 8, 1, 187})
				if fault == "peer-revoked" {
					if child != 0 || s != 7 {
						t.Fatal("authenticated peer category became native verifier proof", child, s)
					}
					stop()
					event = productionOwnerControlV1(t, &registry, h)
					if event[5] == 10 {
						t.Fatal("peer emitted Revoked")
					}
					return
				}
				if s != 0 || child == 0 {
					t.Fatal("stream open", child, s)
				}
				connection, err := target.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(5 * time.Second))
				if s = androidbridge.SendProductionStreamV1(&registry, h, child, []byte{3, 5, 7}); s != 0 {
					t.Fatal("stream send", s)
				}
				var sent [3]byte
				if _, err = io.ReadFull(connection, sent[:]); err != nil || sent != [3]byte{3, 5, 7} {
					t.Fatal("real stream bytes", sent, err)
				}
				if _, err = connection.Write([]byte{2, 4, 6}); err != nil {
					t.Fatal(err)
				}
				if n, tok, s := androidbridge.ReceiveProductionStreamV1(&registry, h, child, make([]byte, 2)); n != 0 || tok != 0 || s != 4 {
					t.Fatal("short stream consumed", n, tok, s)
				}
				n, token, s = androidbridge.ReceiveProductionStreamV1(&registry, h, child, buf)
				if s != 0 || !bytes.Equal(buf[:n], []byte{2, 4, 6}) {
					t.Fatal("stream receive", n, s)
				}
				if fault == "stream-wrong" || fault == "stream-short" || fault == "stream-reject" {
					want := int32(3)
					if fault == "stream-wrong" {
						s = androidbridge.ConfirmProductionStreamV1(&registry, h, child, token+1, uint32(n))
					}
					if fault == "stream-short" {
						s = androidbridge.ConfirmProductionStreamV1(&registry, h, child, token, uint32(n-1))
					}
					if fault == "stream-reject" {
						want = 7
						s = androidbridge.RejectProductionStreamV1(&registry, h, child, token)
					}
					if s != want {
						t.Fatal("invalid stream confirmation", s, want)
					}
					stop()
					return
				}
				if s = androidbridge.ConfirmProductionStreamV1(&registry, h, child, token, uint32(n)); s != 0 {
					t.Fatal("stream confirm", s)
				}
				if fault == "stream-repeat" {
					if s := androidbridge.ConfirmProductionStreamV1(&registry, h, child, token, uint32(n)); s != 3 {
						t.Fatal("repeated stream", s)
					}
					stop()
					return
				}
				if s = androidbridge.HalfCloseProductionStreamV1(&registry, h, child); s != 0 {
					t.Fatal("real FIN", s)
				}
				if s = androidbridge.HalfCloseProductionStreamV1(&registry, h, child); s != 0 {
					t.Fatal("idempotent FIN", s)
				}
				if n, err = connection.Read(buf); n != 0 || err != io.EOF {
					t.Fatal("destination FIN", n, err)
				}
				if err = connection.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if n, tok, s := androidbridge.ReceiveProductionStreamV1(&registry, h, child, buf); n != 0 || tok != 0 || s != 19 {
					t.Fatal("remote FIN", n, tok, s)
				}
				probe := []byte{1, 0, 1, 1, 3, 232, 3, 232, 1}
				result := make([]byte, 21)
				if n, s := androidbridge.RunProductionProbeV1(&registry, h, probe, result); n != 21 || s != 0 || result[1] != 2 || result[3] != 1 || result[4] != 1 || result[5] != 0 || binary.BigEndian.Uint16(result[19:]) != 0 {
					t.Fatal("actual active probe", n, s, result)
				}
				probeConn, err := target.Accept()
				if err != nil {
					t.Fatal(err)
				}
				probeConn.Close()
			} else {
				if child, s := androidbridge.OpenProductionStreamV1(&registry, h, []byte{1, 1, 0, 4, 8, 8, 8, 8, 1, 187}); child != 0 || s != 1 {
					t.Fatal("raw service leaked", child, s)
				}
			}
			stop()
		})
	}
}
func (p *productionOwnerFixturePlatformV1) RegisterProductionCurrentV1(epoch uint64, e *androidbridge.ProductionCurrentExpectationV1, invalidate func() androidbridge.ErrorCode) (androidbridge.MaintenanceRevisionRegistrationV1, androidbridge.ErrorCode) {
	if !e.MatchesSettingsV1(p.settings) {
		return nil, androidbridge.CodeStateCorrupt
	}
	_, code := p.productionFixturePlatformV1.RegisterProductionCurrentV1(epoch, e, invalidate)
	if code != androidbridge.CodeOK {
		return nil, code
	}
	return p, code
}
func (p *productionOwnerFixturePlatformV1) AcquirePublication(ctx context.Context) (androidbridge.MaintenancePublicationLeaseV1, androidbridge.MaintenanceResultV1) {
	return productionOwnerFixtureLeaseV1{p}, p.Revalidate(ctx)
}

type productionOwnerFixtureLeaseV1 struct {
	p *productionOwnerFixturePlatformV1
}

func (l productionOwnerFixtureLeaseV1) IsCurrent() bool {
	return l.p.Revalidate(context.Background()) == androidbridge.MaintenanceSuccess
}
func (l productionOwnerFixtureLeaseV1) Close() androidbridge.ErrorCode {
	if l.p.leaseFailure {
		return androidbridge.CodeStateCorrupt
	}
	return androidbridge.CodeOK
}
func (p *productionOwnerFixturePlatformV1) RegisterProductionSocketV1(ctx context.Context, e *androidbridge.ProductionSocketExpectationV1) (androidbridge.ProductionSocketRegistrationV1, int32) {
	_, _, token, fd, live := e.IdentityV1()
	if !live || token == 0 || fd < 0 || ctx.Err() != nil {
		return nil, 3
	}
	if p.socketRegisterEntered != nil {
		p.socketRegisterDone = ctx.Done()
		p.socketRegisterEntered <- token
		<-p.socketRegisterRelease
	}
	return &productionOwnerFixtureSocketV1{done: make(chan struct{}), status: p.socketCloseStatus, entered: p.socketCloseEntered, release: p.socketCloseRelease}, 0
}

type productionOwnerFixtureSocketV1 struct {
	done             chan struct{}
	once             sync.Once
	status           int32
	entered, release chan struct{}
}

func (s *productionOwnerFixtureSocketV1) BindingRequiredV1() bool { return false }
func (s *productionOwnerFixtureSocketV1) ConfirmV1(ok, has uint8, network uint64) int32 {
	if ok != 1 {
		return 16
	}
	if has != 0 || network != 0 {
		return 3
	}
	return 0
}
func (s *productionOwnerFixtureSocketV1) DoneV1() <-chan struct{} { return s.done }
func (s *productionOwnerFixtureSocketV1) CloseV1() int32 {
	s.once.Do(func() {
		if s.entered != nil {
			close(s.entered)
			<-s.release
		}
		close(s.done)
	})
	return s.status
}
func productionOwnerRequestV1(p *productionOwnerFixturePlatformV1) []byte {
	parts := [][]byte{p.settings, p.input.VerifyRequest, p.input.ActivationRecord, p.input.RecipientRequest, p.input.RecipientPrivate}
	out := make([]byte, 32)
	copy(out, "KPO1")
	out[4], out[5] = 1, 1
	for i := 0; i < 3; i++ {
		binary.BigEndian.PutUint32(out[12+4*i:], uint32(len(parts[i])))
	}
	binary.BigEndian.PutUint16(out[24:], uint16(len(parts[3])))
	binary.BigEndian.PutUint16(out[26:], uint16(len(parts[4])))
	for _, part := range parts {
		out = append(out, part...)
	}
	binary.BigEndian.PutUint32(out[8:], uint32(len(out)))
	return out
}
func productionOwnerControlV1(t *testing.T, r *androidbridge.HandleRegistry, h androidbridge.Handle) []byte {
	t.Helper()
	out := make([]byte, 32800)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, s := androidbridge.NextProductionControlV1(r, h, out)
		if s == 20 {
			continue
		}
		if s != 0 {
			t.Fatalf("control status=%d", s)
		}
		return out[:n]
	}
	t.Fatal("control deadline")
	return nil
}

func TestProductionRuntimeV1GenuineOwnerOpenProtectRunAndClose(t *testing.T) {
	for _, raw := range []bool{true, false} {
		t.Run(map[bool]string{true: "schema2", false: "schema3"}[raw], func(t *testing.T) {
			_, old, listener, snapshot, now := productionSignedNetworkFixtureV1(t, raw)
			p := &productionOwnerFixturePlatformV1{productionFixturePlatformV1: &productionFixturePlatformV1{input: old.input}, settings: productionFixtureSettingsV1()}
			config := productionRuntimeConfigV1(p)
			config.Now = func() time.Time { return now }
			var registry androidbridge.HandleRegistry
			output := bytes.Repeat([]byte{0xa5}, 32768)
			h, n, s := androidbridge.OpenProductionV1(&registry, productionOwnerRequestV1(p), output, config)
			if s != 0 || h == 0 || n < 220 || string(output[:4]) != "KPN1" {
				t.Fatal("genuine opening", h, n, s)
			}
			t.Cleanup(func() {
				if result := androidbridge.CloseProductionV1(&registry, h); result != 0 {
					t.Error("owner cleanup", result)
				}
			})
			event := productionOwnerControlV1(t, &registry, h)
			if event[5] != 1 {
				t.Fatal("socket must be first", event[5])
			}
			token := binary.BigEndian.Uint64(event[32:40])
			bound, resume := make(chan struct{}), make(chan struct{})
			peer := make(chan error, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			go func() {
				peer <- productionControlledPeerExchangeV1(ctx, listener, snapshot, now, raw, "run-hold", bound, resume)
			}()
			if s = androidbridge.ConfirmProductionSocketV1(&registry, h, token, 1, 0, 0); s != 0 {
				t.Fatal("command admission", s)
			}
			for _, kind := range []byte{2, 3, 4} {
				if event = productionOwnerControlV1(t, &registry, h); event[5] != kind {
					t.Fatal("opening event order", event[5], kind)
				}
			}
			select {
			case <-bound:
			case <-ctx.Done():
				t.Fatal("no actual Bind")
			}
			if s = androidbridge.CancelProductionV1(&registry, h); s != 0 {
				t.Fatal("cancel", s)
			}
			close(resume)
			if e := <-peer; e != nil {
				t.Fatal("peer", e)
			}
			if s = androidbridge.CloseProductionV1(&registry, h); s != 0 {
				t.Fatal("close", s)
			}
			if s = androidbridge.CancelProductionV1(&registry, h); s != 0 {
				t.Fatal("retired cancel", s)
			}
		})
	}
}

func TestProductionRuntimeV1FailedInitialLeaseLeavesOutputAndReservationOwned(t *testing.T) {
	_, old, _, _, now := productionSignedNetworkFixtureV1(t, false)
	p := &productionOwnerFixturePlatformV1{productionFixturePlatformV1: &productionFixturePlatformV1{input: old.input}, settings: productionFixtureSettingsV1(), leaseFailure: true}
	config := productionRuntimeConfigV1(p)
	config.Now = func() time.Time { return now }
	var r androidbridge.HandleRegistry
	out := bytes.Repeat([]byte{0x5a}, 32768)
	h, n, s := androidbridge.OpenProductionV1(&r, productionOwnerRequestV1(p), out, config)
	if h != 0 || n != 0 || s != 3 || !bytes.Equal(out, bytes.Repeat([]byte{0x5a}, 32768)) {
		t.Fatal("failed lease published output", h, n, s)
	}
	var fillers []androidbridge.Handle
	for {
		id, code := r.Open(androidbridge.HandleDiagnostic, &struct{}{})
		if code != androidbridge.CodeOK {
			break
		}
		fillers = append(fillers, id)
	}
	if len(fillers) != 63 {
		t.Fatal("failed lease owner prematurely retired", len(fillers))
	}
	for _, id := range fillers {
		r.Free(id)
	}
	if config.ProbeRates != productionMaintenanceConfigV1(androidbridge.MaintenanceConfigV1{}).ProbeRates {
		t.Fatal("maintenance reset process rate history")
	}
}

func TestProductionRuntimeV1ActualSocketCloseIsJoinedAndFailureRetained(t *testing.T) {
	_, old, listener, snapshot, now := productionSignedNetworkFixtureV1(t, true)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	p := &productionOwnerFixturePlatformV1{productionFixturePlatformV1: &productionFixturePlatformV1{input: old.input}, settings: productionFixtureSettingsV1(), socketCloseStatus: 9, socketCloseEntered: entered, socketCloseRelease: release}
	config := productionRuntimeConfigV1(p)
	config.Now = func() time.Time { return now }
	var r androidbridge.HandleRegistry
	h, _, s := androidbridge.OpenProductionV1(&r, productionOwnerRequestV1(p), make([]byte, 32768), config)
	if s != 0 {
		t.Fatal(s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bound, resume := make(chan struct{}), make(chan struct{})
	peer := make(chan error, 1)
	go func() {
		peer <- productionControlledPeerExchangeV1(ctx, listener, snapshot, now, true, "run-hold", bound, resume)
	}()
	defer func() { close(resume); <-peer }()
	event := productionOwnerControlV1(t, &r, h)
	token := binary.BigEndian.Uint64(event[32:40])
	if s = androidbridge.ConfirmProductionSocketV1(&r, h, token, 1, 0, 0); s != 0 {
		t.Fatal(s)
	}
	for _, kind := range []byte{2, 3, 4} {
		if event = productionOwnerControlV1(t, &r, h); event[5] != kind {
			t.Fatal(event[5])
		}
	}
	<-bound
	finished := make(chan int32, 1)
	go func() { finished <- androidbridge.CloseProductionV1(&r, h) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("actual close never entered")
	}
	select {
	case s := <-finished:
		t.Fatal("close returned before owned platform close", s)
	default:
	}
	if s := androidbridge.ReconnectProductionV1(&r, h, 1); s == 0 {
		t.Fatal("successor admitted during teardown")
	}
	unblock()
	if s := <-finished; s != 9 {
		t.Fatal("lost first cleanup error", s)
	}
	if s := androidbridge.CloseProductionV1(&r, h); s != 9 {
		t.Fatal("repeated close changed first error", s)
	}
	if s := androidbridge.CancelProductionV1(&r, h); s != 9 {
		t.Fatal("cancel lost close error", s)
	}
}

func TestProductionRuntimeV1CancelDrainsPendingCommandBeforeAttemptJoin(t *testing.T) {
	_, old, _, _, now := productionSignedNetworkFixtureV1(t, true)
	entered, release := make(chan uint64, 1), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	p := &productionOwnerFixturePlatformV1{productionFixturePlatformV1: &productionFixturePlatformV1{input: old.input}, settings: productionFixtureSettingsV1(), socketRegisterEntered: entered, socketRegisterRelease: release}
	config := productionRuntimeConfigV1(p)
	config.Now = func() time.Time { return now }
	var r androidbridge.HandleRegistry
	h, _, s := androidbridge.OpenProductionV1(&r, productionOwnerRequestV1(p), make([]byte, 32768), config)
	if s != 0 {
		t.Fatal(s)
	}
	var token uint64
	select {
	case token = <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("registration did not enter")
	}
	if s := androidbridge.ConfirmProductionSocketV1(&r, h, token, 1, 0, 0); s != 0 {
		t.Fatal("real bounded command", s)
	}
	finished := make(chan int32, 1)
	go func() { finished <- androidbridge.CancelProductionV1(&r, h) }()
	<-p.socketRegisterDone
	unblock()
	select {
	case s := <-finished:
		if s != 0 {
			t.Fatal("cancel", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pending command stranded attempt join")
	}
	if s := androidbridge.CloseProductionV1(&r, h); s != 0 {
		t.Fatal("close", s)
	}
}
