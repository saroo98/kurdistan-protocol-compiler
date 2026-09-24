// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"io"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
	runtimeengine "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"kurdistan/internal/transport/tlstcp"
	"net"
	"net/netip"
	"testing"
	"time"
)

type productionStreamNetworkFixtureV1 struct{ address string }

func (n productionStreamNetworkFixtureV1) ResolveProxy(context.Context, []byte, *[16]netip.Addr) (int, error) {
	return 0, runtimeengine.ServiceDestinationDeniedV1
}
func (n productionStreamNetworkFixtureV1) DialTCP(ctx context.Context, a netip.AddrPort) (runtimeengine.ServiceTCPConnV1, error) {
	if a != netip.MustParseAddrPort("8.8.8.8:443") {
		return nil, runtimeengine.ServiceDestinationDeniedV1
	}
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp4", n.address)
	if e != nil {
		return nil, e
	}
	return c.(*net.TCPConn), nil
}

func TestProductionStreamV1LateOpenCancelsActualWireAndRetainsTombstone(t *testing.T) {
	f, snapshot := productionTLSCurrentFixtureV1(t, false, true)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	parentTicket, _ := reserveProductionSlotV1(&HandleRegistry{})
	p, _ := newProductionParentV1(parentTicket, 80<<20, time.Time{})
	opening, _ := p.beginUseV1(0, productionBudgetChargeV1{})
	settings := projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false))
	settings.tunnelMode = 2
	o, s := newProductionAdmissionV1(p, opening, f.current, settings, &productionRealCurrentV1{}, &productionSnapshotPlatformV1{snapshot: f.current}, func() time.Time { return f.now }, time.Now, rates, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 80 << 20, MaxArtifactBytes: 1 << 20, MaxPublicationBytes: 1 << 20})
	p.finishUseV1(opening)
	if s != 0 {
		t.Fatal("admit", s, "current", p.admission.current != nil, "plan", len(p.admission.plan.Endpoints), "resources", p.admission.resources != nil)
	}
	defer o.closeV1(context.Background())
	attemptUse, _ := p.beginUseV1(202, productionBudgetChargeV1{})
	a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, attemptUse)
	if s != 0 {
		t.Fatal(s)
	}
	b, s := a.BorrowV1()
	if s != 0 {
		t.Fatal(s)
	}
	defer func() { b.Close(); o.resources.destroyV1(); p.finishUseV1(attemptUse) }()
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	relayReady := make(chan *runtimeengine.ServicePumpV1, 1)
	peer := make(chan error, 1)
	result, carrier := productionActualHandshakeV1(t, b, snapshot, func(rr *auth.ProcessHandshakeResultV1, plan sessionplan.PlanV2, program liveprogram.ProgramV1, c *tlstcp.Conn) error {
		go func() {
			defer rr.Close()
			stream, err := c.SelectRecordStreamV3(ctx, time.Minute)
			if err != nil {
				peer <- err
				return
			}
			admission, ok := snapshot.AdmissionByProfileV1(plan.ProfileContentID, plan.ProfileGeneration)
			if !ok {
				peer <- runtimeengine.ServiceNotAdmittedV1
				return
			}
			scope, err := runtimeengine.NewAuthenticatedProbeScopeV1(envelope.CanonicalProfileV1{ProviderID: admission.ProviderID, LineageID: admission.LineageID, ProfileID: admission.ProfileID})
			if err != nil {
				peer <- err
				return
			}
			port, _ := runtimeengine.NewPacketPortV1(int(plan.MTU))
			defer port.Close()
			rp, err := runtimeengine.NewRelayServicePumpV1(rr, plan, runtimeengine.ServicePumpConfigV1{PacketIO: port, Carrier: stream, CarrierOwnedBytes: 1 << 20, PacketOwnedBytes: 65536, PacketQueuedBytes: uint64(2 * plan.MTU), StreamLimit: 4, StreamQueueBytes: 32768, ProbeLimit: 1, BufferBudget: 64 << 20, MaxRecordBytes: uint32(program.Limits.MaxFrameBytes), Generation: 1, AuthorityDeadline: time.Unix(admission.ValidUntil, 0), Now: func() time.Time { return f.now }, CheckAuthority: func(at time.Time) error {
				if at.Unix() >= admission.ValidUntil {
					return runtimeengine.ServiceAuthorityExpiredV1
				}
				return nil
			}, ProbeScope: scope, ProbeRates: rates, RelayNetwork: productionStreamNetworkFixtureV1{listener.Addr().String()}, NetworkOperationBytes: 8192})
			if err != nil {
				peer <- err
				return
			}
			defer rp.Close()
			exporter, err := c.CarrierBinding()
			if err == nil {
				err = rp.BindV1(ctx, exporter)
			}
			if err != nil {
				peer <- err
				return
			}
			relayReady <- rp
			peer <- rp.Run(ctx)
		}()
		return nil
	})
	if _, s = b.RevalidateV1(ctx); s != 0 {
		t.Fatal(s)
	}
	pump, e := b.AttachServiceV1(ctx, result, carrier)
	if e != nil {
		t.Fatal(e)
	}
	exporter, e := carrier.CarrierBinding()
	if e != nil {
		t.Fatal(e)
	}
	if e = pump.BindV1(ctx, exporter); e != nil {
		t.Fatal(e)
	}
	select {
	case <-relayReady:
	case e := <-peer:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	v := &productionSessionV1{parent: p, pump: pump, attemptContext: ctx, wake: make(chan struct{}, 1)}
	p.session = v
	started := make(chan error, 1)
	run := make(chan error, 1)
	go func() {
		run <- pump.RunWithPublicationV1(ctx, func(publication *runtimeengine.ServiceRunPublicationV1) error {
			e := publication.CommitV1()
			if e == nil {
				p.mu.Lock()
				v.ready = true
				p.mu.Unlock()
			}
			started <- e
			return e
		})
	}()
	if e = <-started; e != nil {
		t.Fatal(e)
	}
	defer func() { pump.Close(); <-run; <-peer }()
	use, _, s := v.beginIOV1(6, 259)
	if s != 0 {
		t.Fatal(s)
	}
	defer p.finishUseV1(use)
	child, s := nextProductionOpaqueIDV1(&productionOpaqueIDsV1)
	if s != 0 {
		t.Fatal(s)
	}
	v.streams[0] = productionStreamV1{child: child, attempt: use.attempt, opening: true}
	wire, e := pump.OpenStream(ctx, runtimeengine.ProxyRequestV1{Kind: 1, Address: []byte{8, 8, 8, 8}, Port: 443})
	if e != nil {
		t.Fatal(e)
	}
	conn, e := listener.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	late, stop := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer stop()
	got, status := v.finishStreamOpenV1(0, use, child, wire, nil, late)
	if got != 0 || status != 8 {
		t.Fatal("late child escaped", got, status)
	}
	var byteOut [1]byte
	if n, e := conn.Read(byteOut[:]); n != 0 || e != io.EOF {
		t.Fatal("installed stream not cancelled", n, e)
	}
	if retired, e := pump.StreamRetiredV1(wire); e != nil || retired || pump.BoundsV1().ActiveStreams != 1 || v.streams[0].wire != wire || !v.streams[0].closed {
		t.Fatal("lost actual tombstone ownership", retired, e, pump.BoundsV1().ActiveStreams, v.streams[0])
	}
}

func TestProductionStreamV1UnpublishedParentCannotReachPump(t *testing.T) {
	r := new(HandleRegistry)
	if child, s := OpenProductionStreamV1(r, 0, nil); child != 0 || s != 3 {
		t.Fatal(child, s)
	}
	if s := SendProductionStreamV1(r, 0, 1, []byte{1}); s != 3 {
		t.Fatal(s)
	}
	if n, token, s := ReceiveProductionStreamV1(r, 0, 1, make([]byte, 40)); n != 0 || token != 0 || s != 3 {
		t.Fatal(n, token, s)
	}
	if s := ConfirmProductionStreamV1(r, 0, 1, 1, 1); s != 3 {
		t.Fatal(s)
	}
	if s := RejectProductionStreamV1(r, 0, 1, 1); s != 3 {
		t.Fatal(s)
	}
	for _, f := range []func(*HandleRegistry, Handle, uint64) int32{HalfCloseProductionStreamV1, CancelProductionStreamV1, CloseProductionStreamV1} {
		if s := f(r, 0, 1); s != 3 {
			t.Fatal(s)
		}
	}
}
