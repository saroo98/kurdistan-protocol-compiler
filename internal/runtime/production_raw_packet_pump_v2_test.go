// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/protocol/liveprogram"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func rawPlanFixtureV2(t testing.TB, narrow sessionplan.NarrowingRequestV2) (sessionplan.PlanV2, liveprogram.ProgramV1) {
	return pumpPlanPolicyFixtureV1(t, narrow, func(p *runtimepolicy.PolicyV2) { p.SchemaVersion = runtimepolicy.SchemaVersionV2; p.Services = nil })
}

func TestRawPacketV2StrictConstruction(t *testing.T) {
	plan, program := rawPlanFixtureV2(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	cr, _, _ := duplexResultsV3(t, program)
	port, _ := NewPacketPortV1(int(plan.MTU))
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	defer port.Close()
	cfg := ServicePumpConfigV1{PacketIO: port, Carrier: a, CarrierOwnedBytes: 16, BufferBudget: 64 << 20, MaxRecordBytes: uint32(program.Limits.MaxFrameBytes), Generation: 1, AuthorityDeadline: serviceTestNowV1.Add(time.Minute), Now: func() time.Time { return serviceTestNowV1 }, CheckAuthority: func(time.Time) error { return nil }}
	if p, e := NewClientServicePumpV1(cr, plan, cfg); e == nil {
		p.Close()
		t.Fatal("service entry accepted schema2")
	}
	p, e := NewClientRawPacketPumpV2(cr, plan, cfg)
	if e != nil {
		t.Fatal("raw schema2 rejected", e)
	}
	defer p.Close()
	base := p.pump
	if base.admission != nil || len(base.streams) != 0 || len(base.probes) != 0 || base.nextID != 0 || base.nextHandle != 0 || base.codec != (ServiceRecordCodecV1{}) {
		t.Fatal("raw created service resources")
	}
	if e := p.Run(context.Background()); e == nil {
		t.Fatal("run before authenticated bind")
	}
	p.Close()
	<-p.Done()
	if p.BoundsV1().OwnedBytes != 0 {
		t.Fatal("joined raw retained ownership")
	}
}

func TestRawPacketV2RunReadyIsBoundOnceAndCancellationJoins(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "callback-failure", true: "cancel-winner"}[cancelled], func(t *testing.T) {
			plan, program := rawPlanFixtureV2(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
			cr, rr, _ := duplexResultsV3(t, program)
			port, _ := NewPacketPortV1(int(plan.MTU))
			ca, ra := net.Pipe()
			defer ca.Close()
			defer ra.Close()
			defer port.Close()
			cfg := ServicePumpConfigV1{PacketIO: port, Carrier: ca, CarrierOwnedBytes: 16, BufferBudget: 64 << 20, MaxRecordBytes: uint32(program.Limits.MaxFrameBytes), Generation: 1, AuthorityDeadline: serviceTestNowV1.Add(time.Minute), Now: func() time.Time { return serviceTestNowV1 }, CheckAuthority: func(time.Time) error { return nil }}
			c, err := NewClientRawPacketPumpV2(cr, plan, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			called := 0
			callback := func(*ServiceRunPublicationV1) error {
				called++
				if err := c.RunWithPublicationV1(context.Background(), func(*ServiceRunPublicationV1) error { t.Error("duplicate raw callback"); return nil }); err != ErrAuthenticatedFrameState {
					t.Error("duplicate raw Run", err)
				}
				return ServiceCancelledV1
			}
			if err := c.RunWithPublicationV1(context.Background(), callback); err != ErrAuthenticatedFrameState || called != 0 {
				t.Fatal("raw unbound callback", err, called)
			}
			relay, err := NewProcessRelayDuplexEndpointV1(rr, plan.Digest, program)
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Abort()
			bound := make(chan error, 1)
			go func() {
				record, e := readBoundedCarrierRecordV1(ra, 1<<20)
				if e == nil {
					record, e = relay.AcceptProfileBind(record, [32]byte{2})
				}
				if e == nil {
					e = writeBoundedRecordV1(ra, record)
				}
				bound <- e
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err = c.BindV1(ctx, [32]byte{2}); err != nil {
				t.Fatal(err)
			}
			if err = <-bound; err != nil {
				t.Fatal(err)
			}
			if cancelled {
				cancel()
			}
			if err = c.RunWithPublicationV1(ctx, callback); err != ServiceCancelledV1 {
				t.Fatal(err)
			}
			want := 1
			if cancelled {
				want = 0
			}
			if called != want {
				t.Fatal("raw callback count", called, want)
			}
			select {
			case <-c.Done():
			default:
				t.Fatal("raw Run did not join")
			}
		})
	}
}

func TestRawPacketV2PreparationExactBudget(t *testing.T) {
	plan, program := rawPlanFixtureV2(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 100})
	n := productionNarrowFixtureV1(plan)
	n.ProbeLimit = 0
	n.TCPFlows = 4096
	n.UDPFlows = 2048
	r, e := PrepareProductionClientRawPacketV2(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	b, e := r.ReservationV1()
	if e != nil {
		t.Fatal(e)
	}
	r.Close()
	if b.ProxyAttributedBytes != 0 || b.StreamChunkBytes != 0 {
		t.Fatal("raw proxy reservation")
	}
	if _, e := PrepareProductionClientRawPacketV2(plan, n, ProductionClientAvailableV1{AggregateBytes: b.OwnedBytes - 1}, serviceTestNowV1, 1); e == nil {
		t.Fatal("one-under budget accepted")
	}
	facts, _ := plan.ConstructionFactsV2()
	calculation, _ := sessionplan.AdmittedCalculationBoundsV2(facts.ProfileBytes)
	construction := max(calculation.SuffixBytes, calculation.DecoderBytes+calculation.PolicyBytes+calculation.ProgramBytes+calculation.PlanBytes+calculation.SelectionBytes)
	if _, e := PrepareProductionClientRawPacketV2(plan, n, ProductionClientAvailableV1{AggregateBytes: construction - 1}, serviceTestNowV1, 1); e == nil {
		t.Fatal("one-under construction accepted")
	}
	r, e = PrepareProductionClientRawPacketV2(plan, n, ProductionClientAvailableV1{AggregateBytes: max(b.OwnedBytes, construction)}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	i, e := r.InstallV1()
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	cr, _, _ := duplexResultsV3(t, program)
	carrier, _ := productionTLSFixtureV1(t, plan.Digest, uint32(program.Limits.MaxFrameBytes))
	a := ProductionClientAuthorityV1{Now: func() time.Time { return serviceTestNowV1 }, AuthorityDeadline: serviceTestNowV1.Add(time.Minute), CheckAuthority: func(time.Time) error { return nil }}
	p, e := NewProductionClientRawPacketPumpV2(context.Background(), cr, i, carrier, a, productionPreparationFixtureV1(t, i))
	if e != nil {
		t.Fatal(e)
	}
	base := p.pump
	if p.BoundsV1().OwnedBytes != b.OwnedBytes || len(base.queue) != 100 || len(base.streams) != 0 || len(base.probes) != 0 || len(i.admission.flow.entries) != 6144 {
		t.Fatal("maximum actual raw allocation geometry")
	}
	i.Close()
	<-i.Done()
}

func rawLegacyPairV2(t *testing.T, installed bool) (*RawPacketPumpV2, *ProcessRelayDuplexEndpointV1, io.ReadWriteCloser, *PacketPortV1, sessionplan.PlanV2, *ProductionClientInstallationV1, *atomic.Int64) {
	t.Helper()
	plan, program := rawPlanFixtureV2(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	cr, rr, _ := duplexResultsV3(t, program)
	clock := &atomic.Int64{}
	authority := ProductionClientAuthorityV1{Now: func() time.Time { return serviceTestNowV1.Add(time.Duration(clock.Load()) * time.Millisecond) }, AuthorityDeadline: serviceTestNowV1.Add(time.Minute), CheckAuthority: func(time.Time) error { return nil }}
	var c *RawPacketPumpV2
	var port *PacketPortV1
	var peer io.ReadWriteCloser
	var installation *ProductionClientInstallationV1
	exporter := [32]byte{5}
	var err error
	if installed {
		n := productionNarrowFixtureV1(plan)
		n.ProbeLimit = 0
		n.SessionIdle = 2 * time.Second
		n.FlowIdle = 2 * time.Second
		r, e := PrepareProductionClientRawPacketV2(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
		if e != nil {
			t.Fatal(e)
		}
		installation, e = r.InstallV1()
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { installation.Close(); <-installation.Done() })
		port, _ = installation.PacketPortV1()
		carrier, relayCarrier := productionTLSFixtureV1(t, plan.Digest, uint32(program.Limits.MaxFrameBytes))
		c, err = NewProductionClientRawPacketPumpV2(context.Background(), cr, installation, carrier, authority, productionPreparationFixtureV1(t, installation))
		if err != nil {
			t.Fatal(err)
		}
		peer, err = relayCarrier.SelectRecordStreamV3(context.Background(), plan.IdleTimeout)
		if err != nil {
			t.Fatal(err)
		}
		exporter, err = carrier.CarrierBinding()
		if err != nil {
			t.Fatal(err)
		}
		if e := c.BindV1(context.Background(), [32]byte{99}); !errors.Is(e, ErrProfileIncompatible) {
			t.Fatal("wrong profile binding", e)
		}
	} else {
		port, _ = NewPacketPortV1(int(plan.MTU))
		ca, ra := net.Pipe()
		peer = ra
		t.Cleanup(func() { ca.Close(); ra.Close(); port.Close() })
		c, err = NewClientRawPacketPumpV2(cr, plan, ServicePumpConfigV1{PacketIO: port, Carrier: ca, CarrierOwnedBytes: 16, BufferBudget: 64 << 20, MaxRecordBytes: uint32(program.Limits.MaxFrameBytes), Generation: 1, Now: authority.Now, AuthorityDeadline: authority.AuthorityDeadline, CheckAuthority: authority.CheckAuthority})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { c.Close(); <-c.Done() })
	r, err := NewProcessRelayDuplexEndpointV1(rr, plan.Digest, program)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Abort)
	bound := make(chan error, 1)
	go func() {
		record, e := readBoundedCarrierRecordV1(peer, 1<<20)
		if e == nil {
			record, e = r.AcceptProfileBind(record, exporter)
		}
		if e == nil {
			e = writeBoundedRecordV1(peer, record)
		}
		bound <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = c.BindV1(ctx, exporter); err != nil {
		t.Fatal(err)
	}
	if err = <-bound; err != nil {
		t.Fatal(err)
	}
	go c.Run(context.Background())
	base := c.pump
	pumpWaitUntilV1(t, func() bool { base.mu.Lock(); defer base.mu.Unlock(); return base.running })
	return c, r, peer, port, plan, installation, clock
}

func TestRawPacketV2OriginalPumpInteroperability(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(map[bool]string{false: "low-level", true: "installed-TLS"}[installed], func(t *testing.T) {
			c, relay, carrier, port, plan, i, _ := rawLegacyPairV2(t, installed)
			policy, e := plan.RuntimePolicyAt(serviceTestNowV1)
			if e != nil {
				t.Fatal(e)
			}
			program, e := liveprogram.DecodeV1(policy.LiveProgram)
			if e != nil {
				t.Fatal(e)
			}
			device := newMemoryPacketDeviceV1()
			old, e := NewPacketPumpV1(PacketPumpConfigV1{TUN: device, Carrier: carrier, Endpoint: relay, Program: program, Direction: DirectionRelayV1, AssignedIPv4: plan.ClientIPv4, DNSIPv4: plan.DNSIPv4, AssignedIPv6: plan.ClientIPv6, DNSIPv6: plan.DNSIPv6, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 1 << 20, IdleTimeout: time.Minute})
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { done <- old.Run(context.Background()) }()
			t.Cleanup(func() { c.Close(); old.Close(); <-done })
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			out := testIPv4TCPPacketV1(plan.ClientIPv4, [4]byte{1, 1, 1, 1}, 12345, 443, 0x10, []byte{1, 2})
			if e = port.Submit(ctx, out); e != nil {
				t.Fatal(e)
			}
			select {
			case got := <-device.writes:
				if !bytes.Equal(got, out) {
					t.Fatal("legacy destination bytes")
				}
			case <-ctx.Done():
				t.Fatal("legacy destination timeout")
			}
			in := testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, plan.ClientIPv4, 443, 12345, 0x10, []byte{3, 4})
			device.injectV1(t, in)
			buf := make([]byte, plan.MTU)
			token, n, e := port.Receive(ctx, buf)
			if e != nil || !bytes.Equal(buf[:n], in) {
				t.Fatal("new destination bytes", e)
			}
			base := c.pump
			state := base.endpoint.(*processClientRawEndpointV2).state
			state.mu.Lock()
			before := state.recvCount
			pending := state.pending
			state.mu.Unlock()
			if pending == nil || c.BoundsV1().PacketsProcessed != 0 {
				t.Fatal("delivery copy committed early")
			}
			if e = port.Acknowledge(ctx, token, n, nil); e != nil {
				t.Fatal(e)
			}
			pumpWaitUntilV1(t, func() bool {
				state.mu.Lock()
				defer state.mu.Unlock()
				return state.recvCount == before+1 && state.pending == nil
			})
			if i != nil {
				i.Close()
				<-i.Done()
			} else {
				c.Close()
				<-c.Done()
			}
		})
	}
}

func TestRawPacketV2InstalledReturnCommitAndIdle(t *testing.T) {
	c, relay, carrier, port, plan, i, clock := rawLegacyPairV2(t, true)
	base := c.pump
	state := base.endpoint.(*processClientRawEndpointV2).state
	clock.Store(1000)
	pumpWaitUntilV1(t, func() bool {
		base.mu.Lock()
		defer base.mu.Unlock()
		return base.lastNow == serviceTestNowV1.Add(time.Second)
	})
	in := testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, plan.ClientIPv4, 443, 12345, 0x10, []byte{3})
	records, e := relay.SealOperation(framing.Operation{Semantic: "data", StreamID: 2, Sequence: 2, Offset: 77, Payload: in}, 2)
	if e != nil {
		t.Fatal(e)
	}
	write := make(chan error, 1)
	go func() { write <- writeBoundedRecordV1(carrier, records[0]) }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	token, n, e := port.Receive(ctx, make([]byte, plan.MTU))
	if e != nil {
		t.Fatal(e)
	}
	if e = <-write; e != nil {
		t.Fatal(e)
	}
	state.mu.Lock()
	var release sync.Once
	unlock := func() { release.Do(state.mu.Unlock) }
	defer unlock()
	if e = port.Acknowledge(ctx, token, n, nil); e != nil {
		t.Fatal(e)
	}
	pumpWaitUntilV1(t, func() bool { return c.BoundsV1().PacketsProcessed == 1 })
	base.mu.Lock()
	activity := base.activity
	base.mu.Unlock()
	if activity != serviceTestNowV1 {
		t.Fatal("ack refreshed before replay commit")
	}
	unlock()
	pumpWaitUntilV1(t, func() bool {
		base.mu.Lock()
		defer base.mu.Unlock()
		return base.activity == serviceTestNowV1.Add(time.Second)
	})
	clock.Store(3000)
	select {
	case <-c.Done():
	case <-ctx.Done():
		t.Fatal("raw local idle did not join")
	}
	i.Close()
	<-i.Done()
}

func TestRawPacketV2ReportsActualLayouts(t *testing.T) {
	plan, _ := rawPlanFixtureV2(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 100})
	n := productionNarrowFixtureV1(plan)
	n.ProbeLimit = 0
	n.TCPFlows = 4096
	n.UDPFlows = 2048
	r, e := PrepareProductionClientRawPacketV2(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	b, _ := r.ReservationV1()
	t.Logf("raw=%d pump=%d recipe=%d installation=%d rawEndpoint=%d v3Endpoint=%d workspace=%d queue=%d port=%d receipt=%d reservation=%+v graph=%+v", unsafe.Sizeof(RawPacketPumpV2{}), unsafe.Sizeof(ServicePumpV1{}), unsafe.Sizeof(*r), unsafe.Sizeof(ProductionClientInstallationV1{}), unsafe.Sizeof(processClientRawEndpointV2{}), unsafe.Sizeof(ProcessClientDuplexEndpointV3{}), unsafe.Sizeof(duplexWorkspaceV3{}), unsafe.Sizeof(serviceQueueSlotV1{}), unsafe.Sizeof(PacketPortV1{}), unsafe.Sizeof(productionReturnReceiptV1{}), b, r.graph)
}

func TestRawPacketV2StrictFailuresPreserveSecret(t *testing.T) {
	for _, scenario := range []string{"schema3", "stream", "probe", "queue", "network", "network-bytes", "probe-scope", "probe-rates", "external", "short-budget", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			plan, program := rawPlanFixtureV2(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
			if scenario == "schema3" {
				plan, program = pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
			}
			cr, _, _ := duplexResultsV3(t, program)
			port, _ := NewPacketPortV1(int(plan.MTU))
			a, b := net.Pipe()
			defer port.Close()
			defer a.Close()
			defer b.Close()
			cfg := ServicePumpConfigV1{PacketIO: port, Carrier: a, CarrierOwnedBytes: 16, BufferBudget: 64 << 20, MaxRecordBytes: uint32(program.Limits.MaxFrameBytes), Generation: 1, Now: func() time.Time { return serviceTestNowV1 }, AuthorityDeadline: serviceTestNowV1.Add(time.Minute), CheckAuthority: func(time.Time) error { return nil }}
			switch scenario {
			case "stream":
				cfg.StreamLimit = 1
			case "probe":
				cfg.ProbeLimit = 1
			case "queue":
				cfg.StreamQueueBytes = 1
			case "network":
				cfg.RelayNetwork = pumpNoNetworkV1{}
			case "network-bytes":
				cfg.NetworkOperationBytes = 1
			case "probe-scope":
				cfg.ProbeScope = AuthenticatedProbeScopeV1{digest: [32]byte{1}}
			case "probe-rates":
				cfg.ProbeRates, _ = NewProbeRateRegistryV1(1)
			case "external":
				cfg.ExternalPacketIngress = true
			case "short-budget":
				preparation, err := ServicePreparationBoundsForPlanV1(plan, false)
				if err != nil {
					t.Fatal(err)
				}
				cfg.BufferBudget = preparation.OwnedBytes - 1
			case "expired":
				cfg.AuthorityDeadline = serviceTestNowV1
			}
			p, e := NewClientRawPacketPumpV2(cr, plan, cfg)
			if e == nil {
				p.Close()
				t.Fatal("invalid raw scope accepted")
			}
			if _, ok := cr.ContextSnapshotV1(); !ok {
				t.Fatal("rejection consumed secret")
			}
		})
	}
}

func TestRawPacketV2StrictRecipeAndAttachment(t *testing.T) {
	for _, scenario := range []string{"mode", "streams", "probes", "queue", "proxy-idle", "proxy-ceiling", "proxy-available", "schema3"} {
		t.Run(scenario, func(t *testing.T) {
			plan, _ := rawPlanFixtureV2(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
			n := productionNarrowFixtureV1(plan)
			n.ProbeLimit = 0
			a := ProductionClientAvailableV1{AggregateBytes: 80 << 20}
			switch scenario {
			case "mode":
				n.Mode = ProductionTUNProxyV1
			case "streams":
				n.StreamLimit = 1
			case "probes":
				n.ProbeLimit = 1
			case "queue":
				n.StreamQueueBytes = 1
			case "proxy-idle":
				n.ProxyIdle = time.Second
			case "proxy-ceiling":
				n.ProxyCeilingBytes = 16 << 20
			case "proxy-available":
				a.ProxyBytes = 1
			case "schema3":
				plan, _ = pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
			}
			r, e := PrepareProductionClientRawPacketV2(plan, n, a, serviceTestNowV1, 1)
			if e == nil {
				r.Close()
				t.Fatal("invalid raw recipe admitted")
			}
		})
	}
	for _, scenario := range []string{"raw-to-service", "service-to-raw", "probe-scope", "probe-rates", "copied", "nil"} {
		t.Run(scenario, func(t *testing.T) {
			plan, program := rawPlanFixtureV2(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
			prepare := PrepareProductionClientRawPacketV2
			if scenario == "service-to-raw" {
				plan, program = pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
				prepare = PrepareProductionClientServiceV1
			}
			n := productionNarrowFixtureV1(plan)
			if scenario != "service-to-raw" {
				n.ProbeLimit = 0
			}
			r, e := prepare(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
			if e != nil {
				t.Fatal(e)
			}
			i, e := r.InstallV1()
			if e != nil {
				t.Fatal(e)
			}
			defer i.Close()
			cr, _, _ := duplexResultsV3(t, program)
			carrier, _ := productionTLSFixtureV1(t, plan.Digest, uint32(program.Limits.MaxFrameBytes))
			a := ProductionClientAuthorityV1{Now: func() time.Time { return serviceTestNowV1 }, AuthorityDeadline: serviceTestNowV1.Add(time.Minute), CheckAuthority: func(time.Time) error { return nil }}
			if scenario == "probe-scope" {
				a.ProbeScope = AuthenticatedProbeScopeV1{digest: [32]byte{1}}
			}
			if scenario == "probe-rates" {
				a.ProbeRates, _ = NewProbeRateRegistryV1(1)
			}
			arg := i
			if scenario == "copied" {
				arg = &ProductionClientInstallationV1{self: i}
			}
			if scenario == "nil" {
				arg = nil
			}
			if scenario == "raw-to-service" {
				_, e = NewProductionClientServicePumpV1(context.Background(), cr, arg, carrier, a, productionPreparationFixtureV1(t, i))
			} else {
				_, e = NewProductionClientRawPacketPumpV2(context.Background(), cr, arg, carrier, a, productionPreparationFixtureV1(t, i))
			}
			if e == nil {
				t.Fatal("mismatched installation accepted")
			}
			if _, ok := cr.ContextSnapshotV1(); !ok {
				t.Fatal("mismatch consumed secret")
			}
			if _, e = carrier.CarrierBinding(); e == nil {
				t.Fatal("mismatch retained concrete carrier")
			}
		})
	}
}

func TestRawPacketV2RejectsServiceMalformedAndWrongAck(t *testing.T) {
	for _, scenario := range []string{"service", "malformed", "wrong-ack", "short-ack", "oversize", "protocol"} {
		t.Run(scenario, func(t *testing.T) {
			c, relay, carrier, port, plan, _, _ := rawLegacyPairV2(t, true)
			packet := testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, plan.ClientIPv4, 443, 12345, 0x10, []byte{1})
			switch scenario {
			case "service":
				packet = []byte{1, byte(ServiceDataV1), 0, 0, 0, 1, 0, 1, 7}
			case "malformed":
				packet = []byte{0x40, 0, 0, 1, 0, 0, 0, 0}
			case "oversize":
				packet = testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, plan.ClientIPv4, 443, 12345, 0x10, make([]byte, 1280))
			case "protocol":
				packet = testIPv4PacketV1([4]byte{1, 1, 1, 1}, plan.ClientIPv4, 1, make([]byte, 8))
			}
			records, e := relay.SealOperation(framing.Operation{Semantic: "data", StreamID: 2, Sequence: 2, Payload: packet}, 2)
			if e != nil {
				t.Fatal(e)
			}
			write := make(chan error, 1)
			go func() { write <- writeBoundedRecordV1(carrier, records[0]) }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if scenario == "wrong-ack" || scenario == "short-ack" {
				token, n, e := port.Receive(ctx, make([]byte, plan.MTU))
				if e != nil {
					t.Fatal(e)
				}
				if scenario == "wrong-ack" {
					token++
				} else {
					n--
				}
				if e = port.Acknowledge(ctx, token, n, nil); e == nil {
					t.Fatal("invalid ack accepted")
				}
			}
			if scenario == "wrong-ack" {
				// The existing port leaves an invalid receipt pending. The later native
				// owner owns terminating a wrong-token confirmation, not this port.
				port.mu.Lock()
				pending := port.received && !port.acked
				port.mu.Unlock()
				if !pending || c.BoundsV1().PacketsProcessed != 0 {
					t.Fatal("wrong receipt completed delivery")
				}
				c.CancelWithReason(ServiceCancelledV1)
			}
			select {
			case <-c.Done():
			case <-ctx.Done():
				t.Fatal("invalid raw record did not join")
			}
			<-write
			b := c.BoundsV1()
			if b.ServicesProcessed != 0 || b.PacketsProcessed != 0 {
				t.Fatal("invalid record delivered/dispatched")
			}
		})
	}
}

func TestRawPacketV2SourceValidationIPv6AndActualWrap(t *testing.T) {
	c, relay, carrier, port, plan, _, _ := rawLegacyPairV2(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, bad := range [][]byte{testIPv4TCPPacketV1(plan.ClientIPv4, [4]byte{1, 1, 1, 1}, 1, 443, 0x10, make([]byte, 1280)), testIPv4PacketV1(plan.ClientIPv4, [4]byte{1, 1, 1, 1}, 1, make([]byte, 8)), testIPv4TCPPacketV1([4]byte{10, 77, 0, 9}, [4]byte{1, 1, 1, 1}, 1, 443, 0x10, nil), {1, 2, 3, 4, 5, 6, 7, 8}} {
		if e := port.Submit(ctx, bad); e == nil {
			t.Fatal("invalid raw source admitted")
		}
	}
	base := c.pump
	remote := [16]byte{0x20, 1, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	tcp := testIPv4TCPPacketV1([4]byte{1}, [4]byte{2}, 12345, 443, 0x10, []byte{1})[20:]
	packet := testIPv6PacketV1(plan.ClientIPv6, remote, 6, tcp)
	for _, before := range []uint32{1, 65533, 65534} {
		base.mu.Lock()
		base.outer = before
		base.mu.Unlock()
		if e := port.Submit(ctx, packet); e != nil {
			t.Fatal("valid IPv6 source", e)
		}
		record, e := readBoundedCarrierRecordV1(carrier, 1<<20)
		if e != nil {
			t.Fatal(e)
		}
		pending, e := relay.OpenFrame(record)
		if e != nil {
			t.Fatal(e)
		}
		want := before + 1
		if want > 65534 {
			want = 2
		}
		op := pending.Operation()
		if op.StreamID != want || op.Sequence != uint64(want) || !bytes.Equal(op.Payload, packet) {
			t.Fatal("actual pump stream/sequence or IPv6 bytes")
		}
		if e = pending.Commit(); e != nil {
			t.Fatal(e)
		}
		pumpWaitUntilV1(t, func() bool { base.mu.Lock(); defer base.mu.Unlock(); return base.used == 0 })
	}
	response := testIPv6PacketV1(remote, plan.ClientIPv6, 6, tcp)
	records, e := relay.SealOperation(framing.Operation{Semantic: "data", StreamID: 2, Sequence: 65534, Offset: 99, Payload: response}, 2)
	if e != nil {
		t.Fatal(e)
	}
	write := make(chan error, 1)
	go func() { write <- writeBoundedRecordV1(carrier, records[0]) }()
	buf := make([]byte, plan.MTU)
	token, n, e := port.Receive(ctx, buf)
	if e != nil || !bytes.Equal(buf[:n], response) {
		t.Fatal("IPv6 return", e)
	}
	if e = port.Acknowledge(ctx, token, n, nil); e != nil {
		t.Fatal(e)
	}
	if e = <-write; e != nil {
		t.Fatal(e)
	}
}

func TestRawPacketV2CloseDuringConcreteBindJoins(t *testing.T) {
	plan, program := rawPlanFixtureV2(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	n := productionNarrowFixtureV1(plan)
	n.ProbeLimit = 0
	r, e := PrepareProductionClientRawPacketV2(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	i, e := r.InstallV1()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { i.Close(); <-i.Done() })
	cr, _, _ := duplexResultsV3(t, program)
	carrier, _ := productionTLSFixtureV1(t, plan.Digest, uint32(program.Limits.MaxFrameBytes))
	a := ProductionClientAuthorityV1{Now: func() time.Time { return serviceTestNowV1 }, AuthorityDeadline: serviceTestNowV1.Add(time.Minute), CheckAuthority: func(time.Time) error { return nil }}
	p, e := NewProductionClientRawPacketPumpV2(context.Background(), cr, i, carrier, a, productionPreparationFixtureV1(t, i))
	if e != nil {
		t.Fatal(e)
	}
	exporter, e := carrier.CarrierBinding()
	if e != nil {
		t.Fatal(e)
	}
	bound := make(chan error, 1)
	go func() { bound <- p.BindV1(context.Background(), exporter) }()
	base := p.pump
	pumpWaitUntilV1(t, func() bool { base.mu.Lock(); defer base.mu.Unlock(); return base.binding })
	i.Close()
	select {
	case e := <-bound:
		if e == nil {
			t.Fatal("close allowed Bind publication")
		}
	case <-time.After(time.Second):
		t.Fatal("raw Bind not joined")
	}
	<-p.Done()
	<-i.Done()
	if p.BoundsV1().OwnedBytes != 0 {
		t.Fatal("raw Bind retained storage")
	}
}
