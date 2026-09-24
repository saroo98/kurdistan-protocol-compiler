// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
	"net"
	"net/netip"
	"reflect"
	goruntime "runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func pumpPlanFixtureV1(t testing.TB, narrow sessionplan.NarrowingRequestV2) (sessionplan.PlanV2, liveprogram.ProgramV1) {
	return pumpPlanPolicyFixtureV1(t, narrow, nil)
}
func pumpPlanPolicyFixtureV1(t testing.TB, narrow sessionplan.NarrowingRequestV2, change func(*runtimepolicy.PolicyV2)) (sessionplan.PlanV2, liveprogram.ProgramV1) {
	t.Helper()
	policy := servicePolicyFixtureV1(t)
	// Pump-success fixtures issue a genuinely larger signed service policy.
	policy.Services.Proxy.MaxBufferBytes = 64 << 20
	policy.AllowedIPModes = []runtimepolicy.IPModeV2{runtimepolicy.IPModeDualStack, runtimepolicy.IPModeIPv4Only, runtimepolicy.IPModeIPv6Only}
	slices.Sort(policy.AllowedIPModes)
	if change != nil {
		change(&policy)
	}
	if policy.SchemaVersion == runtimepolicy.SchemaVersionV3 {
		serviceSignPolicyV1(t, &policy)
	} else {
		var err error
		policy.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestV2At(policy, serviceTestNowV1)
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, e := runtimepolicy.EncodeRuntimeAt(policy, serviceTestNowV1)
	if e != nil {
		t.Fatal(e)
	}
	profile := envelope.CanonicalProfileV1{ContentID: "content.pump", ProfileID: "profile.pump", LineageID: "lineage.pump", ProviderID: "provider.pump", ContractVersion: "product-profile-admission-v1", RevocationScope: "revocation.pump", SnapshotMode: "full-snapshot", UpdateKind: "initial", Generation: 1, RequiredSafetyFloor: 1, ValidFrom: serviceTestNowV1.Add(-time.Minute).Unix(), ValidUntil: serviceTestNowV1.Add(time.Hour).Unix(), RootEpoch: 1, RevocationEpoch: 1, RelayIDs: []string{policy.RelayAuthKeyID}, StrategyIDs: []string{"strategy.kurd-tls13-tcp"}, Policy: raw}
	if policy.Services != nil && policy.Services.Update != nil {
		profile.ProfileID = policy.Services.Update.ProfileID
	}
	receipt := lifecycle.VerifiedReceipt{ContentID: profile.ContentID, ProviderID: profile.ProviderID, LineageID: profile.LineageID, AuthenticatedArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RootEpoch: 1, RevocationEpoch: 1, RecipientEpoch: 1}
	plan, e := sessionplan.BuildV2At(sessionplan.RequestV2{Profile: profile, ActivationReceipt: receipt, RuntimePolicy: policy, Requested: narrow}, serviceTestNowV1)
	if e != nil {
		t.Fatal(e)
	}
	program, e := liveprogram.DecodeV1(policy.LiveProgram)
	if e != nil {
		t.Fatal(e)
	}
	return plan, program
}

type pumpNoNetworkV1 struct{}

func (pumpNoNetworkV1) ResolveProxy(context.Context, []byte, *[16]netip.Addr) (int, error) {
	return 0, ServiceDestinationDeniedV1
}
func (pumpNoNetworkV1) DialTCP(context.Context, netip.AddrPort) (ServiceTCPConnV1, error) {
	return nil, ServiceUnreachableV1
}
func pumpPairFixtureV1(t testing.TB, network RelayServiceNetworkV1, external bool) (*ServicePumpV1, *ServicePumpV1, *PacketPortV1, *PacketPortV1) {
	return pumpPairNarrowV1(t, network, external, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
}
func pumpPairNarrowV1(t testing.TB, network RelayServiceNetworkV1, external bool, narrow sessionplan.NarrowingRequestV2) (*ServicePumpV1, *ServicePumpV1, *PacketPortV1, *PacketPortV1) {
	return pumpPairPolicyV1(t, network, external, narrow, nil)
}
func pumpPairPolicyV1(t testing.TB, network RelayServiceNetworkV1, external bool, narrow sessionplan.NarrowingRequestV2, change func(*runtimepolicy.PolicyV2)) (*ServicePumpV1, *ServicePumpV1, *PacketPortV1, *PacketPortV1) {
	t.Helper()
	plan, program := pumpPlanPolicyFixtureV1(t, narrow, change)
	cr, rr, _ := duplexResultsV3(t, program)
	ca, ra := net.Pipe()
	cp, _ := NewPacketPortV1(1280)
	rp, _ := NewPacketPortV1(1280)
	t.Cleanup(func() { ca.Close(); ra.Close(); cp.Close(); rp.Close() })
	scope, _ := NewAuthenticatedProbeScopeV1(envelope.CanonicalProfileV1{ProviderID: "provider.pump", LineageID: "lineage.pump", ProfileID: "profile.pump"})
	rates, _ := NewProbeRateRegistryV1(1)
	start := time.Now()
	now := func() time.Time { return serviceTestNowV1.Add(time.Since(start)) }
	cfg := ServicePumpConfigV1{PacketIO: cp, Carrier: ca, CarrierOwnedBytes: uint64(unsafe.Sizeof(ca)), StreamLimit: 4, ProbeLimit: 2, StreamQueueBytes: 1024, BufferBudget: 64 << 20, MaxRecordBytes: 1 << 20, Generation: 1, AuthorityDeadline: serviceTestNowV1.Add(time.Minute), Now: now, CheckAuthority: func(time.Time) error { return nil }, ProbeScope: scope, ProbeRates: rates}
	policy, e := plan.RuntimePolicyAt(serviceTestNowV1)
	if e != nil {
		t.Fatal(e)
	}
	if policy.Services.Proxy == nil {
		cfg.StreamLimit = 0
		cfg.StreamQueueBytes = 0
	}
	if policy.Services.Probes == nil {
		cfg.ProbeLimit = 0
	}
	c, e := NewClientServicePumpV1(cr, plan, cfg)
	if e != nil {
		t.Fatal(e)
	}
	cfg.PacketIO = rp
	cfg.Carrier = ra
	cfg.ExternalPacketIngress = external
	cfg.PacketOwnedBytes = 2560 + uint64(unsafe.Sizeof(*rp)) + serviceWorkerReserveV1
	cfg.PacketQueuedBytes = 2560
	cfg.NetworkOperationBytes = 8192
	cfg.RelayNetwork = network
	if network == nil {
		cfg.RelayNetwork = pumpNoNetworkV1{}
	}
	if cfg.StreamLimit == 0 && cfg.ProbeLimit == 0 {
		cfg.RelayNetwork = nil
		cfg.NetworkOperationBytes = 0
	}
	cfg.ProbeRates, _ = NewProbeRateRegistryV1(1)
	r, e := NewRelayServicePumpV1(rr, plan, cfg)
	if e != nil {
		c.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c.Close()
		r.Close()
		select {
		case <-c.Done():
		case <-time.After(2 * time.Second):
			t.Error("client join")
		}
		select {
		case <-r.Done():
		case <-time.After(2 * time.Second):
			t.Error("relay join")
		}
	})
	return c, r, cp, rp
}

func TestServicePumpV1Fix1AuthenticatedAbsentServicesReturnNotAdmitted(t *testing.T) {
	for _, proxy := range []bool{true, false} {
		t.Run(map[bool]string{true: "proxy", false: "probe"}[proxy], func(t *testing.T) {
			c, r, _, _ := pumpPairPolicyV1(t, nil, false, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1, IPMode: runtimepolicy.IPModeIPv6Only}, func(p *runtimepolicy.PolicyV2) {
				if proxy {
					p.Services.Proxy = nil
				} else {
					p.Services.Probes = nil
				}
			})
			// Hold only the relay Run. The client uses the real authenticated endpoint
			// to send a forbidden control and read the categorical protected reply.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			bound := make(chan error, 1)
			go func() { bound <- r.BindV1(ctx, [32]byte{1}) }()
			if e := c.BindV1(ctx, [32]byte{1}); e != nil {
				t.Fatal(e)
			}
			if e := <-bound; e != nil {
				t.Fatal(e)
			}
			go r.Run(context.Background())
			body := []byte{1, 0, 4, 1, 1, 1, 1, 1, 187}
			op := ServiceOpenV1
			wantOp := ServiceOpenResultV1
			if !proxy {
				body = []byte{0, 7, 1, 3, 232}
				op = ServiceProbeV1
				wantOp = ServiceProbeResultV1
			}
			var raw [272]byte
			n, e := c.codec.Encode(raw[:], ServiceRecordViewV1{Opcode: op, ID: 1, Body: body}, ServiceClientToRelayV1, 0)
			if e != nil {
				t.Fatal(e)
			}
			record, e := c.endpoint.SealDataV3(raw[:n], 2, 2)
			if e != nil {
				t.Fatal(e)
			}
			if e = writeBoundedRecordV1(c.cfg.Carrier, record); e != nil {
				t.Fatal(e)
			}
			record, e = c.readRecordV1()
			if e != nil {
				t.Fatal(e)
			}
			pending, e := c.endpoint.OpenFrameV3(record)
			if e != nil {
				t.Fatal(e)
			}
			defer pending.Discard()
			n, e = pending.CopyPayloadIntoV3(raw[:])
			if e != nil {
				t.Fatal(e)
			}
			view, e := c.codec.DecodeBorrowed(raw[:n], ServiceRelayToClientV1, 1000)
			if e != nil {
				t.Fatal(e)
			}
			if view.Opcode != wantOp || view.Body[0] != 0 || view.Body[1] != 1 {
				t.Fatal("absent service reply is not NOT_ADMITTED")
			}
			if e = pending.Commit(); e != nil {
				t.Fatal(e)
			}
		})
	}
}

type pumpCloseGateV1 struct {
	ServiceTCPConnV1
	entered, release chan struct{}
}

func (c pumpCloseGateV1) Close() error {
	e := c.ServiceTCPConnV1.Close()
	close(c.entered)
	<-c.release
	return e
}
func TestServicePumpV1Fix1FinalizerTurnoverCannotExceedRegistrationBudget(t *testing.T) {
	l, network := pumpLocalListenerV1(t)
	c, r, _, _ := pumpPairFixtureV1(t, network, false)
	pumpStartPairV1(t, c, r)
	conn, e := network.DialTCP(context.Background(), netip.MustParseAddrPort("1.1.1.1:443"))
	if e != nil {
		t.Fatal(e)
	}
	peer, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	gated := pumpCloseGateV1{conn, make(chan struct{}), make(chan struct{})}
	defer close(gated.release)
	leaf, cancelLeaf := context.WithCancel(context.Background())
	defer cancelLeaf()
	// Enter the real stream-worker retirement defer with both halves consumed.
	r.mu.Lock()
	r.streams[0] = serviceStreamSlotV1{id: 1, state: 2, worker: true, conn: gated, cancel: cancelLeaf, localFIN: true, remoteFIN: true}
	r.nextID = 1
	r.users++
	r.mu.Unlock()
	go r.workerV1(func() error { return r.streamWorkerV1(0, 1, r.ctx) })
	<-gated.entered
	if leaf.Err() != context.Canceled {
		t.Error("retired operation context not cancelled before blocking Close")
	}
	held := 0
	for {
		e = r.beginUseV1(true)
		if e != nil {
			break
		}
		held++
	}
	defer func() {
		for range held {
			r.endUseV1()
		}
	}()
	if e != ServiceResourceLimitV1 {
		t.Fatal(e)
	}
	r.mu.Lock()
	reusable := r.streams[0].state == 0
	users := r.users
	r.mu.Unlock()
	if !reusable || users != 8+3*len(r.streams)+3*len(r.probes) {
		t.Fatal("finalizer pressure not established")
	}
	c.mu.Lock()
	c.nextID = 1
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e = c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443}); e != ServiceResourceLimitV1 {
		t.Error("replacement registered past live finalizer reservation", e)
	}
}

type pumpCarrierCloseGateV1 struct {
	io.ReadWriteCloser
	entered, release chan struct{}
}

func (c pumpCarrierCloseGateV1) Close() error {
	close(c.entered)
	<-c.release
	return c.ReadWriteCloser.Close()
}

type pumpCancellationDialV1 struct {
	pumpNoNetworkV1
	entered            chan context.Context
	cancelled, release chan struct{}
}

func (n pumpCancellationDialV1) DialTCP(ctx context.Context, _ netip.AddrPort) (ServiceTCPConnV1, error) {
	n.entered <- ctx
	<-ctx.Done()
	close(n.cancelled)
	<-n.release
	return nil, ctx.Err()
}
func TestServicePumpV1Fix1OwnedLeafCancellationPrecedesBlockedCarrierClose(t *testing.T) {
	network := pumpCancellationDialV1{entered: make(chan context.Context, 1), cancelled: make(chan struct{}), release: make(chan struct{})}
	c, r, _, _ := pumpPairFixtureV1(t, network, false)
	gated := pumpCarrierCloseGateV1{r.cfg.Carrier, make(chan struct{}), make(chan struct{})}
	r.cfg.Carrier = gated
	pumpStartPairV1(t, c, r)
	if _, e := c.StartProbe(context.Background(), ProbeRequestV1{7, 1, 1000, 2000, 1}); e != nil {
		t.Fatal(e)
	}
	leaf := <-network.entered
	// Pinned-runtime metadata check: service churn must not populate the
	// long-lived root cancelCtx child map. Leaf ownership is the fixed slot.
	root := reflect.ValueOf(r.ctx).Elem().FieldByName("children")
	if root.Len() != 0 {
		t.Error("service operation retained shared root child membership")
	}
	stopped := make(chan struct{})
	go func() { r.CancelWithReason(ServiceAuthorityRevokedV1); close(stopped) }()
	<-gated.entered
	if leaf.Err() != context.Canceled {
		t.Error("blocking carrier Close prevented leaf cancellation")
	}
	close(gated.release)
	close(network.release)
	<-stopped
	select {
	case <-network.cancelled:
	case <-time.After(time.Second):
		t.Fatal("owned dial was not canceled")
	}
	select {
	case <-r.Done():
	case <-time.After(time.Second):
		t.Fatal("owned leaf did not join terminal cleanup")
	}
}

func TestServicePumpV1Fix1FourProtocolsAndICMPv6Narrowing(t *testing.T) {
	all := []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolICMP, runtimepolicy.PayloadProtocolICMPv6, runtimepolicy.PayloadProtocolTCP, runtimepolicy.PayloadProtocolUDP}
	change := func(p *runtimepolicy.PolicyV2) { p.AllowedProtocols = all }
	for _, mode := range []string{"all", "icmpv6", "icmp"} {
		t.Run(mode, func(t *testing.T) {
			narrow := sessionplan.NarrowingRequestV2{MaxQueuePackets: 1}
			if mode == "icmpv6" {
				narrow.PayloadProtocols = []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolICMPv6}
			}
			if mode == "icmp" {
				narrow.PayloadProtocols = []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolICMP}
			}
			c, _, _, _ := pumpPairPolicyV1(t, nil, false, narrow, change)
			if mode == "all" {
				packet := testIPv4UDPPacketV1(c.client4, [4]byte{1, 1, 1, 1}, 12345, 443, []byte{1})
				if e := c.validatePacketV1(packet, true); e != nil {
					t.Error("fourth effective protocol truncated", e)
				}
			}
			packet := testIPv6PacketV1(c.client6, netip.MustParseAddr("2606:4700::1111").As16(), 58, []byte{128, 0, 0, 0, 0, 0, 0, 1})
			e := c.validatePacketV1(packet, true)
			if mode == "icmp" {
				if e != ErrPacketProtocol {
					t.Error("ICMP authority incorrectly admitted ICMPv6", e)
				}
			} else if e != nil {
				t.Error("ICMPv6 authority not honored", e)
			}
		})
	}
}
func TestServicePumpV1ExternalIngressSameRingBeforeRun(t *testing.T) {
	c, r, cp, _ := pumpPairFixtureV1(t, nil, true)
	packet := testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, [4]byte{10, 77, 0, 2}, 443, 12345, 0x10, []byte{7})
	want := bytes.Clone(packet)
	if e := r.TrySubmitReturnPacketV3(packet); e != nil {
		t.Fatal(e)
	}
	clear(packet)
	if e := r.TrySubmitReturnPacketV3(want); e != ServiceResourceLimitV1 {
		t.Fatal("K descriptor saturation not bounded", e)
	}
	if r.BoundsV1().QueueUsed != 1 {
		t.Fatal("ingress bypassed same ring")
	}
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out := make([]byte, 1280)
	token, n, e := cp.Receive(ctx, out)
	if e != nil || !bytes.Equal(out[:n], want) {
		t.Fatal("retained caller slice or lost pre-run packet", e)
	}
	cp.Acknowledge(ctx, token, n, nil)
}
func TestServicePumpV1EffectiveFamilyAndProtocolRejectBeforeEnqueue(t *testing.T) {
	c, r, _, _ := pumpPairNarrowV1(t, nil, true, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1, IPMode: runtimepolicy.IPModeIPv6Only, PayloadProtocols: []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolTCP}})
	if e := r.TrySubmitReturnPacketV3(testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, [4]byte{10, 77, 0, 2}, 443, 12345, 0x10, nil)); e == nil {
		t.Fatal("disabled IPv4 recovered")
	}
	if r.BoundsV1().QueueUsed != 0 {
		t.Fatal("invalid packet reserved descriptor")
	}
	pumpStartPairV1(t, c, r)
	if _, e := c.OpenStream(context.Background(), ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443}); e != ServiceDestinationDeniedV1 {
		t.Fatal("disabled numeric proxy accepted", e)
	}
	if _, e := c.StartProbe(context.Background(), ProbeRequestV1{7, 1, 1000, 1000, 1}); e != ServiceDestinationDeniedV1 {
		t.Fatal("disabled numeric probe accepted", e)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nextID != 0 {
		t.Fatal("denial consumed wire ID")
	}
}
func pumpStartPairV1(t testing.TB, c, r *ServicePumpV1) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ch := make(chan error, 1)
	go func() { ch <- r.BindV1(ctx, [32]byte{1}) }()
	if e := c.BindV1(ctx, [32]byte{1}); e != nil {
		t.Fatal("client bind", e)
	}
	if e := <-ch; e != nil {
		t.Fatal("relay bind", e)
	}
	go c.Run(context.Background())
	go r.Run(context.Background())
	for _, p := range []*ServicePumpV1{c, r} {
		for {
			p.mu.Lock()
			running := p.running
			p.mu.Unlock()
			if running {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("run not started")
			default:
				time.Sleep(time.Millisecond)
			}
		}
	}
}

func TestServicePumpV1RunPublicationRequiresBindAndJoinsCallbackFailure(t *testing.T) {
	c, r, _, _ := pumpPairFixtureV1(t, nil, false)
	called := 0
	if e := c.RunWithPublicationV1(context.Background(), func(*ServiceRunPublicationV1) error { called++; return nil }); e != ErrAuthenticatedFrameState || called != 0 {
		t.Fatal("unbound readiness", e, called)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	bound := make(chan error, 1)
	go func() { bound <- r.BindV1(ctx, [32]byte{1}) }()
	if e := c.BindV1(ctx, [32]byte{1}); e != nil {
		t.Fatal(e)
	}
	if e := <-bound; e != nil {
		t.Fatal(e)
	}
	go r.Run(context.Background())
	if e := c.RunWithPublicationV1(ctx, func(*ServiceRunPublicationV1) error {
		called++
		c.mu.Lock()
		running := c.running
		c.mu.Unlock()
		if !running {
			t.Error("callback before real Run admission")
		}
		if duplicate := c.RunWithPublicationV1(ctx, func(*ServiceRunPublicationV1) error { t.Error("duplicate callback"); return nil }); duplicate != ErrAuthenticatedFrameState {
			t.Error("duplicate Run", duplicate)
		}
		return ServiceCancelledV1
	}); e != ServiceCancelledV1 {
		t.Fatal("callback cancellation", e)
	}
	if called != 1 {
		t.Fatal("callback count", called)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("Run returned before joined shutdown")
	}
}

func TestServicePumpV1CancelledRunContextCannotPublishReady(t *testing.T) {
	c, r, _, _ := pumpPairFixtureV1(t, nil, false)
	ctx, cancel := context.WithCancel(context.Background())
	bound := make(chan error, 1)
	go func() { bound <- r.BindV1(ctx, [32]byte{4}) }()
	if err := c.BindV1(ctx, [32]byte{4}); err != nil {
		t.Fatal(err)
	}
	if err := <-bound; err != nil {
		t.Fatal(err)
	}
	cancel()
	called := false
	if err := c.RunWithPublicationV1(ctx, func(*ServiceRunPublicationV1) error { called = true; return nil }); err == nil || called {
		t.Fatal("cancel winner published readiness", err, called)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("cancelled run did not join")
	}
}

func TestServicePumpV1RunPublicationRejectsMissingRepeatedAndEscapedCommit(t *testing.T) {
	for _, mode := range []string{"missing", "repeated", "escaped"} {
		t.Run(mode, func(t *testing.T) {
			c, r, _, _ := pumpPairFixtureV1(t, nil, false)
			if e := c.RunWithPublicationV1(context.Background(), nil); e != ServiceInvalidRequestV1 {
				t.Fatal("nil publication callback", e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			bound := make(chan error, 1)
			go func() { bound <- r.BindV1(ctx, [32]byte{8}) }()
			if e := c.BindV1(ctx, [32]byte{8}); e != nil {
				t.Fatal(e)
			}
			if e := <-bound; e != nil {
				t.Fatal(e)
			}
			peer := make(chan error, 1)
			go func() { peer <- r.Run(ctx) }()
			defer func() { r.Close(); <-peer }()
			var escaped *ServiceRunPublicationV1
			err := c.RunWithPublicationV1(ctx, func(p *ServiceRunPublicationV1) error {
				escaped = p
				if mode == "escaped" {
					if e := p.CommitV1(); e != nil {
						t.Fatal(e)
					}
					return ServiceCancelledV1
				}
				if mode == "repeated" {
					if e := p.CommitV1(); e != nil {
						t.Fatal(e)
					}
					if e := p.CommitV1(); e == nil {
						t.Error("repeat accepted")
					}
				}
				return nil
			})
			want := error(ErrAuthenticatedFrameState)
			if mode == "escaped" {
				want = ServiceCancelledV1
			}
			if err != want {
				t.Fatal("invalid publication reported success", err)
			}
			if escaped == nil || escaped.CommitV1() != ErrAuthenticatedFrameState {
				t.Fatal("escaped capability accepted")
			}
			select {
			case <-c.Done():
			default:
				t.Fatal("callback rejection did not join")
			}
		})
	}
}
func TestServicePumpV1AuthenticatedPacketsBothDirectionsAndAck(t *testing.T) {
	c, r, cp, rp := pumpPairFixtureV1(t, nil, false)
	pumpStartPairV1(t, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	outbound := testIPv4TCPPacketV1([4]byte{10, 77, 0, 2}, [4]byte{1, 1, 1, 1}, 12345, 443, 0x10, []byte{1, 2})
	if e := cp.Submit(ctx, outbound); e != nil {
		t.Fatal(e)
	}
	dst := make([]byte, 1280)
	tok, n, e := rp.Receive(ctx, dst)
	if e != nil || !bytes.Equal(dst[:n], outbound) {
		t.Fatal("real relay packet delivery", e)
	}
	if r.BoundsV1().PacketsProcessed != 0 {
		t.Fatal("copy committed packet")
	}
	if e = rp.Acknowledge(ctx, tok, n, nil); e != nil {
		t.Fatal(e)
	}
	inbound := testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, [4]byte{10, 77, 0, 2}, 443, 12345, 0x10, []byte{3, 4})
	if e = rp.Submit(ctx, inbound); e != nil {
		t.Fatal(e)
	}
	tok, n, e = cp.Receive(ctx, dst)
	if e != nil || !bytes.Equal(dst[:n], inbound) {
		t.Fatal("real client packet delivery", e)
	}
	if e = cp.Acknowledge(ctx, tok, n, nil); e != nil {
		t.Fatal(e)
	}
}
func TestServicePumpV1CloseDuringBindJoinsBorrowers(t *testing.T) {
	cr, plan, cfg, _ := pumpClientFixtureV1(t)
	p, e := NewClientServicePumpV1(cr, plan, cfg)
	if e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { result <- p.BindV1(context.Background(), [32]byte{1}) }()
	p.Close()
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("bind success after close")
		}
	case <-time.After(time.Second):
		t.Fatal("bind not woken")
	}
	select {
	case <-p.Done():
	case <-time.After(time.Second):
		t.Fatal("borrower not joined")
	}
}
func pumpClientFixtureV1(t testing.TB) (*auth.ProcessHandshakeResultV1, sessionplan.PlanV2, ServicePumpConfigV1, net.Conn) {
	t.Helper()
	plan, program := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	cr, _, _ := duplexResultsV3(t, program)
	port, _ := NewPacketPortV1(1280)
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close(); port.Close() })
	rates, _ := NewProbeRateRegistryV1(1)
	scope, e := NewAuthenticatedProbeScopeV1(envelope.CanonicalProfileV1{ProviderID: "provider.pump", LineageID: "lineage.pump", ProfileID: "profile.pump"})
	if e != nil {
		t.Fatal(e)
	}
	return cr, plan, ServicePumpConfigV1{PacketIO: port, Carrier: a, CarrierOwnedBytes: uint64(unsafe.Sizeof(a)), StreamLimit: 4, ProbeLimit: 2, StreamQueueBytes: 1024, BufferBudget: 64 << 20, MaxRecordBytes: 1 << 20, Generation: 1, AuthorityDeadline: serviceTestNowV1.Add(time.Minute), Now: func() time.Time { return serviceTestNowV1 }, CheckAuthority: func(time.Time) error { return nil }, ProbeScope: scope, ProbeRates: rates}, b
}
func TestServicePumpV1PreRunCloseJoinsOwnedResources(t *testing.T) {
	cr, plan, cfg, peer := pumpClientFixtureV1(t)
	p, e := NewClientServicePumpV1(cr, plan, cfg)
	if e != nil {
		t.Fatal("valid authenticated factory", e)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-p.Done():
	case <-time.After(time.Second):
		t.Fatal("pre-run close did not finalize")
	}
	if _, e = peer.Write([]byte{1}); e == nil {
		t.Fatal("carrier not closed")
	}
	if e = p.Run(context.Background()); e == nil {
		t.Fatal("closed pump ran")
	}
}
func TestServicePumpV1FactoryFailurePreservesSecretAndResources(t *testing.T) {
	cr, plan, cfg, _ := pumpClientFixtureV1(t)
	bad := cfg
	bad.BufferBudget = 1024
	if p, e := NewClientServicePumpV1(cr, plan, bad); e == nil || p != nil {
		t.Fatal("insufficient combined memory accepted")
	}
	if _, ok := cr.ContextSnapshotV1(); !ok {
		t.Fatal("secret/result consumed on failure")
	}
	p, e := NewClientServicePumpV1(cr, plan, cfg)
	if e != nil {
		t.Fatal("retry same result", e)
	}
	p.Close()
	<-p.Done()
}

func TestServicePumpV1Fix1ConstructionReserveBeforePlanValidation(t *testing.T) {
	cr, plan, cfg, _ := pumpClientFixtureV1(t)
	bad := cfg
	bad.BufferBudget = (3 << 20) - 1
	if _, e := NewClientServicePumpV1(cr, sessionplan.PlanV2{}, bad); e != ServiceResourceLimitV1 {
		t.Error("construction budget not checked before Plan work", e)
	}
	p, e := NewClientServicePumpV1(cr, plan, cfg)
	if e != nil {
		t.Fatal("early refusal consumed secret", e)
	}
	p.Close()
	<-p.Done()
}
func TestServicePumpV1Fix1ExactCombinedBudgetReusesRefusedSecret(t *testing.T) {
	plan, _ := pumpPlanPolicyFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1}, func(p *runtimepolicy.PolicyV2) { p.Services.Proxy = nil })
	cr, _, cfg, _ := pumpClientFixtureV1(t)
	cfg.StreamLimit = 0
	cfg.StreamQueueBytes = 0
	p, e := NewClientServicePumpV1(cr, plan, cfg)
	if e != nil {
		t.Fatal(e)
	}
	preparation, err := ServicePreparationBoundsForPlanV1(plan, false)
	if err != nil {
		t.Fatal(err)
	}
	retained := p.BoundsV1().OwnedBytes
	required := retained + preparation.OwnedBytes
	p.Close()
	<-p.Done()
	cr, _, cfg, _ = pumpClientFixtureV1(t)
	cfg.StreamLimit = 0
	cfg.StreamQueueBytes = 0
	cfg.BufferBudget = required - 1
	if _, e = NewClientServicePumpV1(cr, plan, cfg); e != ServiceResourceLimitV1 {
		t.Fatal("budget-minus-one accepted", e)
	}
	cfg.BufferBudget = required
	p, e = NewClientServicePumpV1(cr, plan, cfg)
	if e != nil {
		t.Fatal("exact-budget retry failed", e)
	}
	if p.BoundsV1().OwnedBytes != retained {
		t.Error("exact combined reservation drifted")
	}
	p.Close()
	<-p.Done()
}
func TestServicePumpV1MTUPreflightPreservesSecret(t *testing.T) {
	cr, plan, cfg, _ := pumpClientFixtureV1(t)
	bad := cfg
	bad.MaxRecordBytes = 1000
	if p, e := NewClientServicePumpV1(cr, plan, bad); e == nil || p != nil {
		t.Fatal("record ceiling below MTU admitted")
	}
	p, e := NewClientServicePumpV1(cr, plan, cfg)
	if e != nil {
		t.Fatal("MTU preflight consumed result", e)
	}
	p.Close()
	<-p.Done()
}

func TestServicePumpV1FactoryRejectsAdapterArithmeticOverflow(t *testing.T) {
	cr, plan, cfg, _ := pumpClientFixtureV1(t)
	cfg.PacketOwnedBytes = ^uint64(0)
	cfg.PacketQueuedBytes = ^uint64(0)
	cfg.NetworkOperationBytes = 1
	cfg.RelayNetwork = pumpNoNetworkV1{}
	if p, e := NewRelayServicePumpV1(cr, plan, cfg); e == nil || p != nil {
		if p != nil {
			p.Close()
		}
		t.Fatal("overflowed external owned charge accepted")
	}
	if _, ok := cr.ContextSnapshotV1(); !ok {
		t.Fatal("invalid adapter accounting consumed secret")
	}
}

func TestServicePumpV1RejectsTypedNilOwnedIO(t *testing.T) {
	cr, plan, cfg, _ := pumpClientFixtureV1(t)
	cfg.PacketIO = (*PacketPortV1)(nil)
	if _, e := NewClientServicePumpV1(cr, plan, cfg); e == nil {
		t.Fatal("typed nil packet owner admitted")
	}
}

func TestServicePumpV1FirstTerminalReasonAndRevocationJoin(t *testing.T) {
	c, r, _, _ := pumpPairFixtureV1(t, nil, false)
	pumpStartPairV1(t, c, r)
	c.CancelWithReason(ServiceAuthorityRevokedV1)
	c.Close()
	<-c.Done()
	if e := c.Run(context.Background()); e != ServiceAuthorityRevokedV1 {
		t.Fatal("revocation lost fence", e)
	}
	if b := c.BoundsV1(); b.OwnedBytes != 0 || b.QueuedBytes != 0 || b.QueueUsed != 0 {
		t.Fatal("joined ownership not released", b)
	}
}

func TestServicePumpV1AuthenticatedInvalidServiceStateFailsClosed(t *testing.T) {
	for name, payload := range map[string][]byte{"unknown_id": {1, 4, 0, 0, 0, 99, 0, 0}, "wrong_direction": {1, 2, 0, 0, 0, 1, 0, 2, 0, 0}, "invalid_marker": {2, 0, 0, 0, 0, 0, 0, 0}} {
		t.Run(name, func(t *testing.T) {
			c, r, _, _ := pumpPairFixtureV1(t, nil, false)
			pumpStartPairV1(t, c, r)
			c.mu.Lock()
			i, e := c.reserveV1(context.Background(), c.deadline, false)
			if e == nil {
				c.queueCopyLockedV1(i, payload, 0, 0)
			}
			c.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			select {
			case <-r.Done():
			case <-time.After(time.Second):
				t.Fatal("authenticated invalid service state accepted")
			}
			if e = r.Run(context.Background()); e != ErrServiceRecordV1 {
				t.Fatal("wrong failure category", e)
			}
		})
	}
}
func TestServicePumpV1OwnedCapacityAndPolicyAllowance(t *testing.T) {
	plan, _ := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	goruntime.GC()
	var before, after goruntime.MemStats
	goruntime.ReadMemStats(&before)
	for range 20 {
		if e := sessionplan.ValidateV2At(plan, serviceTestNowV1); e != nil {
			t.Fatal(e)
		}
		policy, e := plan.RuntimePolicyAt(serviceTestNowV1)
		if e != nil {
			t.Fatal(e)
		}
		admission, e := NewServiceAdmissionV1(policy, serviceTestNowV1)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = liveprogram.DecodeV1(policy.LiveProgram); e != nil {
			t.Fatal(e)
		}
		goruntime.KeepAlive(admission)
	}
	goruntime.ReadMemStats(&after)
	per := (after.TotalAlloc - before.TotalAlloc) / 20
	preparation, err := ServicePreparationBoundsForPlanV1(plan, true)
	if err != nil {
		t.Fatal(err)
	}
	if per > preparation.OwnedBytes {
		t.Fatal("policy allowance below observed allocations", per)
	}
	c, r, _, _ := pumpPairFixtureV1(t, nil, false)
	cb, rb := c.BoundsV1(), r.BoundsV1()
	if cb.OwnedBytes > 16<<20 || rb.OwnedBytes > 16<<20 || cb.QueuedBytes > 16<<20 || rb.QueuedBytes > 16<<20 {
		t.Fatal("capacity bound")
	}
	t.Logf("policy validation/projection=%d B/call; client owned=%d queued=%d; relay owned=%d queued=%d; pump=%d ring-slot=%d stream-slot=%d probe-slot=%d packet-port=%d", per, cb.OwnedBytes, cb.QueuedBytes, rb.OwnedBytes, rb.QueuedBytes, unsafe.Sizeof(ServicePumpV1{}), unsafe.Sizeof(serviceQueueSlotV1{}), unsafe.Sizeof(serviceStreamSlotV1{}), unsafe.Sizeof(serviceProbeSlotV1{}), unsafe.Sizeof(PacketPortV1{}))
}

func TestServicePumpV1Fix1MaximumShapePolicyAllocationCorroboration(t *testing.T) {
	plan, program := pumpPlanPolicyFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1}, func(p *runtimepolicy.PolicyV2) {
		p.AllowedProtocols = []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolICMP, runtimepolicy.PayloadProtocolICMPv6, runtimepolicy.PayloadProtocolTCP, runtimepolicy.PayloadProtocolUDP}
		p.Endpoints = make([]runtimepolicy.EndpointV2, 4)
		for i := range p.Endpoints {
			a := netip.MustParseAddr("2606:4700::100").As16()
			a[15] += byte(i)
			p.Endpoints[i] = runtimepolicy.EndpointV2{Family: 6, Address: a[:], Port: 443, Priority: uint8(i)}
		}
		p.Fallback.EndpointIndexes = []uint8{0, 1, 2, 3}
		proxy := p.Services.Proxy
		proxy.DestinationCIDRs = make([]runtimepolicy.PrefixV2, 64)
		for i := range proxy.DestinationCIDRs {
			a := netip.MustParseAddr("2606:4700::100").As16()
			a[15] = byte(i)
			proxy.DestinationCIDRs[i] = runtimepolicy.PrefixV2{Address: a[:], PrefixLen: 128}
		}
		proxy.DestinationPorts = make([]runtimepolicy.PortRangeV1, 16)
		for i := range proxy.DestinationPorts {
			port := uint16(1000 + 2*i)
			proxy.DestinationPorts[i] = runtimepolicy.PortRangeV1{First: port, Last: port}
		}
		probes := p.Services.Probes
		probes.Targets = make([]runtimepolicy.ProbeTargetV1, 16)
		for i := range probes.Targets {
			a := netip.MustParseAddr("2606:4700::100").As16()
			a[15] = byte(i)
			probes.Targets[i] = runtimepolicy.ProbeTargetV1{ID: uint16(i + 1), Address: a[:], Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000}
		}
		prefix := "https://updates.example/"
		p.Services.Update = &runtimepolicy.UpdateV1{URL: prefix + strings.Repeat("a", 2048-len(prefix)), ProfileID: strings.Repeat("a", envelope.MaxCanonicalIDBytes), MaxArtifactBytes: 1024, TimeoutMillis: 1000, MinCheckIntervalSeconds: 60}
		program, e := liveprogram.DecodeV1(p.LiveProgram)
		if e != nil {
			t.Fatal(e)
		}
		// Maximize the accepted encoded program via a field whose grammar is
		// nonempty text, without imposing the endpoint's later projection limit.
		lo, hi := 1, liveprogram.MaxEncodedBytes
		for lo < hi {
			mid := (lo + hi + 1) / 2
			program.SourceSchemaVersion = strings.Repeat("p", mid)
			_, e := liveprogram.EncodeV1(program)
			if e == nil {
				lo = mid
			} else if liveprogram.IsCategory(e, liveprogram.ErrorSize) {
				hi = mid - 1
			} else {
				t.Fatal(e)
			}
		}
		program.SourceSchemaVersion = strings.Repeat("p", lo)
		p.LiveProgram, e = liveprogram.EncodeV1(program)
		if e != nil {
			t.Fatal(e)
		}
		p.LiveProgramSHA256 = sha256.Sum256(p.LiveProgram)
	})
	work := func() {
		if e := sessionplan.ValidateV2At(plan, serviceTestNowV1); e != nil {
			t.Fatal(e)
		}
		policy, e := plan.RuntimePolicyAt(serviceTestNowV1)
		if e != nil {
			t.Fatal(e)
		}
		admission, e := NewServiceAdmissionV1(policy, serviceTestNowV1)
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := liveprogram.DecodeV1(policy.LiveProgram)
		if e != nil {
			t.Fatal(e)
		}
		goruntime.KeepAlive(decoded)
		goruntime.KeepAlive(admission)
		goruntime.KeepAlive(policy)
	}
	work()
	goruntime.GC()
	var before, after goruntime.MemStats
	goruntime.ReadMemStats(&before)
	for range 10 {
		work()
	}
	goruntime.ReadMemStats(&after)
	policy, e := plan.RuntimePolicyAt(serviceTestNowV1)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := runtimepolicy.EncodeRuntimeAt(policy, serviceTestNowV1)
	if e != nil {
		t.Fatal(e)
	}
	for _, size := range []struct {
		name      string
		got, want uintptr
	}{
		{"PolicyV2", unsafe.Sizeof(runtimepolicy.PolicyV2{}), 592}, {"EndpointV2", unsafe.Sizeof(runtimepolicy.EndpointV2{}), 40}, {"PrefixV2", unsafe.Sizeof(runtimepolicy.PrefixV2{}), 32}, {"PortRangeV1", unsafe.Sizeof(runtimepolicy.PortRangeV1{}), 4}, {"ProbeTargetV1", unsafe.Sizeof(runtimepolicy.ProbeTargetV1{}), 96}, {"ServicesV1", unsafe.Sizeof(runtimepolicy.ServicesV1{}), 32}, {"ProxyV1", unsafe.Sizeof(runtimepolicy.ProxyV1{}), 96}, {"ProbesV1", unsafe.Sizeof(runtimepolicy.ProbesV1{}), 40}, {"UpdateV1", unsafe.Sizeof(runtimepolicy.UpdateV1{}), 48}, {"ProgramV1", unsafe.Sizeof(liveprogram.ProgramV1{}), 768}, {"MessageV1", unsafe.Sizeof(liveprogram.MessageV1{}), 64},
	} {
		if size.got != size.want {
			t.Errorf("worksheet target layout %s=%d want %d", size.name, size.got, size.want)
		}
	}
	clone := policy.Clone()
	programClone := program.Clone()
	policyBacking := uint64(unsafe.Sizeof(policy)) + pumpVariableBackingV1(reflect.ValueOf(policy), true)
	cloneBacking := uint64(unsafe.Sizeof(clone)) + pumpVariableBackingV1(reflect.ValueOf(clone), false)
	programBacking := uint64(unsafe.Sizeof(program)) + pumpVariableBackingV1(reflect.ValueOf(program), true)
	programCloneBacking := uint64(unsafe.Sizeof(programClone)) + pumpVariableBackingV1(reflect.ValueOf(programClone), false)
	if policyBacking > 141840 || cloneBacking > 120270 || programBacking > 101240 || programCloneBacking > 3956 {
		t.Fatal("actual typed clone capacity exceeded source worksheet", policyBacking, cloneBacking, programBacking, programCloneBacking)
	}
	t.Logf("actual typed backing including root: C=%d Cm=%d P=%d Pm=%d; clone terms exclude shared strings", policyBacking, cloneBacking, programBacking, programCloneBacking)
	t.Logf("maximal arrays and long accepted text: policy=%d program=%d text=%d endpoints=%d CIDRs=%d ports=%d targets=%d; sequential TotalAlloc=%d B/call, not peak retained capacity", len(encoded), len(policy.LiveProgram), len(program.SourceSchemaVersion), len(policy.Endpoints), len(policy.Services.Proxy.DestinationCIDRs), len(policy.Services.Proxy.DestinationPorts), len(policy.Services.Probes.Targets), (after.TotalAlloc-before.TotalAlloc)/10)
}

// Resource-model corroboration only: count exposed slice capacities and pointed
// objects, not allocator headers, unreachable growth buffers or Go runtime RSS.
func pumpVariableBackingV1(v reflect.Value, stringsOwned bool) uint64 {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return 0
		}
		return uint64(v.Type().Elem().Size()) + pumpVariableBackingV1(v.Elem(), stringsOwned)
	case reflect.Struct:
		var n uint64
		for i := 0; i < v.NumField(); i++ {
			n += pumpVariableBackingV1(v.Field(i), stringsOwned)
		}
		return n
	case reflect.Slice:
		n := uint64(v.Cap()) * uint64(v.Type().Elem().Size())
		for i := 0; i < v.Len(); i++ {
			n += pumpVariableBackingV1(v.Index(i), stringsOwned)
		}
		return n
	case reflect.String:
		if stringsOwned {
			return uint64(v.Len())
		}
	}
	return 0
}

func BenchmarkServicePumpV1MixedPacketAndStream(b *testing.B) {
	listener, network := pumpLocalListenerV1(b)
	c, r, cp, rp := pumpPairFixtureV1(b, network, false)
	pumpStartPairV1(b, c, r)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id, e := c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
	if e != nil {
		b.Fatal(e)
	}
	conn, e := listener.AcceptTCP()
	if e != nil {
		b.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	packet := testIPv4TCPPacketV1([4]byte{10, 77, 0, 2}, [4]byte{1, 1, 1, 1}, 12345, 443, 0x10, make([]byte, 64))
	stream := make([]byte, 1024)
	destination := make([]byte, 1024)
	returnBytes := []byte{1, 2, 3, 4}
	packetOut := make([]byte, 1280)
	returnOut := make([]byte, 1024)
	b.SetBytes(int64(len(packet) + len(stream) + len(returnBytes)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if e = cp.Submit(ctx, packet); e != nil {
			b.Fatal(e)
		}
		token, n, e := rp.Receive(ctx, packetOut)
		if e != nil {
			b.Fatal(e)
		}
		if e = rp.Acknowledge(ctx, token, n, nil); e != nil {
			b.Fatal(e)
		}
		if _, e = c.WriteStream(ctx, id, stream); e != nil {
			b.Fatal(e)
		}
		if _, e = io.ReadFull(conn, destination); e != nil {
			b.Fatal(e)
		}
		if _, e = conn.Write(returnBytes); e != nil {
			b.Fatal(e)
		}
		streamToken, n, e := c.ReceiveStream(ctx, id, returnOut)
		if e != nil {
			b.Fatal(e)
		}
		if e = c.ConfirmStreamDelivery(id, streamToken, n); e != nil {
			b.Fatal(e)
		}
	}
}
