// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/transport/tlstcp"
	"net"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// This fixture states the trusted test owner's scalar attachment reservation.
func productionPreparationFixtureV1(t testing.TB, i *ProductionClientInstallationV1) ProductionClientAttachmentPreparationV1 {
	t.Helper()
	s, err := ServicePreparationBoundsForPlanV1(i.recipe.plan, i.recipe.limits.Mode != ProductionTUNV1)
	if err != nil {
		t.Fatal(err)
	}
	return ProductionClientAttachmentPreparationV1{s.OwnedBytes, s.ProxyAttributedBytes}
}

// The prepared path reuses its one authenticated snapshot and framing codec.
// This narrow source contract complements the real raw/mixed attachment tests:
// adding either reconstruction would invalidate the zero-extra A/F allowance.
func TestProductionRecipeV1PreparedConstructionMultiplicity(t *testing.T) {
	paths := []string{"production_client_recipe_v1.go", "production_raw_packet_pump_v2.go", "service_pump_v1.go", "process_duplex_buffer_v3.go"}
	sources := make(map[string][]byte, len(paths))
	for _, path := range paths {
		var err error
		sources[path], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := productionPreparedConstructionContractV1(sources, "", ""); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ function, call string }{
		{"newProductionClientPumpV1", "ProjectedContextSnapshotV3"},
		{"newProductionClientPumpV1", "NewLiveDataCodecV3"},
		{"newPacketPumpPreparedV1", "ProjectedContextSnapshotV3"},
		{"newPacketPumpPreparedV1", "NewLiveDataCodecV3"},
		{"newPacketPumpPreparedV1", "newDuplexStateMinimumV3"},
		{"constructDuplexV3", "NewLiveDataCodecV3"},
		{"NewProductionClientServicePumpV1", "newDuplexStateMinimumV3"},
		{"NewProductionClientRawPacketPumpV2", "newDuplexStateMinimumV3"},
	} {
		t.Run(mutation.function+"/"+mutation.call, func(t *testing.T) {
			if err := productionPreparedConstructionContractV1(sources, mutation.function, mutation.call); err == nil {
				t.Fatal("in-memory reconstruction mutant escaped contract")
			} else {
				t.Log("rejected in-memory mutant:", err)
			}
		})
	}
}

// Parse only the four local construction sources; mutants add one call in memory
// and never alter production files. Counts include both public attachment paths
// and the shared installed branch, but exclude only explicit installed == nil
// branches. This is deliberately not a general call-graph or allocator proof.
func productionPreparedConstructionContractV1(sources map[string][]byte, mutateFunction, mutateCall string) error {
	want := map[string]map[string]int{
		"NewProductionClientServicePumpV1":   {"newProductionClientPumpV1": 1},
		"NewProductionClientRawPacketPumpV2": {"newProductionClientPumpV1": 1},
		"newProductionClientPumpV1":          {"ProjectedContextSnapshotV3": 1, "NewLiveDataCodecV3": 1, "newPacketPumpPreparedV1": 1},
		"newPacketPumpPreparedV1":            {"constructDuplexV3": 1},
		"constructDuplexV3":                  {},
	}
	tracked := map[string]bool{"ProjectedContextSnapshotV3": true, "ContextSnapshotV1": true, "NewLiveDataCodecV3": true, "newDuplexStateMinimumV3": true, "newDuplexStateV3": true, "newProductionClientPumpV1": true, "newPacketPumpPreparedV1": true, "constructDuplexV3": true}
	seen := make(map[string]bool)
	for path, source := range sources {
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			return err
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			expected, ok := want[function.Name.Name]
			if !ok {
				continue
			}
			seen[function.Name.Name] = true
			if function.Name.Name == mutateFunction {
				function.Body.List = append(function.Body.List, &ast.ExprStmt{X: &ast.CallExpr{Fun: ast.NewIdent(mutateCall)}})
			}
			counts := make(map[string]int)
			var visit func(ast.Node) bool
			visit = func(node ast.Node) bool {
				if branch, ok := node.(*ast.IfStmt); ok && function.Name.Name == "newPacketPumpPreparedV1" {
					if condition, ok := branch.Cond.(*ast.BinaryExpr); ok && condition.Op == token.EQL {
						left, lok := condition.X.(*ast.Ident)
						right, rok := condition.Y.(*ast.Ident)
						if lok && rok && left.Name == "installed" && right.Name == "nil" {
							if branch.Else != nil {
								ast.Inspect(branch.Else, visit)
							}
							return false
						}
					}
				}
				if call, ok := node.(*ast.CallExpr); ok {
					name := ""
					switch callee := call.Fun.(type) {
					case *ast.Ident:
						name = callee.Name
					case *ast.SelectorExpr:
						name = callee.Sel.Name
					}
					if tracked[name] {
						counts[name]++
					}
				}
				return true
			}
			ast.Inspect(function.Body, visit)
			for call := range tracked {
				if counts[call] != expected[call] {
					return fmt.Errorf("%s: %s calls = %d, want %d", function.Name.Name, call, counts[call], expected[call])
				}
			}
		}
	}
	if len(seen) != len(want) {
		return fmt.Errorf("missing prepared construction functions: found %d, want %d", len(seen), len(want))
	}
	return nil
}

func TestProductionClientAttachmentPreparationV1RejectsInsufficientClaim(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		plan, program := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
		n := productionNarrowFixtureV1(plan)
		available := ProductionClientAvailableV1{AggregateBytes: 80 << 20}
		if mixed {
			n.Mode, n.StreamLimit, n.StreamQueueBytes, n.ProxyIdle, n.ProxyCeilingBytes = ProductionTUNProxyV1, 4, 1024, time.Second, 64<<20
			available.ProxyBytes = 64 << 20
		}
		for _, which := range []string{"zero", "owned", "proxy"} {
			if !mixed && which == "proxy" {
				continue
			}
			r, err := PrepareProductionClientServiceV1(plan, n, available, serviceTestNowV1, 1)
			if err != nil {
				t.Fatal(err)
			}
			i, err := r.InstallV1()
			if err != nil {
				t.Fatal(err)
			}
			cr, _, _ := duplexResultsV3(t, program)
			carrier, _ := productionTLSFixtureV1(t, plan.Digest, r.reservation.MaxRecordBytes)
			s, err := ServicePreparationBoundsForPlanV1(plan, mixed)
			if err != nil {
				t.Fatal(err)
			}
			claim := ProductionClientAttachmentPreparationV1{s.OwnedBytes, s.ProxyAttributedBytes}
			if which == "zero" {
				claim = ProductionClientAttachmentPreparationV1{}
			} else if which == "owned" {
				claim.OwnedBytes--
			} else {
				claim.ProxyAttributedBytes--
			}
			p, err := NewProductionClientServicePumpV1(context.Background(), cr, i, carrier, productionAuthorityFixtureV1(t), claim)
			if p != nil || err != ServiceResourceLimitV1 {
				t.Fatal("unfunded attachment accepted", which, err)
			}
			if _, ok := cr.ContextSnapshotV1(); !ok {
				t.Fatal("preflight consumed secret")
			}
			i.Close()
			<-i.Done()
		}
	}
}

func TestProductionClientRecipePreparationSignedProxyShortfallV1(t *testing.T) {
	plan, _ := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	n := productionNarrowFixtureV1(plan)
	n.Mode, n.StreamLimit, n.StreamQueueBytes = ProductionTUNProxyV1, 4, 1024
	n.ProxyIdle, n.ProxyCeilingBytes = 2*time.Second, 16<<20
	r, err := PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20, ProxyBytes: 16 << 20}, serviceTestNowV1, 1)
	if r != nil {
		r.Close()
	}
	if err != ServiceResourceLimitV1 {
		t.Fatal("signed proxy scratch escaped ceiling", err)
	}
}

// This fixture attaches the real recipe to a real TLS connection and a legacy
// relay with local-only socket authority. It changes no production callbacks.
func productionProxyPairFix1V1(t *testing.T, network RelayServiceNetworkV1) (*ServicePumpV1, *ServicePumpV1, *ProductionClientInstallationV1, *atomic.Int64) {
	t.Helper()
	plan, program := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	n := productionNarrowFixtureV1(plan)
	n.Mode, n.StreamLimit, n.StreamQueueBytes = ProductionTUNProxyV1, 4, 1024
	n.SessionIdle, n.FlowIdle, n.ProxyIdle, n.ProxyCeilingBytes = 10*time.Second, 10*time.Second, 2*time.Second, 64<<20
	r, e := PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20, ProxyBytes: 64 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	i, e := r.InstallV1()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { i.Close(); <-i.Done() })
	cr, rr, _ := duplexResultsV3(t, program)
	carrier, peer := productionTLSFixtureV1(t, plan.Digest, uint32(program.Limits.MaxFrameBytes))
	clock := &atomic.Int64{}
	a := productionAuthorityFixtureV1(t)
	a.Now = func() time.Time { return serviceTestNowV1.Add(time.Duration(clock.Load()) * time.Millisecond) }
	c, e := NewProductionClientServicePumpV1(context.Background(), cr, i, carrier, a, productionPreparationFixtureV1(t, i))
	if e != nil {
		t.Fatal(e)
	}
	rp, _ := NewPacketPortV1(int(plan.MTU))
	t.Cleanup(func() { rp.Close() })
	stream, e := peer.SelectRecordStreamV3(context.Background(), plan.IdleTimeout)
	if e != nil {
		t.Fatal(e)
	}
	cfg := ServicePumpConfigV1{PacketIO: rp, Carrier: stream, StreamLimit: 4, ProbeLimit: 2, StreamQueueBytes: 1024, BufferBudget: 64 << 20, MaxRecordBytes: uint32(program.Limits.MaxFrameBytes), Generation: 1, AuthorityDeadline: a.AuthorityDeadline, Now: a.Now, CheckAuthority: a.CheckAuthority, ProbeScope: a.ProbeScope, ProbeRates: a.ProbeRates, RelayNetwork: network, PacketOwnedBytes: uint64(2*plan.MTU) + uint64(unsafe.Sizeof(*rp)) + serviceWorkerReserveV1, PacketQueuedBytes: uint64(2 * plan.MTU), NetworkOperationBytes: 8192, CarrierOwnedBytes: tlstcp.RecordStreamOwnedBytesV3()}
	relay, e := NewRelayServicePumpV1(rr, plan, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { i.Close(); relay.Close(); <-relay.Done() })
	if i.recipe.plan.IdleTimeout != 30*time.Second || c.admission.policy.Services.Proxy.IdleTimeoutSeconds != 30 || c.proxyIdle != 2*time.Second {
		t.Fatal("signed/local idle changed")
	}
	exporter, e := carrier.CarrierBinding()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	bound := make(chan error, 1)
	go func() { bound <- relay.BindV1(ctx, exporter) }()
	if e = c.BindV1(ctx, exporter); e != nil {
		t.Fatal(e)
	}
	if e = <-bound; e != nil {
		t.Fatal(e)
	}
	go c.Run(context.Background())
	go relay.Run(context.Background())
	pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.running })
	return c, relay, i, clock
}

func TestProductionRecipeV1Fix1TombstoneCommitsWithoutActivity(t *testing.T) {
	l, network := pumpLocalListenerV1(t)
	c, relay, installed, clock := productionProxyPairFix1V1(t, network)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	id, e := c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
	if e != nil {
		t.Fatal(e)
	}
	conn, e := l.AcceptTCP()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if e = c.CancelStream(id); e != nil {
		t.Fatal(e)
	}
	pumpWaitUntilV1(t, func() bool { relay.mu.Lock(); defer relay.mu.Unlock(); return relay.streams[0].state == 3 })
	pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.used == 0 })
	s := c.endpoint.(*ProcessClientDuplexEndpointV3).state
	s.mu.Lock()
	before := s.recvCount
	s.mu.Unlock()
	c.mu.Lock()
	initial := c.activity
	c.mu.Unlock()
	clock.Store(1000)
	pumpSendControlV1(t, relay, id, ServiceDataV1, []byte{1})
	pumpWaitUntilV1(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.recvCount == before+1 })
	pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.delivery.deadline.IsZero() })
	c.mu.Lock()
	activity, discarded, terminal := c.activity, c.streams[0].discarded, c.terminal
	c.mu.Unlock()
	if discarded != 1 || terminal {
		t.Fatal("bounded tombstone discard changed")
	}
	if activity != initial {
		t.Fatalf("committed tombstone DATA refreshed session activity by %s", activity.Sub(initial))
	}
	installed.Close()
	<-installed.Done()
}

func TestProductionRecipeV1Fix1WrongHandshakeProgramSameSizesPreservesSecret(t *testing.T) {
	plan, program := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	r, e := PrepareProductionClientServiceV1(plan, productionNarrowFixtureV1(plan), ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	i, e := r.InstallV1()
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	other := program.Clone()
	other.Frame.Compiled.ProfileXORStreamMask ^= 1
	cr, _, _ := duplexResultsV3(t, other)
	projected, e := auth.ProjectProcessResourcesV3(other, "tls13-tcp", auth.ProjectedContextValidationBytesV3)
	if e != nil {
		t.Fatal(e)
	}
	config, e := strictConfigFromSourcesV1(projected.Policy, projected.ConfigSource, projected.Limits)
	if e != nil {
		t.Fatal(e)
	}
	cryptoBytes, e := security.EnvelopeStorageOwnedBytesV3(projected.Policy)
	if e != nil {
		t.Fatal(e)
	}
	codec, e := framing.NewLiveDataCodecV3(other)
	if e != nil {
		t.Fatal(e)
	}
	size, e := sizeDuplexV3(other, codec, config.MaxEnvelopeBytes, cryptoBytes, r.reservation.MaxRecordBytes, uint32(plan.MTU), r.endpoint.bounds.OwnedBytes)
	if e != nil || size != r.endpoint {
		t.Fatal("wrong-program fixture did not preserve numerical sizes", e)
	}
	carrier, _ := productionTLSFixtureV1(t, plan.Digest, r.reservation.MaxRecordBytes)
	pump, e := NewProductionClientServicePumpV1(context.Background(), cr, i, carrier, productionAuthorityFixtureV1(t), productionPreparationFixtureV1(t, i))
	if pump != nil || !errors.Is(e, ErrProfileIncompatible) {
		t.Fatal("wrong handshake program admitted", e)
	}
	if _, ok := cr.ContextSnapshotV1(); !ok {
		t.Fatal("wrong program refusal consumed secret")
	}
	if _, e = carrier.CarrierBinding(); e == nil {
		t.Fatal("wrong program refusal leaked carrier")
	}
	if _, e = i.PacketPortV1(); !errors.Is(e, ServiceInvalidRequestV1) {
		t.Fatal("failed installation reusable", e)
	}
}

func TestProductionRecipeV1Fix1MaximumSimultaneousStreamProbeGeometry(t *testing.T) {
	plan, program := pumpPlanPolicyFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 100}, func(policy *runtimepolicy.PolicyV2) {
		policy.Services.Proxy.MaxConcurrentStreams = 64
		policy.Services.Proxy.MaxQueuedBytesPerDirection = 65536
		policy.Services.Probes.MaxConcurrentOperations = 4
	})
	n := productionNarrowFixtureV1(plan)
	n.Mode, n.StreamLimit, n.ProbeLimit, n.StreamQueueBytes = ProductionTUNProxyV1, 64, 4, 65536
	n.TCPFlows, n.UDPFlows, n.ProxyIdle, n.ProxyCeilingBytes = 4096, 2048, 30*time.Second, 64<<20
	r, e := PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20, ProxyBytes: 64 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	i, e := r.InstallV1()
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	cr, _, _ := duplexResultsV3(t, program)
	carrier, _ := productionTLSFixtureV1(t, plan.Digest, r.reservation.MaxRecordBytes)
	pump, e := NewProductionClientServicePumpV1(context.Background(), cr, i, carrier, productionAuthorityFixtureV1(t), productionPreparationFixtureV1(t, i))
	if e != nil {
		t.Fatal(e)
	}
	if len(pump.streams) != 64 || len(pump.probes) != 4 || len(pump.queue) != 100 || pump.chunk != 16384 || pump.BoundsV1().OwnedBytes != r.reservation.OwnedBytes || pump.BoundsV1().QueuedBytes != r.reservation.QueuedBytes {
		t.Fatal("maximum reservation/actual geometry mismatch")
	}
	pump.mu.Lock()
	e = pump.reserveUsesLockedV1(8 + 3*64 + 3*4)
	excess := pump.reserveUsesLockedV1(1)
	pump.mu.Unlock()
	registered := 0
	if e == nil {
		registered += 8 + 3*64 + 3*4
	}
	if excess == nil {
		registered++
	}
	for j := 0; j < registered; j++ {
		pump.endUseV1()
	}
	if e != nil {
		t.Fatal("maximum user reservation", e)
	}
	if !errors.Is(excess, ServiceResourceLimitV1) {
		t.Fatal("maximum registration overflow", excess)
	}
	t.Logf("S=64 H=4 K=100 U=212: owned=%d queued=%d proxy=%d flow=%d", r.reservation.OwnedBytes, r.reservation.QueuedBytes, r.reservation.ProxyAttributedBytes, r.reservation.FlowOwnedBytes)
	i.Close()
	<-i.Done()
	if pump.BoundsV1().OwnedBytes != 0 {
		t.Fatal("maximum geometry retained after join")
	}
}

func TestProductionRecipeV1Fix1ProxyIdleNeedsDeliveredCommit(t *testing.T) {
	for _, confirm := range []bool{false, true} {
		t.Run(map[bool]string{false: "unconfirmed", true: "committed"}[confirm], func(t *testing.T) {
			l, network := pumpLocalListenerV1(t)
			c, _, installed, clock := productionProxyPairFix1V1(t, network)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			id, e := c.OpenStream(ctx, ProxyRequestV1{1, []byte{1, 1, 1, 1}, 443})
			if e != nil {
				t.Fatal(e)
			}
			conn, e := l.AcceptTCP()
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.used == 0 && c.delivery.id == 0 })
			clock.Store(1000)
			pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.lastNow == serviceTestNowV1.Add(time.Second) })
			for j := 0; j < 4; j++ {
				c.BoundsV1()
				installed.ReservationV1()
				installed.InstalledLimitsV1()
			}
			if _, e = conn.Write([]byte{1}); e != nil {
				t.Fatal(e)
			}
			token, count, e := c.ReceiveStream(ctx, id, make([]byte, 1))
			if e != nil {
				t.Fatal(e)
			}
			c.mu.Lock()
			idle, activity, processed := c.streams[0].idle, c.activity, c.bounds.ServicesProcessed
			c.mu.Unlock()
			if idle != serviceTestNowV1 || activity != serviceTestNowV1 {
				t.Fatal("poll or unconfirmed DATA refreshed idle")
			}
			if confirm {
				s := c.endpoint.(*ProcessClientDuplexEndpointV3).state
				s.mu.Lock()
				var release sync.Once
				t.Cleanup(func() { release.Do(s.mu.Unlock) })
				if e = c.ConfirmStreamDelivery(id, token, count); e != nil {
					t.Fatal(e)
				}
				pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.bounds.ServicesProcessed == processed+1 })
				c.mu.Lock()
				idle, activity = c.streams[0].idle, c.activity
				c.mu.Unlock()
				if idle != serviceTestNowV1 || activity != serviceTestNowV1 {
					t.Fatal("delivery confirmation outran replay Commit")
				}
				clock.Store(1500)
				pumpWaitUntilV1(t, func() bool {
					c.mu.Lock()
					defer c.mu.Unlock()
					return c.lastNow == serviceTestNowV1.Add(1500*time.Millisecond)
				})
				release.Do(s.mu.Unlock)
				pumpWaitUntilV1(t, func() bool {
					c.mu.Lock()
					defer c.mu.Unlock()
					return c.streams[0].idle == serviceTestNowV1.Add(1500*time.Millisecond) && c.activity == c.streams[0].idle
				})
				clock.Store(3499)
				pumpWaitUntilV1(t, func() bool {
					c.mu.Lock()
					defer c.mu.Unlock()
					return c.lastNow == serviceTestNowV1.Add(3499*time.Millisecond)
				})
				select {
				case <-c.Done():
					t.Fatal("proxy expired before refreshed deadline")
				default:
				}
				clock.Store(3500)
			} else {
				clock.Store(2000)
			}
			select {
			case <-c.Done():
			case <-ctx.Done():
				t.Fatal("local proxy idle did not terminate")
			}
			c.mu.Lock()
			reason := c.reason
			c.mu.Unlock()
			if !errors.Is(reason, ServiceTimeoutV1) {
				t.Fatal("proxy idle reason", reason)
			}
			installed.Close()
			<-installed.Done()
			if c.BoundsV1().OwnedBytes != 0 {
				t.Fatal("proxy cancellation did not join")
			}
		})
	}
}

func TestProductionRecipeV1CloseWinsBeforeAttachmentPreparation(t *testing.T) {
	for _, raw := range []bool{false, true} {
		plan, program := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
		prepare := PrepareProductionClientServiceV1
		if raw {
			plan, program = rawPlanFixtureV2(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
			prepare = PrepareProductionClientRawPacketV2
		}
		n := productionNarrowFixtureV1(plan)
		if raw {
			n.ProbeLimit = 0
		}
		r, err := prepare(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
		if err != nil {
			t.Fatal(err)
		}
		i, err := r.InstallV1()
		if err != nil {
			t.Fatal(err)
		}
		claim := productionPreparationFixtureV1(t, i)
		cr, _, _ := duplexResultsV3(t, program)
		carrier, _ := productionTLSFixtureV1(t, plan.Digest, r.reservation.MaxRecordBytes)
		i.Close()
		<-i.Done()
		if raw {
			p, e := NewProductionClientRawPacketPumpV2(context.Background(), cr, i, carrier, productionAuthorityFixtureV1(t), claim)
			err = e
			if p != nil {
				t.Fatal("closed raw installation attached")
			}
		} else {
			p, e := NewProductionClientServicePumpV1(context.Background(), cr, i, carrier, productionAuthorityFixtureV1(t), claim)
			err = e
			if p != nil {
				t.Fatal("closed installation attached")
			}
		}
		if err != ServiceInvalidRequestV1 {
			t.Fatal("close-winner category", err)
		}
		if _, ok := cr.ContextSnapshotV1(); !ok {
			t.Fatal("close-winner consumed secret")
		}
	}
}

func TestProductionRecipeV1ConcurrentAttachmentCloseJoinsBeforeDestroy(t *testing.T) {
	plan, program := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	r, e := PrepareProductionClientServiceV1(plan, productionNarrowFixtureV1(plan), ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	i, e := r.InstallV1()
	if e != nil {
		t.Fatal(e)
	}
	cr, _, _ := duplexResultsV3(t, program)
	carrier, _ := productionTLSFixtureV1(t, plan.Digest, uint32(program.Limits.MaxFrameBytes))
	a := productionAuthorityFixtureV1(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	a.CheckAuthority = func(time.Time) error { once.Do(func() { close(entered); <-release }); return nil }
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); i.Close() })
	type result struct {
		p *ServicePumpV1
		e error
	}
	returned := make(chan result, 1)
	go func() {
		p, e := NewProductionClientServicePumpV1(context.Background(), cr, i, carrier, a, productionPreparationFixtureV1(t, i))
		returned <- result{p, e}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("attachment authority gate")
	}
	closed := make(chan struct{})
	go func() { i.Close(); close(closed) }()
	pumpWaitUntilV1(t, func() bool { i.mu.Lock(); defer i.mu.Unlock(); return i.closing })
	select {
	case <-i.Done():
		t.Fatal("close destroyed borrowed recipe before attachment joined")
	default:
	}
	if _, ok := cr.ContextSnapshotV1(); !ok {
		t.Fatal("blocked pretransfer authority consumed secret")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case got := <-returned:
		if got.e == nil || got.p != nil {
			t.Fatal("closed attachment published pump")
		}
	case <-time.After(time.Second):
		t.Fatal("attachment join")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("installation join")
	}
	if _, ok := cr.ContextSnapshotV1(); !ok {
		t.Fatal("cancelled attachment consumed secret")
	}
}

func TestProductionRecipeV1CloseDuringActualBindJoinsOwnership(t *testing.T) {
	plan, program := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	r, e := PrepareProductionClientServiceV1(plan, productionNarrowFixtureV1(plan), ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
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
	p, e := NewProductionClientServicePumpV1(context.Background(), cr, i, carrier, productionAuthorityFixtureV1(t), productionPreparationFixtureV1(t, i))
	if e != nil {
		t.Fatal(e)
	}
	exporter, e := carrier.CarrierBinding()
	if e != nil {
		t.Fatal(e)
	}
	bound := make(chan error, 1)
	go func() { bound <- p.BindV1(context.Background(), exporter) }()
	pumpWaitUntilV1(t, func() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.binding })
	i.Close()
	select {
	case e = <-bound:
		if e == nil {
			t.Fatal("closed Bind succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Bind did not join")
	}
	<-i.Done()
	if p.BoundsV1().OwnedBytes != 0 {
		t.Fatal("Bind borrower retained ownership")
	}
}

func TestProductionRecipeV1ActualBindRunTrafficAndLocalIdle(t *testing.T) {
	plan, program := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	n := productionNarrowFixtureV1(plan)
	n.SessionIdle = 2 * time.Second
	n.FlowIdle = 2 * time.Second
	r, e := PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	i, e := r.InstallV1()
	if e != nil {
		t.Fatal(e)
	}
	cr, rr, _ := duplexResultsV3(t, program)
	carrier, relayCarrier := productionTLSFixtureV1(t, plan.Digest, uint32(program.Limits.MaxFrameBytes))
	var millis atomic.Int64
	a := productionAuthorityFixtureV1(t)
	a.Now = func() time.Time { return serviceTestNowV1.Add(time.Duration(millis.Load()) * time.Millisecond) }
	c, e := NewProductionClientServicePumpV1(context.Background(), cr, i, carrier, a, productionPreparationFixtureV1(t, i))
	if e != nil {
		t.Fatal(e)
	}
	cp, _ := i.PacketPortV1()
	rp, _ := NewPacketPortV1(int(plan.MTU))
	stream, e := relayCarrier.SelectRecordStreamV3(context.Background(), plan.IdleTimeout)
	if e != nil {
		t.Fatal(e)
	}
	cfg := ServicePumpConfigV1{PacketIO: rp, Carrier: stream, StreamLimit: 4, ProbeLimit: 2, StreamQueueBytes: 1024, BufferBudget: 64 << 20, MaxRecordBytes: uint32(program.Limits.MaxFrameBytes), Generation: 1, AuthorityDeadline: a.AuthorityDeadline, Now: a.Now, CheckAuthority: a.CheckAuthority, ProbeScope: a.ProbeScope, ProbeRates: a.ProbeRates, RelayNetwork: pumpNoNetworkV1{}, PacketOwnedBytes: uint64(2*plan.MTU) + uint64(unsafe.Sizeof(*rp)) + serviceWorkerReserveV1, PacketQueuedBytes: uint64(2 * plan.MTU), NetworkOperationBytes: 8192, CarrierOwnedBytes: tlstcp.RecordStreamOwnedBytesV3()}
	relay, e := NewRelayServicePumpV1(rr, plan, cfg)
	if e != nil {
		i.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { i.Close(); relay.Close(); <-relay.Done() })
	exporter, e := carrier.CarrierBinding()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if e = c.BindV1(ctx, [32]byte{1}); !errors.Is(e, ErrProfileIncompatible) {
		t.Fatal("arbitrary exporter admitted", e)
	}
	bound := make(chan error, 1)
	go func() { bound <- relay.BindV1(ctx, exporter) }()
	if e = c.BindV1(ctx, exporter); e != nil {
		t.Fatal(e)
	}
	if e = <-bound; e != nil {
		t.Fatal(e)
	}
	go c.Run(context.Background())
	go relay.Run(context.Background())
	pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.running })
	out := testIPv4TCPPacketV1(plan.ClientIPv4, [4]byte{1, 1, 1, 1}, 12345, 443, 0x10, []byte{1})
	if e = cp.Submit(ctx, out); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 1280)
	token, count, e := rp.Receive(ctx, buf)
	if e != nil {
		t.Fatal(e)
	}
	if e = rp.Acknowledge(ctx, token, count, nil); e != nil {
		t.Fatal(e)
	}
	pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.used == 0 })
	millis.Store(1000)
	pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.lastNow == serviceTestNowV1.Add(time.Second) })
	in := testIPv4TCPPacketV1([4]byte{1, 1, 1, 1}, plan.ClientIPv4, 443, 12345, 0x10, []byte{2})
	if e = rp.Submit(ctx, in); e != nil {
		t.Fatal(e)
	}
	token, count, e = cp.Receive(ctx, buf)
	if e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	activity := c.activity
	c.mu.Unlock()
	if activity != serviceTestNowV1 {
		t.Fatal("unacknowledged return extended session idle")
	}
	if e = cp.Acknowledge(ctx, token, count, nil); e != nil {
		t.Fatal(e)
	}
	pumpWaitUntilV1(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.activity == serviceTestNowV1.Add(time.Second) })
	millis.Store(3000)
	select {
	case <-c.Done():
	case <-ctx.Done():
		t.Fatal("local idle did not terminate actual running pump")
	}
	c.mu.Lock()
	reason := c.reason
	c.mu.Unlock()
	if !errors.Is(reason, ServiceTimeoutV1) {
		t.Fatal("local idle reason", reason)
	}
	i.Close()
	<-i.Done()
}

func TestProductionRecipeV1ReportsActualLayoutsAndCapacities(t *testing.T) {
	plan, _ := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	n := productionNarrowFixtureV1(plan)
	n.TCPFlows = 4096
	n.UDPFlows = 2048
	r, e := PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	i, e := r.InstallV1()
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	b, _ := i.ReservationV1()
	if b.FlowOwnedBytes != i.admission.flow.ownedBytesV1() {
		t.Fatal("actual flow reservation mismatch")
	}
	t.Logf("pump=%d queue=%d stream=%d probe=%d port=%d flowTable=%d flowEntry=%d flowRef=%d receipt=%d recipe=%d installation=%d admission=%d", unsafe.Sizeof(ServicePumpV1{}), unsafe.Sizeof(serviceQueueSlotV1{}), unsafe.Sizeof(serviceStreamSlotV1{}), unsafe.Sizeof(serviceProbeSlotV1{}), unsafe.Sizeof(PacketPortV1{}), unsafe.Sizeof(productionFlowTableV1{}), unsafe.Sizeof(productionFlowEntryV1{}), unsafe.Sizeof(productionFlowRefV1{}), unsafe.Sizeof(productionReturnReceiptV1{}), unsafe.Sizeof(ProductionClientRecipeV1{}), unsafe.Sizeof(ProductionClientInstallationV1{}), unsafe.Sizeof(productionPacketAdmissionV1{}))
	t.Logf("max-flow recipe: owned=%d queued=%d dormant=%d flow=%d endpoint=%d extra=%d record=%d payload=%d", b.OwnedBytes, b.QueuedBytes, b.DormantOwnedBytes, b.FlowOwnedBytes, r.endpoint.bounds.OwnedBytes, r.extraBytes, b.MaxRecordBytes, b.MaxPayloadBytes)
}

func productionTLSFixtureV1(t *testing.T, digest [32]byte, record uint32) (*tlstcp.Conn, *tlstcp.Conn) {
	t.Helper()
	cc, sc := phase11TLSConfigsV1(t)
	a, b := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type result struct {
		c *tlstcp.Conn
		e error
	}
	done := make(chan result, 1)
	go func() { c, e := tlstcp.Server(ctx, b, sc, digest, record); done <- result{c, e} }()
	c, e := tlstcp.Client(ctx, a, cc, digest, record)
	r := <-done
	if e != nil || r.e != nil {
		a.Close()
		b.Close()
		t.Fatal(e, r.e)
	}
	t.Cleanup(func() { c.Close(); r.c.Close() })
	return c, r.c
}

func productionAuthorityFixtureV1(t *testing.T) ProductionClientAuthorityV1 {
	t.Helper()
	scope, e := NewAuthenticatedProbeScopeV1(envelope.CanonicalProfileV1{ProviderID: "provider.pump", LineageID: "lineage.pump", ProfileID: "profile.pump"})
	if e != nil {
		t.Fatal(e)
	}
	rates, e := NewProbeRateRegistryV1(1)
	if e != nil {
		t.Fatal(e)
	}
	return ProductionClientAuthorityV1{AuthorityDeadline: serviceTestNowV1.Add(time.Minute), Now: func() time.Time { return serviceTestNowV1 }, CheckAuthority: func(time.Time) error { return nil }, ProbeScope: scope, ProbeRates: rates}
}

func TestProductionRecipeV1ActualAttachmentReconcilesBeforeSecret(t *testing.T) {
	for _, scenario := range []string{"wrong-plan-carrier", "wrong-capacity", "expired", "success"} {
		t.Run(scenario, func(t *testing.T) {
			plan, program := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
			n := productionNarrowFixtureV1(plan)
			r, e := PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
			if e != nil {
				t.Fatal(e)
			}
			i, e := r.InstallV1()
			if e != nil {
				t.Fatal(e)
			}
			defer i.Close()
			cr, _, _ := duplexResultsV3(t, program)
			digest := plan.Digest
			record := uint32(program.Limits.MaxFrameBytes)
			if scenario == "wrong-plan-carrier" {
				digest[0] ^= 1
			}
			if scenario == "wrong-capacity" {
				record++
			}
			carrier, _ := productionTLSFixtureV1(t, digest, record)
			a := productionAuthorityFixtureV1(t)
			if scenario == "expired" {
				a.AuthorityDeadline = serviceTestNowV1
			}
			pump, e := NewProductionClientServicePumpV1(context.Background(), cr, i, carrier, a, productionPreparationFixtureV1(t, i))
			if scenario != "success" {
				if e == nil || pump != nil {
					t.Fatal("predictable mismatch accepted")
				}
				if _, ok := cr.ContextSnapshotV1(); !ok {
					t.Fatal("pre-transfer refusal consumed secret")
				}
				if _, e = carrier.CarrierBinding(); e == nil {
					t.Fatal("failed attachment retained carrier")
				}
				if _, e = i.PacketPortV1(); !errors.Is(e, ServiceInvalidRequestV1) {
					t.Fatal("failed installation reusable", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, ok := cr.ContextSnapshotV1(); ok {
				t.Fatal("successful attachment did not consume secret")
			}
			b, _ := i.ReservationV1()
			if pump.BoundsV1().OwnedBytes != b.OwnedBytes || pump.idleTimeout != n.SessionIdle || len(pump.streams) != 0 || pump.production != i.admission {
				t.Fatal("actual installation differs from reservation")
			}
			if pump.ready {
				t.Fatal("attachment claimed Bind readiness")
			}
			i.Close()
			<-i.Done()
			if pump.BoundsV1().OwnedBytes != 0 {
				t.Fatal("joined owner retained storage")
			}
		})
	}
}

func productionNarrowFixtureV1(plan sessionplan.PlanV2) ProductionClientNarrowingV1 {
	return ProductionClientNarrowingV1{Mode: ProductionTUNV1, SessionIdle: min(30*time.Second, plan.IdleTimeout), FlowIdle: min(30*time.Second, plan.IdleTimeout), TCPFlows: 16, UDPFlows: 0, ProbeLimit: 2, AggregateCeilingBytes: 80 << 20}
}

func TestProductionRecipeV1LegacyFactoryCannotConsumeInstalledPort(t *testing.T) {
	cr, plan, cfg, _ := pumpClientFixtureV1(t)
	r, e := PrepareProductionClientServiceV1(plan, productionNarrowFixtureV1(plan), ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	i, e := r.InstallV1()
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	cfg.PacketIO, _ = i.PacketPortV1()
	p, e := NewClientServicePumpV1(cr, plan, cfg)
	if p != nil {
		p.Close()
		<-p.Done()
	}
	if !errors.Is(e, ServiceInvalidRequestV1) {
		t.Fatal("legacy factory accepted installed consumer", e)
	}
	if _, ok := cr.ContextSnapshotV1(); !ok {
		t.Fatal("alternate constructor consumed result")
	}
}

func TestProductionRecipeV1PreparesDormantExactReservationAndSingleUse(t *testing.T) {
	var zeroRecipe ProductionClientRecipeV1
	var zeroInstall ProductionClientInstallationV1
	if _, e := zeroRecipe.InstallV1(); !errors.Is(e, ServiceInvalidRequestV1) {
		t.Fatal("zero recipe", e)
	}
	if _, e := zeroInstall.PacketPortV1(); !errors.Is(e, ServiceInvalidRequestV1) || zeroInstall.Done() != nil {
		t.Fatal("zero installation", e)
	}
	plan, _ := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	n := productionNarrowFixtureV1(plan)
	r, e := PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	b, e := r.ReservationV1()
	if e != nil || b.OwnedBytes == 0 || b.FlowOwnedBytes == 0 || b.ProxyAttributedBytes != 0 || b.StreamChunkBytes != 0 {
		t.Fatal("reservation", b, e)
	}
	if _, e = PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: b.OwnedBytes - 1}, serviceTestNowV1, 2); !errors.Is(e, ServiceResourceLimitV1) {
		t.Fatal("one-under aggregate", e)
	}
	facts, _ := plan.ConstructionFactsV2()
	calculation, _ := sessionplan.AdmittedCalculationBoundsV2(facts.ProfileBytes)
	construction := max(calculation.SuffixBytes, calculation.DecoderBytes+calculation.PolicyBytes+calculation.ProgramBytes+calculation.PlanBytes+calculation.SelectionBytes) + serviceAdmissionMaximumBytesV1()
	exact, e := PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: max(b.OwnedBytes, construction)}, serviceTestNowV1, 2)
	if e != nil {
		t.Fatal("exact aggregate", e)
	}
	exact.Close()
	// Deliberately exercise the invalid copied handle without invoking any copied mutex.
	var copied ProductionClientRecipeV1
	reflect.ValueOf(&copied).Elem().Set(reflect.ValueOf(r).Elem())
	if _, e = copied.InstallV1(); !errors.Is(e, ServiceInvalidRequestV1) {
		t.Fatal("copied recipe", e)
	}
	plan.Destroy()
	i, e := r.InstallV1()
	if e != nil {
		t.Fatal("borrowed caller mutation", e)
	}
	t.Cleanup(func() { i.Close(); <-i.Done() })
	var copiedInstall ProductionClientInstallationV1
	reflect.ValueOf(&copiedInstall).Elem().Set(reflect.ValueOf(i).Elem())
	if _, e = copiedInstall.PacketPortV1(); !errors.Is(e, ServiceInvalidRequestV1) || copiedInstall.Done() != nil {
		t.Fatal("copied installation", e)
	}
	if _, e = r.InstallV1(); !errors.Is(e, ServiceInvalidRequestV1) {
		t.Fatal("recipe reused", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal("nonowning close", e)
	}
	limits, e := i.InstalledLimitsV1()
	if e != nil || limits != n {
		t.Fatal("installed limits", e)
	}
	port, e := i.PacketPortV1()
	if e != nil {
		t.Fatal(e)
	}
	if e = port.Submit(context.Background(), productionTCPPacketV1(1)); !errors.Is(e, ServiceInvalidRequestV1) {
		t.Fatal("dormant byte admission", e)
	}
	i.Close()
	<-i.Done()
	if _, e = i.PacketPortV1(); !errors.Is(e, ServiceInvalidRequestV1) {
		t.Fatal("closed installation", e)
	}
}

func TestProductionRecipeV1DecoderWorkspacePrecedesValidationAndIsNotLifetimeCredit(t *testing.T) {
	calculation, ok := sessionplan.AdmittedCalculationBoundsV2(envelope.MaxPayloadBytes)
	if !ok {
		t.Fatal("bounds")
	}
	workspace := max(calculation.SuffixBytes, calculation.DecoderBytes+calculation.PolicyBytes+calculation.ProgramBytes+calculation.PlanBytes+calculation.SelectionBytes)
	if recipe, err := PrepareProductionClientServiceV1(sessionplan.PlanV2{}, ProductionClientNarrowingV1{}, ProductionClientAvailableV1{AggregateBytes: workspace - 1}, serviceTestNowV1, 1); recipe != nil || !errors.Is(err, ServiceResourceLimitV1) {
		t.Fatal("decoder before budget", err)
	}
	plan, _ := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	defer plan.Destroy()
	recipe, err := PrepareProductionClientServiceV1(plan, productionNarrowFixtureV1(plan), ProductionClientAvailableV1{AggregateBytes: workspace}, serviceTestNowV1, 1)
	if err != nil {
		t.Fatal("exact construction workspace", err)
	}
	defer recipe.Close()
	reservation, err := recipe.ReservationV1()
	if err != nil || reservation.OwnedBytes >= workspace {
		t.Fatal("recipe lifetime must be independently smaller", reservation, err)
	}
}

func TestProductionRecipeV1IndependentProxyCeilingAndMode(t *testing.T) {
	plan, _ := pumpPlanFixtureV1(t, sessionplan.NarrowingRequestV2{MaxQueuePackets: 1})
	n := productionNarrowFixtureV1(plan)
	n.Mode = ProductionTUNProxyV1
	n.StreamLimit = 4
	n.StreamQueueBytes = 1024
	n.ProxyIdle = 30 * time.Second
	n.ProxyCeilingBytes = 64 << 20
	r, e := PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20, ProxyBytes: 64 << 20}, serviceTestNowV1, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	b, _ := r.ReservationV1()
	if b.ProxyAttributedBytes == 0 || b.ProxyAttributedBytes >= b.OwnedBytes {
		t.Fatal("shared/disjoint attribution", b)
	}
	if _, e = PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20, ProxyBytes: b.ProxyAttributedBytes - 1}, serviceTestNowV1, 2); !errors.Is(e, ServiceResourceLimitV1) {
		t.Fatal("proxy one-under", e)
	}
	facts, _ := plan.ConstructionFactsV2()
	calculation, _ := sessionplan.AdmittedCalculationBoundsV2(facts.ProfileBytes)
	construction := max(calculation.SuffixBytes, calculation.DecoderBytes+calculation.PolicyBytes+calculation.ProgramBytes+calculation.PlanBytes+calculation.SelectionBytes) + serviceAdmissionMaximumBytesV1()
	exact, e := PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: max(b.OwnedBytes, construction), ProxyBytes: max(b.ProxyAttributedBytes, construction)}, serviceTestNowV1, 2)
	if e != nil {
		t.Fatal("independent exact caps", e)
	}
	exact.Close()
	n.Mode = ProductionProxyOnlyV1
	n.TCPFlows = 0
	n.UDPFlows = 0
	n.FlowIdle = 0
	proxy, e := PrepareProductionClientServiceV1(plan, n, ProductionClientAvailableV1{AggregateBytes: 80 << 20, ProxyBytes: 64 << 20}, serviceTestNowV1, 3)
	if e != nil {
		t.Fatal(e)
	}
	defer proxy.Close()
	i, e := proxy.InstallV1()
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	p, e := i.PacketPortV1()
	if e != nil {
		t.Fatal(e)
	}
	if p.production.flow != nil || p.production.raw || cap(p.inbound)+cap(p.outbound) != 2*int(plan.MTU) {
		t.Fatal("proxy-only installed raw storage")
	}
	b, _ = i.ReservationV1()
	if b.FlowOwnedBytes != 0 {
		t.Fatal("proxy-only charged nonexistent flow")
	}
}
