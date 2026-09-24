// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
	runtimeengine "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"kurdistan/internal/transport/tlstcp"
	"math"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestProductionAttemptV1OverlappingClockSamplesDoNotExpireAuthority(t *testing.T) {
	f, _ := productionTLSCurrentFixtureV1(t, false)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	o := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
	use, status := o.parent.beginUseV1(202, productionBudgetChargeV1{})
	if status != 0 {
		t.Fatal(status)
	}
	a, status := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
	if status != 0 {
		t.Fatal(status)
	}
	b, status := a.BorrowV1()
	if status != 0 {
		t.Fatal(status)
	}
	t.Cleanup(func() { b.Close(); o.resources.destroyV1(); o.parent.finishUseV1(use) })
	clock := &productionTestClockV1{at: f.now}
	o.now = clock.now
	// A pump has sampled time; another admitted operation completes before
	// the pump validates that sample. This is not a backwards clock change.
	earlier := clock.now()
	later := earlier.Add(time.Millisecond)
	clock.set(later)
	if status := o.acceptTimeV1(use); status != 0 {
		t.Fatal(status)
	}
	if err := b.nativeAuthorityV1(earlier); err != nil {
		t.Fatal("overlapping valid sample cancelled authority", err)
	}
	if !o.lastNow.Equal(later) {
		t.Fatal("accepted time moved backwards")
	}
	// A genuine rollback of the trusted clock still fails closed.
	clock.set(earlier)
	if _, err := b.acceptNativeTimeV1(time.Time{}, false); err != runtimeengine.ServiceAuthorityExpiredV1 {
		t.Fatal("actual clock rollback accepted", err)
	}
}

func TestProductionAttemptV1AttachmentRetirementTypedNilAndErrorPrecedence(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, original := range []error{nil, runtimeengine.ServiceCancelledV1} {
			for _, stale := range []bool{false, true} {
				ledger, status := newProductionBudgetV1(80 << 20)
				if status != 0 {
					t.Fatal(status)
				}
				before := ledger.owned
				ticket, status := ledger.reserveV1(productionBudgetChargeV1{owned: 64})
				if status != 0 {
					t.Fatal(status)
				}
				r := &productionResourcesV1{attachmentScratchBytes: 64, attachmentScratchSerial: ticket.serial}
				b := &ProductionAttemptBorrowV1{admission: &ProductionAttemptAdmissionV1{resources: r, owner: &productionAdmissionV1{parent: &productionParentV1{budget: ledger}}}}
				arg := ticket
				if stale {
					arg.serial++
				}
				err := original
				if raw {
					var pump *runtimeengine.RawPacketPumpV2
					finishProductionAttachmentV1(b, arg, &pump, &err)
				} else {
					var pump *runtimeengine.ServicePumpV1
					finishProductionAttachmentV1(b, arg, &pump, &err)
				}
				want := original
				if stale && want == nil {
					want = runtimeengine.ServiceInvalidRequestV1
				}
				if err != want {
					t.Fatal("retirement replaced original error", raw, stale, err, want)
				}
				if stale {
					if ledger.owned != before+64 || r.attachmentScratchBytes != 64 {
						t.Fatal("stale release retired a live ticket")
					}
					if err := b.releaseAttachmentPreparationV1(ticket); err != nil {
						t.Fatal(err)
					}
				}
				if ledger.owned != before || r.attachmentScratchBytes != 0 {
					t.Fatal("valid retirement leaked scratch")
				}
			}
		}
	}
}

func TestProductionAttemptV1AttachmentScratchActualLedger(t *testing.T) {
	for _, raw := range []bool{false, true} {
		f, _ := productionTLSCurrentFixtureV1(t, raw)
		rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
		o := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
		use, s := o.parent.beginUseV1(202, productionBudgetChargeV1{})
		if s != 0 {
			t.Fatal(s)
		}
		a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
		if s != 0 {
			t.Fatal(s)
		}
		b, s := a.BorrowV1()
		if s != 0 {
			t.Fatal(s)
		}
		t.Cleanup(func() { b.Close(); o.resources.destroyV1(); o.parent.finishUseV1(use) })
		if s := b.beginV1(false, false); s != 0 {
			t.Fatal(s)
		}
		defer b.endV1()
		minimum, err := runtimeengine.ServicePreparationBoundsForPlanV1(o.plan, false)
		if err != nil {
			t.Fatal(err)
		}
		ledger := o.parent.budget
		ledger.mu.Lock()
		before, queued, capacity := ledger.owned, ledger.queued, ledger.cap
		ledger.cap = before + minimum.OwnedBytes - 1
		ledger.mu.Unlock()
		if _, _, err := b.reserveAttachmentPreparationV1(); err != runtimeengine.ServiceResourceLimitV1 {
			t.Fatal("recipe alone was mistaken for attachment capacity", err)
		}
		ledger.mu.Lock()
		ledger.cap++
		ledger.mu.Unlock()
		claim, ticket, err := b.reserveAttachmentPreparationV1()
		if err != nil || claim.OwnedBytes != minimum.OwnedBytes || claim.ProxyAttributedBytes != 0 {
			t.Fatal("exact residual refused", err)
		}
		ledger.mu.Lock()
		ownedNow, queuedNow := ledger.owned, ledger.queued
		ledger.mu.Unlock()
		if ownedNow != before+minimum.OwnedBytes || queuedNow != queued {
			t.Fatal("scratch is not additional or was charged as queued payload")
		}
		if _, _, err := b.reserveAttachmentPreparationV1(); err == nil {
			t.Fatal("duplicate scratch owner")
		}
		if err := b.releaseAttachmentPreparationV1(ticket); err != nil {
			t.Fatal(err)
		}
		ledger.mu.Lock()
		if ledger.owned != before || ledger.queued != queued {
			t.Error("scratch ticket leaked")
		}
		ledger.cap = capacity
		ledger.mu.Unlock()
	}
}

func productionProxyAdmissionForPreparationV1(t *testing.T) *productionAdmissionV1 {
	t.Helper()
	f, _ := productionTLSCurrentFixtureV1(t, false, true)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	ticket, _ := reserveProductionSlotV1(&HandleRegistry{})
	p, _ := newProductionParentV1(ticket, 80<<20, time.Time{})
	opening, _ := p.beginUseV1(0, productionBudgetChargeV1{})
	settings := projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false))
	settings.tunnelMode = 2
	o, status := newProductionAdmissionV1(p, opening, f.current, settings, &productionRealCurrentV1{}, &productionSnapshotPlatformV1{snapshot: f.current}, func() time.Time { return f.now }, time.Now, rates, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 80 << 20, MaxArtifactBytes: 1 << 20, MaxPublicationBytes: 1 << 20})
	p.finishUseV1(opening)
	if status != 0 {
		t.Fatal(status)
	}
	t.Cleanup(func() { o.closeV1(context.Background()) })
	return o
}

func TestProductionAttemptV1ProxyPreparationResidual(t *testing.T) {
	o := productionProxyAdmissionForPreparationV1(t)
	use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
	a, status := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
	if status != 0 {
		t.Fatal(status)
	}
	b, status := a.BorrowV1()
	if status != 0 {
		t.Fatal(status)
	}
	t.Cleanup(func() { b.Close(); o.resources.destroyV1(); o.parent.finishUseV1(use) })
	if status := b.beginV1(false, false); status != 0 {
		t.Fatal(status)
	}
	defer b.endV1()
	r := o.resources
	reservation, err := r.installation.ReservationV1()
	if err != nil {
		t.Fatal(err)
	}
	if r.proxyRetainedBytes != productionResourcesHolderBytesV1()+reservation.ProxyAttributedBytes || r.proxyCeilingBytes != 32<<20 {
		t.Fatal("trusted recipe/holder subtotal not retained")
	}
	minimum, err := runtimeengine.ServicePreparationBoundsForPlanV1(o.plan, true)
	if err != nil {
		t.Fatal(err)
	}
	ceiling := r.proxyCeilingBytes
	r.proxyCeilingBytes = r.proxyRetainedBytes + productionAttemptHolderBytesV1() + minimum.ProxyAttributedBytes - 1
	if _, _, err := b.reserveAttachmentPreparationV1(); err != runtimeengine.ServiceResourceLimitV1 {
		t.Fatal("proxy one-under accepted", err)
	}
	r.proxyCeilingBytes++
	claim, ticket, err := b.reserveAttachmentPreparationV1()
	if err != nil || claim.ProxyAttributedBytes != minimum.OwnedBytes {
		t.Fatal("proxy exact residual refused", err)
	}
	if err := b.releaseAttachmentPreparationV1(ticket); err != nil {
		t.Fatal(err)
	}
	if err := b.releaseAttachmentPreparationV1(ticket); err == nil {
		t.Fatal("stale scratch release")
	}
	r.proxyCeilingBytes = ceiling
}

func TestProductionAttemptV1PostConstructionCancellationRetiresScratch(t *testing.T) {
	for _, raw := range []bool{false, true} {
		f, snapshot := productionTLSCurrentFixtureV1(t, raw)
		rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
		o := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
		use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
		a, status := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
		if status != 0 {
			t.Fatal(status)
		}
		b, status := a.BorrowV1()
		if status != 0 {
			t.Fatal(status)
		}
		t.Cleanup(func() { b.Close(); o.resources.destroyV1(); o.parent.finishUseV1(use) })
		result, carrier := productionActualHandshakeV1(t, b, snapshot)
		if _, status := b.RevalidateV1(context.Background()); status != 0 {
			t.Fatal(status)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		before, queued := o.parent.budget.owned, o.parent.budget.queued
		var calls atomic.Int32
		o.now = func() time.Time {
			if calls.Add(1) == 3 {
				cancel()
			}
			return f.now
		}
		var err error
		if raw {
			p, e := b.AttachRawV2(ctx, result, carrier)
			err = e
			if p != nil {
				t.Fatal("cancelled raw pump escaped")
			}
		} else {
			p, e := b.AttachServiceV1(ctx, result, carrier)
			err = e
			if p != nil {
				t.Fatal("cancelled service pump escaped")
			}
		}
		if err != runtimeengine.ServiceCancelledV1 {
			t.Fatal("post-construction cancellation lost", err, calls.Load())
		}
		if _, ok := result.ContextSnapshotV1(); ok {
			t.Fatal("fixture did not reach actual endpoint secret transfer")
		}
		if o.parent.budget.owned != before || o.parent.budget.queued != queued || o.resources.attachmentScratchBytes != 0 {
			t.Fatal("scratch leaked after refused endpoint cleanup")
		}
		select {
		case <-o.resources.installation.Done():
		default:
			t.Fatal("refused installed graph not joined")
		}
	}
}

func TestProductionAttemptV1HolderProxyPreflight(t *testing.T) {
	o := productionProxyAdmissionForPreparationV1(t)
	use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
	t.Cleanup(func() { o.resources.destroyV1(); o.parent.finishUseV1(use) })
	r := o.resources
	ceiling := r.proxyCeilingBytes
	r.proxyCeilingBytes = r.proxyRetainedBytes + productionAttemptHolderBytesV1() - 1
	before := o.parent.budget.owned
	if a, status := newProductionAttemptAdmissionV1(o, r, 0, use); a != nil || status != 5 || o.attempt != nil || o.parent.budget.owned != before {
		t.Fatal("attempt holder allocated before proxy reservation", status)
	}
	r.proxyCeilingBytes++
	a, status := newProductionAttemptAdmissionV1(o, r, 0, use)
	if status != 0 || a == nil || o.parent.budget.owned != before+productionAttemptHolderBytesV1() {
		t.Fatal("exact holder capacity refused", status)
	}
	r.proxyCeilingBytes = ceiling
}

func TestProductionAttemptV1TransportProxyPreflight(t *testing.T) {
	o := productionProxyAdmissionForPreparationV1(t)
	use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
	a, status := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
	if status != 0 {
		t.Fatal(status)
	}
	t.Cleanup(func() {
		if a.borrow != nil {
			a.borrow.Close()
		}
		o.resources.destroyV1()
		o.parent.finishUseV1(use)
	})
	factory := &productionReservationFixtureV1{requirement: 12345, proxy: 12345}
	o.resources.proxyCeilingBytes = o.resources.proxyRetainedBytes + productionAttemptHolderBytesV1() + 12344
	before, queued := o.parent.budget.owned, o.parent.budget.queued
	if _, status := a.PrepareV1(context.Background(), factory); status != 5 || factory.prepares != 0 {
		t.Fatal("proxy overflow reached transport factory", status, factory.prepares)
	}
	if o.parent.budget.owned != before || o.parent.budget.queued != queued || a.transportTicket.serial != 0 || a.transportProxyBytes != 0 {
		t.Fatal("refused transport leaked capacity")
	}
}

func TestProductionAttemptV1ZeroAndDedicatedUse(t *testing.T) {
	var a ProductionAttemptAdmissionV1
	if b, s := a.BorrowV1(); b != nil || s != 3 {
		t.Fatal("zero admission", s)
	}
	var b ProductionAttemptBorrowV1
	if b.Close() == nil {
		t.Fatal("zero borrow close")
	}
	p := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	use, s := p.beginUseV1(202, productionBudgetChargeV1{owned: 64})
	if s != 0 {
		t.Fatal("dedicated attempt slot", s)
	}
	if _, s = p.beginUseV1(203, productionBudgetChargeV1{}); s != 2 {
		t.Fatal("out of range slot", s)
	}
	if _, s = p.nextAttemptV1(); s != 3 {
		t.Fatal("advanced while attempt live", s)
	}
	if s = p.finishUseV1(use); s != 0 {
		t.Fatal(s)
	}
	if _, s = p.nextAttemptV1(); s != 0 {
		t.Fatal(s)
	}
}

type productionReservationFixtureV1 struct {
	requirement uint64
	proxy       uint64
	prepares    int
}

func (f *productionReservationFixtureV1) ReservationV1(b *ProductionAttemptBorrowV1) (ProductionAttemptReservationV1, int32) {
	if !b.validV1() {
		return ProductionAttemptReservationV1{}, 3
	}
	return ProductionAttemptReservationV1{OwnedBytes: f.requirement, ProxyAttributedBytes: f.proxy}, 0
}
func (f *productionReservationFixtureV1) PrepareV1(b *ProductionAttemptBorrowV1) (ProductionAttemptTransportV1, int32) {
	f.prepares++
	return nil, 25
}

func TestProductionAttemptV1ReservationBeforePrepare(t *testing.T) {
	for _, under := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "one-under"}[under], func(t *testing.T) {
			f, _ := productionTLSCurrentFixtureV1(t, true)
			o := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, nil)
			use, s := o.parent.beginUseV1(202, productionBudgetChargeV1{})
			if s != 0 {
				t.Fatal(s)
			}
			a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
			if s != 0 {
				t.Fatal(s)
			}
			t.Cleanup(func() {
				if a.borrow != nil {
					a.borrow.Close()
				}
				o.resources.destroyV1()
				o.parent.finishUseV1(use)
			})
			factory := &productionReservationFixtureV1{requirement: 12345}
			ledger := o.parent.budget
			ledger.mu.Lock()
			ledger.cap = ledger.owned + factory.requirement
			if under {
				ledger.cap--
			}
			ledger.mu.Unlock()
			transport, s := a.PrepareV1(context.Background(), factory)
			want := int32(25)
			calls := 1
			if under {
				want = 5
				calls = 0
			}
			if transport != nil || s != want || factory.prepares != calls {
				t.Fatalf("prepare %v %d %d", transport, s, factory.prepares)
			}
			if _, s := a.PrepareV1(context.Background(), factory); s != 3 {
				t.Fatalf("repeat: %d", s)
			}
			copy := *a
			if _, s := copy.PrepareV1(context.Background(), factory); s != 3 {
				t.Fatalf("copy: %d", s)
			}
		})
	}
	var zero ProductionAttemptAdmissionV1
	if _, s := zero.PrepareV1(context.Background(), &productionReservationFixtureV1{}); s != 3 {
		t.Fatal(s)
	}
}

func productionTLSCurrentFixtureV1(t *testing.T, raw bool, proxy ...bool) (maintenanceSignedFixture, *selfhost.RelayRuntimeSnapshotV1) {
	t.Helper()
	base := t.TempDir()
	dir, recovery := filepath.Join(base, "node"), filepath.Join(base, "recovery")
	now := time.Unix(1780000062, 0).UTC()
	pass := []byte("private local admission fixture recovery")
	if _, e := selfhost.Initialize(selfhost.InitOptions{DataDir: dir, DeploymentName: "production-admission-fixture", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: pass, Now: now.Add(-2 * time.Minute)}); e != nil {
		t.Fatal(e)
	}
	if e := selfhost.ConfirmRecovery(dir, recovery, pass, now.Add(-time.Minute)); e != nil {
		t.Fatal(e)
	}
	model, e := compiler.Generate(71)
	if e != nil {
		t.Fatal(e)
	}
	features := ir.SecurityCapabilities()
	program, e := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: model, ClientMandatoryFeatures: features[:2], RelayMandatoryFeatures: features[:2], SelectedFeatures: features})
	if e != nil {
		t.Fatal(e)
	}
	wire, e := liveprogram.EncodeV1(program)
	if e != nil {
		t.Fatal(e)
	}
	request, private, e := enrollment.Generate(now, 24*time.Hour, rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	requestWire, e := enrollment.EncodeRequestV1(request)
	if e != nil {
		t.Fatal(e)
	}
	privateWire, e := enrollment.EncodePrivateBundleV1(private)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(privateWire); clear(private.RecipientPrivate); clear(private.ClientAuthSeed) })
	var services *runtimepolicy.ServicesV1
	if !raw {
		services = &runtimepolicy.ServicesV1{Version: 1, Probes: &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 1, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000}}, MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 10, MaxOperationMillis: 30000}}
		if len(proxy) == 1 && proxy[0] {
			services.Proxy = &runtimepolicy.ProxyV1{AddressKinds: []uint8{1}, DestinationCIDRs: []runtimepolicy.PrefixV2{{Address: []byte{8, 8, 8, 8}, PrefixLen: 32}}, DestinationPorts: []runtimepolicy.PortRangeV1{{First: 443, Last: 443}}, MaxConcurrentStreams: 4, MaxBufferBytes: 64 << 20, ConnectTimeoutMillis: 1000, IdleTimeoutSeconds: 30, MaxQueuedBytesPerDirection: 32768}
		}
	}
	issued, e := selfhost.CreateProfile(dir, selfhost.CreateProfileOptions{Name: "admitted-device", ValidFor: 12 * time.Hour, Now: now, RecipientRequest: requestWire, LiveProgram: wire, RegistryDir: filepath.Join(base, "registry"), Services: services})
	if e != nil {
		t.Fatal(e)
	}
	activation, e := selfhost.NewAndroidLiveActivationSessionForRecipient(issued.Artifact, now, lifecycle.VerifiedState{}, request, private)
	if e != nil {
		t.Fatal(e)
	}
	defer activation.Destroy()
	var staged profile.ActivationRecord
	for {
		command, ok := activation.Next()
		if !ok {
			break
		}
		result := profile.ActivationCommandResult{}
		if command.Kind == profile.ActivationCommandStageCandidate {
			staged = command.Record
		}
		if command.Kind == profile.ActivationCommandReopenCandidate {
			result.Record = staged
		}
		if e = activation.Submit(command, result); e != nil {
			t.Fatal(e)
		}
	}
	record, e := activation.Result()
	if e != nil {
		t.Fatal(e)
	}
	recordWire, e := EncodeActivationRecord(record)
	if e != nil {
		t.Fatal(e)
	}
	verifyWire, e := EncodeVerifyRequest(VerifyRequest{Ingress: envelope.IngressFile, Class: envelope.ArtifactDeviceRecipient, Parts: [][]byte{issued.Artifact}})
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := selfhost.OpenRelayRuntimeSnapshotV1(dir, now.Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(snapshot.Close)
	return maintenanceSignedFixture{now: now.Add(time.Minute), current: MaintenanceCurrentInputV1{verifyWire, recordWire, requestWire, privateWire}, artifact: issued.Artifact, record: record}, snapshot
}

func productionActualHandshakeV1(t *testing.T, b *ProductionAttemptBorrowV1, snapshot *selfhost.RelayRuntimeSnapshotV1, continuation ...func(*auth.ProcessHandshakeResultV1, sessionplan.PlanV2, liveprogram.ProgramV1, *tlstcp.Conn) error) (*auth.ProcessHandshakeResultV1, *tlstcp.Conn) {
	t.Helper()
	if _, s := b.RevalidateV1(context.Background()); s != 0 {
		t.Fatal(s)
	}
	var cr *auth.ProcessHandshakeResultV1
	var carrier *tlstcp.Conn
	err := b.WithInputsV1(func(plan sessionplan.PlanV2, policy runtimepolicy.PolicyV2, program liveprogram.ProgramV1, seed []byte, _ uint8, now time.Time) error {
		server, e := snapshot.ServerTLSConfigV1()
		if e != nil {
			return e
		}
		defer func() {
			for i := range server.Certificates {
				if key, ok := server.Certificates[i].PrivateKey.(ed25519.PrivateKey); ok {
					clear(key)
				}
			}
		}()
		leaf, e := x509.ParseCertificate(policy.TLSLeafDER)
		if e != nil {
			return e
		}
		roots := x509.NewCertPool()
		roots.AddCert(leaf)
		client := &tls.Config{ServerName: policy.TLSServerName, RootCAs: roots, Time: func() time.Time { return now }}
		left, right := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		type tlsResult struct {
			c *tlstcp.Conn
			e error
		}
		done := make(chan tlsResult, 1)
		go func() {
			c, e := tlstcp.Server(ctx, right, server, plan.Digest, uint32(program.Limits.MaxFrameBytes))
			done <- tlsResult{c, e}
		}()
		carrier, e = tlstcp.Client(ctx, left, client, plan.Digest, uint32(program.Limits.MaxFrameBytes))
		relay := <-done
		if e != nil || relay.e != nil {
			left.Close()
			right.Close()
			if e != nil {
				return e
			}
			return relay.e
		}
		t.Cleanup(func() { carrier.Close(); relay.c.Close() })
		exporter, e := carrier.CarrierBinding()
		if e != nil {
			return e
		}
		peerExporter, e := relay.c.CarrierBinding()
		if e != nil || exporter != peerExporter {
			return runtimeengine.ErrProfileIncompatible
		}
		config, e := auth.NewProjectedProcessHandshakeConfigV1(policy.ClientAuthKeyID, policy.RelayAuthKeyID, program, "tls13-tcp")
		if e != nil {
			return e
		}
		private := ed25519.NewKeyFromSeed(seed)
		defer clear(private)
		cache, e := auth.NewHandshakeReplayCache(64)
		if e != nil {
			return e
		}
		ch, e := runtimeengine.NewProcessWireClientHandshakeV1(config, auth.Dependencies{Identity: maintenanceHandshakeIdentity{policy.ClientAuthKeyID, private}, Trust: maintenanceHandshakeTrust{policy.RelayAuthKeyID, policy.RelayAuthPublic[:]}}, exporter)
		if e != nil {
			return e
		}
		defer ch.Close()
		rh, e := runtimeengine.NewProcessWireRelayHandshakeV1(config, auth.Dependencies{Identity: snapshot, Trust: snapshot}, cache, exporter)
		if e != nil {
			return e
		}
		defer rh.Close()
		hello, e := ch.Start()
		if e != nil {
			return e
		}
		response, e := rh.AcceptClientHello(hello)
		if e != nil {
			return e
		}
		finish, e := ch.AcceptServerHello(response)
		if e != nil {
			return e
		}
		last, rr, e := rh.AcceptClientFinish(finish)
		if e != nil {
			return e
		}
		cr, e = ch.AcceptServerFinish(last)
		if e == nil && len(continuation) == 1 {
			return continuation[0](rr, plan, program, relay.c)
		}
		rr.Close()
		return e
	})
	if err != nil {
		t.Fatal("genuine local TLS/Kurd", err)
	}
	t.Cleanup(func() { cr.Close() })
	return cr, carrier
}

func TestProductionAttemptV1ActualStrictAttachments(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, wrong := range []bool{false, true} {
			t.Run(map[bool]string{false: "service", true: "raw"}[raw]+map[bool]string{false: "-right", true: "-wrong"}[wrong], func(t *testing.T) {
				f, snapshot := productionTLSCurrentFixtureV1(t, raw)
				rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
				o := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
				use, s := o.parent.beginUseV1(202, productionBudgetChargeV1{})
				if s != 0 {
					t.Fatal(s)
				}
				a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
				if s != 0 {
					t.Fatal(s)
				}
				b, s := a.BorrowV1()
				if s != 0 {
					t.Fatal(s)
				}
				t.Cleanup(func() { b.Close(); o.resources.destroyV1(); o.parent.finishUseV1(use) })
				result, carrier := productionActualHandshakeV1(t, b, snapshot)
				if _, s = b.RevalidateV1(context.Background()); s != 0 {
					t.Fatal(s)
				}
				var err error
				if raw != wrong {
					pump, e := b.AttachRawV2(context.Background(), result, carrier)
					err = e
					if pump != nil {
						done := pump.Done()
						var releaseErr error
						finishProductionAttachmentV1(b, productionBudgetTicketV1{}, &pump, &releaseErr)
						if pump != nil || releaseErr != runtimeengine.ServiceInvalidRequestV1 {
							t.Fatal("failed release exposed raw pump", releaseErr)
						}
						select {
						case <-done:
						default:
							t.Fatal("failed release did not join raw pump")
						}
					}
				} else {
					pump, e := b.AttachServiceV1(context.Background(), result, carrier)
					err = e
					if pump != nil {
						done := pump.Done()
						var releaseErr error
						finishProductionAttachmentV1(b, productionBudgetTicketV1{}, &pump, &releaseErr)
						if pump != nil || releaseErr != runtimeengine.ServiceInvalidRequestV1 {
							t.Fatal("failed release exposed service pump", releaseErr)
						}
						select {
						case <-done:
						default:
							t.Fatal("failed release did not join service pump")
						}
					}
				}
				if wrong {
					if err == nil {
						t.Fatal("cross-schema attach succeeded")
					}
					if _, e := result.ProjectedContextSnapshotV3(o.program, "tls13-tcp", auth.ProjectedContextValidationBytesV3); e != nil {
						t.Fatal("pre-Take refusal consumed result", e)
					}
					if _, e := carrier.CarrierBinding(); e == nil {
						t.Fatal("refused carrier not closed")
					}
				} else if err != nil {
					t.Fatal("actual strict attach", err)
				}
			})
		}
	}
}

func TestProductionAttemptV1DeadlineBetweenRevalidationAndBorrow(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	o := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
	clock := &productionTestClockV1{at: f.now}
	o.now = clock.now
	use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
	a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
	if s != 0 {
		t.Fatal(s)
	}
	b, s := a.BorrowV1()
	if s != 0 {
		t.Fatal(s)
	}
	t.Cleanup(func() { b.Close(); o.resources.destroyV1(); o.parent.finishUseV1(use) })
	if _, s = b.RevalidateV1(context.Background()); s != 0 {
		t.Fatal(s)
	}
	clock.set(o.deadline)
	called := false
	err := b.WithInputsV1(func(sessionplan.PlanV2, runtimepolicy.PolicyV2, liveprogram.ProgramV1, []byte, uint8, time.Time) error {
		called = true
		return nil
	})
	if err == nil || called {
		t.Fatal("expired authority reached borrowed callback")
	}
}

func TestProductionAttemptV1ActualAttachmentsPreservePreTakeExpiry(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(map[bool]string{false: "service", true: "raw"}[raw], func(t *testing.T) {
			f, snapshot := productionTLSCurrentFixtureV1(t, raw)
			rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
			o := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
			use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
			a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
			if s != 0 {
				t.Fatal(s)
			}
			b, s := a.BorrowV1()
			if s != 0 {
				t.Fatal(s)
			}
			t.Cleanup(func() { b.Close(); o.resources.destroyV1(); o.parent.finishUseV1(use) })
			result, carrier := productionActualHandshakeV1(t, b, snapshot)
			if _, s = b.RevalidateV1(context.Background()); s != 0 {
				t.Fatal(s)
			}
			var calls atomic.Int32
			o.now = func() time.Time {
				if calls.Add(1) == 1 {
					return f.now
				}
				return o.deadline
			}
			var err error
			if raw {
				pump, e := b.AttachRawV2(context.Background(), result, carrier)
				err = e
				if pump != nil {
					pump.Close()
					t.Error("expired raw pump escaped")
				}
			} else {
				pump, e := b.AttachServiceV1(context.Background(), result, carrier)
				err = e
				if pump != nil {
					pump.Close()
					t.Error("expired service pump escaped")
				}
			}
			if !errors.Is(err, runtimeengine.ServiceAuthorityExpiredV1) {
				t.Error("authoritative expiry lost", err)
			}
			if _, e := result.ProjectedContextSnapshotV3(o.program, "tls13-tcp", auth.ProjectedContextValidationBytesV3); e != nil {
				t.Error("pre-Take expiry consumed result", e)
			}
			if _, e := carrier.CarrierBinding(); e == nil {
				t.Error("expired carrier remained open")
			}
			if o.parent.terminal != 12 || o.parent.useCurrentV1(use) != 7 {
				t.Error("legacy parent expiry mapping changed")
			}
		})
	}
}

func TestProductionAttemptV1ContextEndsDuringFinalRevalidation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deadline bool
		terminal int32
	}{
		{"cancelled", false, 0}, {"deadline", true, 0}, {"selected-expiry", false, 12}, {"selected-revocation", false, 13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMaintenanceSignedFixture(t)
			rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
			o := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
			use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
			a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
			if s != 0 {
				t.Fatal(s)
			}
			b, s := a.BorrowV1()
			if s != 0 {
				t.Fatal(s)
			}
			t.Cleanup(func() { b.Close(); o.resources.destroyV1(); o.parent.finishUseV1(use) })
			ctx, cancel := context.WithCancel(context.Background())
			want := int32(7)
			if tc.deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				want = 8
			}
			if tc.terminal != 0 {
				want = tc.terminal
			}
			defer cancel()
			calls := 0
			o.now = func() time.Time {
				calls++
				if calls == 2 {
					if !tc.deadline {
						cancel()
					}
					<-ctx.Done()
					if tc.terminal != 0 {
						o.parent.cancelV1(tc.terminal)
					}
				}
				return f.now
			}
			if _, s = b.RevalidateV1(ctx); s != want {
				t.Error("ended context published stage", s)
			}
			if b.ready {
				t.Error("ended context left ready borrow")
			}
			called := false
			if e := b.WithInputsV1(func(sessionplan.PlanV2, runtimepolicy.PolicyV2, liveprogram.ProgramV1, []byte, uint8, time.Time) error {
				called = true
				return nil
			}); e == nil || called {
				t.Error("ended context reached input callback")
			}
		})
	}
}

func TestProductionAttemptV1CallbackExpirySuppressesLateSuccess(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	o := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
	clock := &productionTestClockV1{at: f.now}
	o.now = clock.now
	use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
	a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
	if s != 0 {
		t.Fatal(s)
	}
	b, s := a.BorrowV1()
	if s != 0 {
		t.Fatal(s)
	}
	t.Cleanup(func() { b.Close(); o.resources.destroyV1(); o.parent.finishUseV1(use) })
	if _, s = b.RevalidateV1(context.Background()); s != 0 {
		t.Fatal(s)
	}
	called := false
	err := b.WithInputsV1(func(sessionplan.PlanV2, runtimepolicy.PolicyV2, liveprogram.ProgramV1, []byte, uint8, time.Time) error {
		called = true
		clock.set(o.deadline)
		return nil
	})
	if !called || !errors.Is(err, runtimeengine.ServiceAuthorityExpiredV1) {
		t.Error("callback spanning expiry returned late success", err)
	}
	if o.parent.terminal != 12 {
		t.Error("callback expiry did not fence parent")
	}
}

func TestProductionAttemptV1IdentityEndpointAndSingleStage(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	o := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
	use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
	if a, s := newProductionAttemptAdmissionV1(o, o.resources, o.endpointCount, use); a != nil || s != 3 {
		t.Fatal("out of fallback", s)
	}
	stale := use
	stale.serial++
	if a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, stale); a != nil || s != 3 {
		t.Fatal("stale use", s)
	}
	other := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	wrong, _ := other.beginUseV1(202, productionBudgetChargeV1{})
	if a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, wrong); a != nil || s != 3 {
		t.Fatal("cross parent", s)
	}
	other.finishUseV1(wrong)
	a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
	if s != 0 {
		t.Fatal(s)
	}
	t.Cleanup(func() {
		if a.borrow != nil {
			a.borrow.Close()
		}
		o.resources.destroyV1()
		o.parent.finishUseV1(use)
	})
	copied := *a
	if b, s := copied.BorrowV1(); b != nil || s != 3 {
		t.Fatal("copied admission", s)
	}
	o.nextBorrow = math.MaxUint64
	if b, s := a.BorrowV1(); b != nil || s != 3 {
		t.Fatal("wrapped serial", s)
	}
	o.nextBorrow = 0
	b, s := a.BorrowV1()
	if s != 0 {
		t.Fatal(s)
	}
	copyBorrow := *b
	if _, s := copyBorrow.RevalidateV1(context.Background()); s != 3 {
		t.Fatal("copied borrow", s)
	}
	callback := func(sessionplan.PlanV2, runtimepolicy.PolicyV2, liveprogram.ProgramV1, []byte, uint8, time.Time) error {
		return nil
	}
	if b.WithInputsV1(callback) == nil {
		t.Fatal("borrow without stage")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, s := b.RevalidateV1(cancelled); s != 7 {
		t.Fatal("cancelled stage admitted", s)
	}
	if _, s := b.RevalidateV1(context.Background()); s != 0 {
		t.Fatal(s)
	}
	if e := b.WithInputsV1(callback); e != nil {
		t.Fatal(e)
	}
	if b.WithInputsV1(callback) == nil {
		t.Fatal("reused stage")
	}
	if e := b.Close(); e != nil {
		t.Fatal(e)
	}
	if _, s := b.RevalidateV1(context.Background()); s != 3 {
		t.Fatal("closed borrow", s)
	}
}

func TestProductionAttemptV1TrustedRollbackAndMonotonicDeadline(t *testing.T) {
	for _, mono := range []bool{false, true} {
		t.Run(map[bool]string{false: "trusted-rollback", true: "monotonic-end"}[mono], func(t *testing.T) {
			f := newMaintenanceSignedFixture(t)
			rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
			o := productionAdmittedFixtureV1(t, f, &productionSnapshotPlatformV1{snapshot: f.current}, rates)
			use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
			a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
			if s != 0 {
				t.Fatal(s)
			}
			b, s := a.BorrowV1()
			if s != 0 {
				t.Fatal(s)
			}
			t.Cleanup(func() { b.Close(); o.resources.destroyV1(); o.parent.finishUseV1(use) })
			if mono {
				o.monotonicNow = func() time.Time { return o.monotonicDeadline }
			} else {
				o.now = func() time.Time { return f.now.Add(-time.Nanosecond) }
			}
			if _, s = b.RevalidateV1(context.Background()); s != 12 {
				t.Fatal("clock authority extended", s)
			}
		})
	}
}

func TestProductionAttemptV1BlockedActualAttachmentKeepsUseAndTerminalCause(t *testing.T) {
	f, snapshot := productionTLSCurrentFixtureV1(t, false)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	platform := &productionSnapshotPlatformV1{snapshot: f.current}
	o := productionAdmittedFixtureV1(t, f, platform, rates)
	use, _ := o.parent.beginUseV1(202, productionBudgetChargeV1{})
	a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
	if s != 0 {
		t.Fatal(s)
	}
	b, s := a.BorrowV1()
	if s != 0 {
		t.Fatal(s)
	}
	result, carrier := productionActualHandshakeV1(t, b, snapshot)
	if _, s = b.RevalidateV1(context.Background()); s != 0 {
		t.Fatal(s)
	}
	beforeOwned, beforeQueued := o.parent.budget.owned, o.parent.budget.queued
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	o.now = func() time.Time {
		if calls.Add(1) == 2 {
			close(entered)
			<-release
		}
		return f.now
	}
	attached := make(chan error, 1)
	go func() {
		pump, err := b.AttachServiceV1(context.Background(), result, carrier)
		if pump != nil {
			pump.Close()
		}
		attached <- err
	}()
	<-entered
	o.parent.mu.Lock()
	scratch := o.resources.attachmentScratchBytes
	o.parent.mu.Unlock()
	o.parent.budget.mu.Lock()
	charged, queued := o.parent.budget.owned, o.parent.budget.queued
	o.parent.budget.mu.Unlock()
	if scratch == 0 || charged != beforeOwned+scratch || queued != beforeQueued {
		t.Fatal("blocked attachment did not retain separate scratch ticket")
	}
	invalidated := make(chan ErrorCode, 1)
	go func() { invalidated <- platform.invalidate() }()
	// Wait for the real parent cancellation fence, not elapsed wall-clock time.
	<-o.parent.cancelContext.Done()
	if !o.seedLive || o.parent.finishUseV1(use) != 3 {
		t.Fatal("blocked attachment released authority")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- b.Close() }()
	select {
	case <-closeDone:
		t.Fatal("close did not join actual attachment")
	default:
	}
	close(release)
	err := <-attached
	if o.resources.attachmentScratchBytes != 0 || o.parent.budget.owned != beforeOwned || o.parent.budget.queued != beforeQueued {
		t.Fatal("scratch did not retire after attachment cleanup")
	}
	if e := <-closeDone; e != nil {
		t.Fatal(e)
	}
	if o.resources.destroyV1() != 0 || o.parent.finishUseV1(use) != 0 {
		t.Fatal("post attachment join")
	}
	if code := <-invalidated; code != CodeOK {
		t.Fatal(code)
	}
	if !errors.Is(err, runtimeengine.ServiceCancelledV1) {
		t.Fatal("ordinary revision cancellation lost to incidental constructor time error", err)
	}
}

func TestProductionAttemptV1CloseAndInvalidationJoinRealBorrow(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	platform := &productionSnapshotPlatformV1{snapshot: f.current}
	o := productionAdmittedFixtureV1(t, f, platform, rates)
	p := o.parent
	use, s := p.beginUseV1(202, productionBudgetChargeV1{})
	if s != 0 {
		t.Fatal(s)
	}
	a, s := newProductionAttemptAdmissionV1(o, o.resources, 0, use)
	if s != 0 {
		t.Fatal(s)
	}
	b, s := a.BorrowV1()
	if s != 0 {
		t.Fatal(s)
	}
	if _, s = a.BorrowV1(); s != 3 {
		t.Fatal("second borrow", s)
	}
	if _, s = b.RevalidateV1(context.Background()); s != 0 {
		t.Fatal(s)
	}
	before := p.budget.owned
	entered, release, callbackDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		callbackDone <- b.WithInputsV1(func(plan sessionplan.PlanV2, policy runtimepolicy.PolicyV2, program liveprogram.ProgramV1, seed []byte, index uint8, now time.Time) error {
			if len(seed) != 32 || !bytes.Equal(seed, o.seed[:]) || plan.Digest != o.plan.Digest || index != 0 || now != f.now || len(policy.LiveProgram) == 0 || len(program.Messages) == 0 {
				t.Error("wrong borrowed authority")
			}
			if err := b.WithInputsV1(func(sessionplan.PlanV2, runtimepolicy.PolicyV2, liveprogram.ProgramV1, []byte, uint8, time.Time) error {
				return nil
			}); err == nil {
				t.Error("nested callback")
			}
			close(entered)
			<-release
			if !bytes.Equal(seed, o.seed[:]) || !o.seedLive {
				t.Error("seed cleared before callback returned")
			}
			return nil
		})
	}()
	<-entered
	if s = p.finishUseV1(use); s != 3 {
		close(release)
		<-callbackDone
		t.Fatal("attempt released under real callback", s)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- b.Close() }()
	invalidated := make(chan ErrorCode, 1)
	go func() { invalidated <- platform.invalidate() }()
	select {
	case <-invalidated:
		t.Fatal("invalidation acknowledged before join")
	default:
	}
	select {
	case <-closeDone:
		t.Fatal("borrow close did not join")
	default:
	}
	if !o.seedLive || p.budget.owned != before {
		t.Fatal("early storage release")
	}
	close(release)
	<-callbackDone
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if p.activeUses != 1 {
		t.Fatal("borrow close retired transport")
	}
	if o.resources.destroyV1() != 0 {
		t.Fatal("installation join")
	}
	if p.finishUseV1(use) != 0 {
		t.Fatal("attempt finish")
	}
	if code := <-invalidated; code != CodeOK {
		t.Fatal("joined invalidation", code)
	}
	if o.seedLive || o.seed != ([32]byte{}) {
		t.Fatal("joined seed retained")
	}
}
