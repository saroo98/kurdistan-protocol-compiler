// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	runtimeengine "kurdistan/internal/runtime"
	"testing"
	"time"
)

func TestProductionResourcesV1ReservesDecoderBeforeSmallerRecipeLifetime(t *testing.T) {
	now := time.Unix(1800000000, 0)
	a := productionAuthorityFixtureV1(t, now, nil)
	p, s := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false)), a, now)
	if s != 0 {
		t.Fatal(s)
	}
	defer p.Destroy()
	facts, _ := p.plan.ConstructionFactsV2()
	calculation, _ := sessionplan.AdmittedCalculationBoundsV2(facts.ProfileBytes)
	ledger, _ := newProductionBudgetV1(80 << 20)
	base := ledger.owned
	available := runtimeengine.ProductionClientAvailableV1{AggregateBytes: productionResourcesHolderBytesV1() + calculation.SuffixBytes - 1}
	if resource, status := prepareProductionResourcesV1(&p, ledger, available, now, 1); resource != nil || status != int32(productionResourceLimitV1) {
		if resource != nil {
			resource.destroyV1()
		}
		t.Fatal("decoder ran without admitted workspace", status)
	}
	if ledger.owned != base {
		t.Fatal("preflight changed ledger")
	}
	resource, status := prepareProductionResourcesV1(&p, ledger, runtimeengine.ProductionClientAvailableV1{AggregateBytes: ledger.cap - base}, now, 1)
	if status != 0 {
		t.Fatal(status)
	}
	reservation, err := resource.installation.ReservationV1()
	if err != nil || reservation.OwnedBytes >= calculation.SuffixBytes {
		t.Fatal("fixture must exercise recipe smaller than decoder scratch", reservation, err)
	}
	if ledger.owned != base+productionResourcesHolderBytesV1()+reservation.OwnedBytes {
		t.Fatal("scratch credited as lifetime or not released")
	}
	if resource.destroyV1() != 0 || ledger.owned != base {
		t.Fatal("joined ticket retirement")
	}
}

func TestProductionResourcesV1MapsActualProjectionAndReservesJoinedOwnership(t *testing.T) {
	now := time.Unix(1800000000, 0)
	services := &runtimepolicy.ServicesV1{Version: 1, Probes: &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 7, Address: []byte{1, 1, 1, 1}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1}, TimeoutMillis: 1000}}, MaxConcurrentOperations: 2, MaxSamplesPerOperation: 3, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 4, MaxOperationMillis: 5000}}
	authority := productionAuthorityFixtureV1(t, now, services)
	p, status := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false)), authority, now)
	if status != productionSuccessV1 {
		t.Fatal(status)
	}
	defer p.Destroy()
	ledger, status32 := newProductionBudgetV1(80 << 20)
	if status32 != 0 {
		t.Fatal(status32)
	}
	base := ledger.owned
	resource, status32 := prepareProductionResourcesV1(&p, ledger, runtimeengine.ProductionClientAvailableV1{AggregateBytes: ledger.cap - base}, now, 1)
	if status32 != 0 {
		t.Fatal("prepare", status32)
	}
	defer resource.destroyV1()
	limits, e := resource.installation.InstalledLimitsV1()
	if e != nil {
		t.Fatal(e)
	}
	if limits.TCPFlows != 256 || limits.UDPFlows != 128 || limits.SessionIdle != 30*time.Second || limits.ProbeLimit != 0 {
		t.Fatal("used safe maxima instead of signed active mode", limits)
	}
	if p.plan.Digest != ([32]byte{}) {
		t.Fatal("transferred preview not destroyed")
	}
	b, e := resource.installation.ReservationV1()
	if e != nil {
		t.Fatal(e)
	}
	if ledger.owned != base+b.OwnedBytes+productionResourcesHolderBytesV1() || ledger.queued != b.QueuedBytes {
		t.Fatal("reservation not exact/shared", ledger.owned, base, b)
	}
	if status32 = resource.destroyV1(); status32 != 0 {
		t.Fatal(status32)
	}
	select {
	case <-resource.installation.Done():
	default:
		t.Fatal("released ledger before joined destruction")
	}
	if ledger.owned != base || ledger.queued != 0 {
		t.Fatal("resource reservation leaked")
	}
	if status32 = resource.destroyV1(); status32 != 0 || ledger.owned != base {
		t.Fatal("double release")
	}
}

func TestProductionResourcesV1StrictRawProjection(t *testing.T) {
	now := time.Unix(1800000000, 0)
	a := productionAuthorityFixtureV1(t, now, nil)
	p, status := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false)), a, now)
	if status != 0 {
		t.Fatal(status)
	}
	defer p.Destroy()
	ledger, status32 := newProductionBudgetV1(80 << 20)
	if status32 != 0 {
		t.Fatal(status32)
	}
	base := ledger.owned
	resource, result := prepareProductionResourcesV1(&p, ledger, runtimeengine.ProductionClientAvailableV1{AggregateBytes: ledger.cap - base}, now, 1)
	if result != 0 || resource == nil {
		t.Fatal("strict schema2 preparation", result)
	}
	n, err := resource.installation.InstalledLimitsV1()
	if err != nil || n.Mode != runtimeengine.ProductionTUNV1 || n.ProbeLimit != 0 || n.StreamLimit != 0 || n.StreamQueueBytes != 0 || n.ProxyIdle != 0 || n.ProxyCeilingBytes != 0 {
		t.Fatal("raw resource widened", n, err)
	}
	if resource.destroyV1() != 0 {
		t.Fatal("raw cleanup")
	}
	if ledger.owned != base || ledger.queued != 0 {
		t.Fatal("failed prep leaked charge")
	}
}

func TestProductionResourcesV1RawRefusesProxyResidualAndMode(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, mode := range []bool{false, true} {
		a := productionAuthorityFixtureV1(t, now, nil)
		p, s := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, productionSettingsRowsV1(false)), a, now)
		if s != 0 {
			t.Fatal(s)
		}
		ledger, _ := newProductionBudgetV1(80 << 20)
		base := ledger.owned
		available := runtimeengine.ProductionClientAvailableV1{AggregateBytes: ledger.cap - base, ProxyBytes: 16 << 20}
		if mode {
			p.effectiveMode = 3
		}
		r, status := prepareProductionResourcesV1(&p, ledger, available, now, 1)
		if r != nil || status == 0 {
			t.Fatal("raw projection broadened", mode, status)
		}
		if ledger.owned != base {
			t.Fatal("refused wrapper leaked")
		}
		p.Destroy()
	}
}
