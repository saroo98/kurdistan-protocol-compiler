// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"errors"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/runtime"
	"net"
	"net/netip"
	"testing"
	"time"
)

func maintenanceProbeAdmission(t *testing.T, samples uint8) runtime.ProbeAdmissionV1 {
	t.Helper()
	p := &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 1, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000}}, MaxConcurrentOperations: 1, MaxSamplesPerOperation: 10, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 60, MaxOperationMillis: 30000}
	a, err := runtime.AdmitProbePolicyV1(p, runtime.ProbeRequestV1{TargetID: 1, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 3000, Samples: samples}, runtime.ProbeDisconnectedDefaultV1, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Destroy)
	return a
}
func TestMaintenanceDisconnectedProbeActualConnectAndFirstRateDenial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		c, e := listener.Accept()
		if e == nil {
			c.Close()
		}
	}()
	a := maintenanceProbeAdmission(t, 1)
	scope := updateScope(t, "probe")
	rates, _ := runtime.NewProbeRateRegistryV1(1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	calls := 0
	dial := func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		calls++
		if dst != netip.MustParseAddrPort("8.8.8.8:443") {
			t.Error("wrong signed target")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}
	request := runtime.ProbeRequestV1{TargetID: 1, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 3000, Samples: 1}
	run := func() (runtime.ProbeAggregateV1, MaintenanceResultV1, ErrorCode) {
		return maintenanceDisconnectedSamplesV1(ctx, a, scope, rates, request, time.Now().Add(3*time.Second), time.Now, dial, func() MaintenanceResultV1 { return MaintenanceSuccess })
	}
	out, r, cleanup := run()
	if cleanup != CodeOK || r != MaintenanceSuccess || out.Attempted != 1 || !out.HasLatency || out.Path != runtime.ProbeDisconnectedTCPConnectV1 {
		t.Fatal(out, r)
	}
	out, r, cleanup = run()
	if cleanup != CodeOK || r != MaintenanceRateLimited || out.Attempted != 0 || calls != 1 {
		t.Fatal(out, r, calls)
	}
	<-accepted
}
func TestMaintenanceDisconnectedProbeCancelDoesNotFabricateAttempt(t *testing.T) {
	a := maintenanceProbeAdmission(t, 3)
	rates, _ := runtime.NewProbeRateRegistryV1(1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dial := func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) { cancel(); return nil, ctx.Err() }
	out, r, cleanup := maintenanceDisconnectedSamplesV1(ctx, a, updateScope(t, "cancel"), rates, runtime.ProbeRequestV1{TargetID: 1, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 3000, Samples: 3}, time.Now().Add(3*time.Second), time.Now, dial, func() MaintenanceResultV1 { return MaintenanceSuccess })
	if cleanup != CodeOK || r != MaintenanceCancelled || out.Attempted != 0 || out.LossPermille != 0 {
		t.Fatal(out, r)
	}
}

type maintenanceProbeCloseFailureV1 struct {
	net.Conn
	closes int
}

func (c *maintenanceProbeCloseFailureV1) Close() error {
	c.closes++
	return errors.New("fixture close failure")
}

func TestMaintenanceDisconnectedProbeCloseFailureSuppressesAggregate(t *testing.T) {
	a := maintenanceProbeAdmission(t, 1)
	rates, _ := runtime.NewProbeRateRegistryV1(1)
	connection := &maintenanceProbeCloseFailureV1{}
	dial := func(context.Context, netip.AddrPort) (net.Conn, error) { return connection, nil }
	out, result, cleanup := maintenanceDisconnectedSamplesV1(context.Background(), a, updateScope(t, "close-failure"), rates,
		runtime.ProbeRequestV1{TargetID: 1, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 3000, Samples: 1},
		time.Now().Add(3*time.Second), time.Now, dial, func() MaintenanceResultV1 { return MaintenanceSuccess })
	if cleanup != CodeStateCorrupt || result != MaintenanceInternalFailure || out != (runtime.ProbeAggregateV1{}) || connection.closes != 1 {
		t.Fatalf("failed close published: out=%+v result=%v closes=%d", out, result, connection.closes)
	}
}
func TestMaintenanceProbeMissingTransportIsUnavailable(t *testing.T) {
	p := newMaintenanceStateFixture(t)
	var registry HandleRegistry
	p.registry = &registry
	h, _ := registry.Open(HandleMaintenance, p)
	p.handle = h
	out, r := RunMaintenanceProbeV1(&registry, h, runtime.ProbeRequestV1{TargetID: 1, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 1000, Samples: 1})
	if r != MaintenanceNetworkUnavailable || out.Attempted != 0 {
		t.Fatal(out, r)
	}
}

type maintenanceProbeBoundaryFixture struct {
	request        runtime.ProbeRequestV1
	cancelled      bool
	workerRetained bool
	cancel         context.CancelFunc
}

func (f *maintenanceProbeBoundaryFixture) StartProbe(_ context.Context, r runtime.ProbeRequestV1) (uint64, error) {
	f.request = r
	f.workerRetained = true
	return 7, nil
}
func (f *maintenanceProbeBoundaryFixture) AwaitProbe(ctx context.Context, id uint64) (runtime.ProbeAggregateV1, error) {
	if id != 7 {
		panic("wrong child")
	}
	f.cancel()
	<-ctx.Done()
	return runtime.ProbeAggregateV1{Path: runtime.ProbeActiveRelayEndToEndV1, Attempted: 1, HasLatency: true, LatencyMicros: 123, Stability: runtime.ProbeNotEnoughSamplesV1}, runtime.ServiceCancelledV1
}
func (f *maintenanceProbeBoundaryFixture) CancelProbe(id uint64) error {
	if id != 7 {
		panic("wrong child")
	}
	f.cancelled = true
	return nil
}
func TestMaintenanceActiveDelegationPreservesAggregateAndDoesNotClaimPumpJoin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &maintenanceProbeBoundaryFixture{cancel: cancel}
	request := runtime.ProbeRequestV1{TargetID: 7, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 3000, Samples: 3}
	out, r := maintenanceAwaitActiveProbeV1(ctx, f, request, func() MaintenanceResultV1 { return maintenanceContextResultV1(ctx) })
	if r != MaintenanceCancelled || out.Attempted != 1 || out.LatencyMicros != 123 || !f.cancelled || !f.workerRetained || f.request != request {
		t.Fatal(out, r)
	}
}

func TestMaintenanceDisconnectedAttemptTimeoutCountsOnlyTheAttempt(t *testing.T) {
	a := maintenanceProbeAdmission(t, 1)
	rates, _ := runtime.NewProbeRateRegistryV1(1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dial := func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	out, r, cleanup := maintenanceDisconnectedSamplesV1(ctx, a, updateScope(t, "timeout"), rates, runtime.ProbeRequestV1{TargetID: 1, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 3000, Samples: 1}, time.Now().Add(3*time.Second), time.Now, dial, func() MaintenanceResultV1 { return MaintenanceSuccess })
	if cleanup != CodeOK || r != MaintenanceSuccess || out.Attempted != 1 || out.HasLatency || out.LossPermille != 1000 {
		t.Fatal(out, r)
	}
}
