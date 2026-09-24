//go:build !phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"context"
	"kurdistan/internal/androidbridge"
	"kurdistan/internal/runtime"
	"net/netip"
	"testing"
)

type maintenancePlatformTestNetwork struct {
	done   chan struct{}
	closed int
}

func (n *maintenancePlatformTestNetwork) Mode() runtime.ProbeModeV1 {
	return runtime.ProbeDisconnectedDefaultV1
}
func (n *maintenancePlatformTestNetwork) IPFamilies() uint8 { return 3 }
func (n *maintenancePlatformTestNetwork) DNSServersInto(dst *[4]netip.AddrPort) (int, androidbridge.MaintenanceResultV1) {
	dst[0] = netip.MustParseAddrPort("127.0.0.1:53")
	return 1, androidbridge.MaintenanceSuccess
}
func (n *maintenancePlatformTestNetwork) BindSocket(uintptr) androidbridge.MaintenanceResultV1 {
	return androidbridge.MaintenanceNetworkUnavailable
}
func (n *maintenancePlatformTestNetwork) IsCurrent() bool       { return true }
func (n *maintenancePlatformTestNetwork) Done() <-chan struct{} { return n.done }
func (n *maintenancePlatformTestNetwork) Close() androidbridge.ErrorCode {
	n.closed++
	return androidbridge.CodeOK
}

type maintenancePlatformTestEnvironment struct {
	network         *maintenancePlatformTestNetwork
	acquired, roots int
}

func (e *maintenancePlatformTestEnvironment) AcquireNetwork(context.Context) (androidbridge.MaintenanceNetworkLeaseV1, androidbridge.MaintenanceResultV1) {
	e.acquired++
	return e.network, androidbridge.MaintenanceSuccess
}
func (e *maintenancePlatformTestEnvironment) SystemRootsInto(context.Context, []byte) (int, androidbridge.MaintenanceResultV1) {
	e.roots++
	return 0, androidbridge.MaintenanceTLSTrustUnavailable
}
func TestMaintenanceTransportSignedAdmissionAndProcessRateSurviveReopen(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	var registry androidbridge.HandleRegistry
	rates, r := androidbridge.NewMaintenanceUpdateRateRegistryV1(1)
	if r != androidbridge.MaintenanceSuccess {
		t.Fatal(r)
	}
	for round := 0; round < 2; round++ {
		environment := &maintenancePlatformTestEnvironment{network: &maintenancePlatformTestNetwork{done: make(chan struct{})}}
		config := maintenanceConfig(fixture.now)
		config.Transport = environment
		config.UpdateRates = rates
		handle, r := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, &releaseMaintenancePlatform{}, config)
		if r != androidbridge.MaintenanceSuccess {
			t.Fatal(r)
		}
		got := androidbridge.CheckSameDeploymentUpdateV1(&registry, handle, 2000)
		if got.Result != androidbridge.MaintenanceInvalidRequest {
			t.Fatal("signed timeout widening", got.Result)
		}
		got = androidbridge.CheckSameDeploymentUpdateV1(&registry, handle, 1000)
		want := androidbridge.MaintenanceTLSTrustUnavailable
		if round == 1 {
			want = androidbridge.MaintenanceRateLimited
		}
		if got.Result != want || got.Candidate != 0 || got.Preview.ArtifactLength != 0 {
			t.Fatal(got.Result)
		}
		if environment.acquired != 1 || environment.roots != 1-round {
			t.Fatal("provider acquired again or rate spent late")
		}
		if code := registry.Free(handle); code != androidbridge.CodeOK {
			t.Fatal(code)
		}
		if environment.network.closed != 1 {
			t.Fatal("lease not closed exactly once")
		}
	}
}
