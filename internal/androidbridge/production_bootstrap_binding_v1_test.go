// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bytes"
	"fmt"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/selfhost"
	"testing"
	"time"
)

func TestReadProductionRuntimeBootstrapBindingV1MaximumTargetsAndAbsentServices(t *testing.T) {
	probes := &runtimepolicy.ProbesV1{MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 10, MaxOperationMillis: 30000}
	for id := uint16(1); id <= 16; id++ {
		probes.Targets = append(probes.Targets, runtimepolicy.ProbeTargetV1{ID: id, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000})
	}
	for _, services := range []*runtimepolicy.ServicesV1{nil, {Version: 1, Probes: probes}} {
		f := bootstrapSignedFixtureV1(t, services)
		wire := productionSettingsMessageV1(productionSettingsRowsV1(false))
		before := bytes.Clone(wire)
		a, d := make([]byte, 512), make([]byte, 512)
		facts, an, dn, status := ReadProductionRuntimeBootstrapBindingV1(f.current, wire, &productionRealCurrentV1{}, f.now, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 128 << 20, MaxArtifactBytes: 1052763, MaxPublicationBytes: 1052763}, a, d)
		if status != 0 || facts.Generation == 0 || !bytes.Equal(wire, before) {
			t.Fatal("maximum-target read", status)
		}
		for _, encoded := range [][]byte{a[:an], d[:dn]} {
			decoded, status := decodeProductionSelectorsV1(encoded)
			if status != 0 || decoded.strategyCount != 1 {
				t.Fatal("catalogue", status)
			}
			want := uint8(0)
			if services != nil {
				want = 16
			}
			if decoded.probeCount != want {
				t.Fatal("probe count", decoded.probeCount, want)
			}
			for i := 0; i < int(want); i++ {
				if string(decoded.probeIDs[i]) != fmt.Sprintf("probe-%d", i+1) {
					t.Fatal("numeric canonical order", i)
				}
			}
		}
	}
}
func TestReadProductionRuntimeBootstrapBindingV1ModesAndRoleBinding(t *testing.T) {
	services := &runtimepolicy.ServicesV1{Version: 1,
		Proxy: &runtimepolicy.ProxyV1{AddressKinds: []uint8{1, 2}, DestinationCIDRs: []runtimepolicy.PrefixV2{{Address: []byte{0, 0, 0, 0}, PrefixLen: 0}}, DestinationPorts: []runtimepolicy.PortRangeV1{{First: 443, Last: 443}}, MaxConcurrentStreams: 8, MaxBufferBytes: 24 << 20, ConnectTimeoutMillis: 5000, IdleTimeoutSeconds: 120, MaxQueuedBytesPerDirection: 32768},
		Probes: &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{
			{ID: 2, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{2}, TimeoutMillis: 1000},
			{ID: 3, Address: []byte{9, 9, 9, 9}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000},
			{ID: 10, Address: []byte{1, 1, 1, 1}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1}, TimeoutMillis: 1000}},
			MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 10, MaxOperationMillis: 30000}}
	f := bootstrapSignedFixtureV1(t, services)
	for _, mode := range []byte{1, 2, 3} {
		rows := productionSettingsRowsV1(false)
		rows[9][0] = mode
		rows[1][2] = 1
		wire := productionSettingsMessageV1(rows)
		e := &productionRealCurrentV1{}
		a, d := make([]byte, 512), make([]byte, 512)
		facts, an, dn, status := ReadProductionRuntimeBootstrapBindingV1(f.current, wire, e, f.now, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 128 << 20, MaxArtifactBytes: 1052763, MaxPublicationBytes: 1052763}, a, d)
		if status != 0 || e.calls != 1 {
			t.Fatal("read", mode, status, e.calls)
		}
		policy, err := runtimepolicy.DecodeRuntimeAt(f.record.Profile.Policy, f.now)
		if err != nil {
			t.Fatal(err)
		}
		projection, s := projectProductionSettingsV1(projectionSettingsFromRowsV1(t, rows), sessionplan.RequestV2{Profile: f.record.Profile, ActivationReceipt: f.record.State.Receipt, RuntimePolicy: policy}, f.now)
		if s != 0 {
			t.Fatal(s)
		}
		if facts.Generation != projection.plan.ProfileGeneration || facts.PlanDigest != projection.plan.Digest || facts.EffectiveMTU != 1280 || facts.SignedRetryMaximum != projection.signedReconnectMax || facts.EffectiveAutomaticReconnectMaximum != projection.effectiveAutomaticReconnectMax {
			t.Fatal("facts differ")
		}
		projection.Destroy()
		active, as := decodeProductionSelectorsV1(a[:an])
		disconnected, ds := decodeProductionSelectorsV1(d[:dn])
		if as != 0 || ds != 0 || !active.matches(facts.Generation, facts.PlanDigest) || !disconnected.matches(facts.Generation, facts.PlanDigest) {
			t.Fatal("catalogue binding")
		}
		if active.probeCount != 2 || string(active.probeIDs[0]) != "probe-2" || string(active.probeIDs[1]) != "probe-3" || disconnected.probeCount != 2 || string(disconnected.probeIDs[0]) != "probe-3" || string(disconnected.probeIDs[1]) != "probe-10" {
			t.Fatal("role/order mismatch")
		}
	}
}
func TestReadProductionRuntimeBootstrapBindingV1FailuresNeverPublish(t *testing.T) {
	f := bootstrapSignedFixtureV1(t, nil)
	for _, kind := range []string{"budget", "mode", "short", "overlap", "record", "expired"} {
		e := &productionRealCurrentV1{}
		a, d := bytes.Repeat([]byte{99}, 512), bytes.Repeat([]byte{99}, 512)
		rows := productionSettingsRowsV1(false)
		input := f.current
		now := f.now
		limits := selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 128 << 20, MaxArtifactBytes: 1052763, MaxPublicationBytes: 1052763}
		switch kind {
		case "budget":
			limits.OwnedBudgetBytes = 1
		case "mode":
			rows[9][0] = 2
		case "short":
			a = a[:511]
		case "overlap":
			d = a
		case "record":
			input.ActivationRecord = []byte{0}
		case "expired":
			now = now.Add(24 * time.Hour)
		}
		facts, an, dn, status := ReadProductionRuntimeBootstrapBindingV1(input, productionSettingsMessageV1(rows), e, now, limits, a, d)
		if status == 0 || facts != (ProductionBootstrapFactsV1{}) || an != 0 || dn != 0 {
			t.Fatal("failure published", kind, status)
		}
		if (kind == "budget" || kind == "short" || kind == "overlap") && e.calls != 0 {
			t.Fatal("verification before preflight", kind)
		}
		if !bytes.Equal(a, bytes.Repeat([]byte{99}, len(a))) {
			t.Fatal("partial output", kind)
		}
	}
}
