// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/selfhost"
	"path/filepath"
	"testing"
	"time"
	"unsafe"
)

// Invoked by the genuine release-environment fixture, not a fake verifier.
func assertBootstrapPrivateBindingSuccessV1(t *testing.T, input androidbridge.MaintenanceCurrentInputV1, expected androidbridge.RuntimeSessionSnapshotV2) {
	t.Helper()
	policy, err := androidbridge.EncodeRuntimeOpenRequest(androidbridge.RuntimeOpenRequest{VerifyRequest: []byte{1}, ActivationRecord: []byte{1}, Policy: androidbridge.RuntimePolicyRequest{
		SelectionMode: androidbridge.RuntimeSelectionAutomatic, PerAppMode: androidbridge.RuntimePerAppAllApps, IPMode: androidbridge.RuntimeIPV4Only, DNSMode: androidbridge.RuntimeDNSInternal, MTU: 1280}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(policy)
	rows := [5][]byte{input.VerifyRequest, input.ActivationRecord, input.RecipientRequest, input.RecipientPrivate, policy}
	var spans [5]bootstrapSpanV1
	for i, row := range rows {
		spans[i] = bootstrapSpanV1{unsafe.Pointer(&row[0]), uint32(len(row))}
	}
	legacy := bytes.Repeat([]byte{99}, 44)
	if status := bootstrapLegacyBindingV1(spans, bootstrapSpanV1{unsafe.Pointer(&legacy[0]), 44}); status != 0 {
		t.Fatal("real legacy private binding", status)
	}
	if binary.BigEndian.Uint64(legacy[:8]) != expected.Generation || !bytes.Equal(legacy[8:40], expected.PlanDigest[:]) || legacy[40] != expected.MaxReconnectAttempts || legacy[41] != 99 {
		t.Fatal("legacy serialization parity")
	}
	before := bytes.Clone(legacy)
	if status := bootstrapLegacyBindingAtV1(spans, bootstrapSpanV1{unsafe.Pointer(&legacy[0]), 44}, bootstrapOverrunEnvironmentV1{}, time.Now().UTC()); status != -6401 || !bytes.Equal(before, legacy) {
		t.Fatal("private adapter lost capacity signal or published", status)
	}
	settings, err := hex.DecodeString("4b50533101000000000000510100000100000000000301010005dc0000000001000000000002000100010100030303012c0100008000500000000102012a382a390410012c0020001e0001000100000000")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(settings)
	spans[4] = bootstrapSpanV1{unsafe.Pointer(&settings[0]), uint32(len(settings))}
	facts := bytes.Repeat([]byte{99}, 45)
	active, disconnected := bytes.Repeat([]byte{99}, 512), bytes.Repeat([]byte{99}, 512)
	var a, d uint32
	status := bootstrapProductionBindingV1(spans, bootstrapSpanV1{unsafe.Pointer(&facts[0]), 45}, bootstrapSpanV1{unsafe.Pointer(&active[0]), 512}, &a, bootstrapSpanV1{unsafe.Pointer(&disconnected[0]), 512}, &d)
	if status != 0 {
		t.Fatal("real production private binding", status)
	}
	want, an, dn, status := androidbridge.ReadProductionRuntimeBootstrapBindingV1(input, settings, selfHostedBridgeEnvironment{}, time.Now().UTC(), bootstrapLimitsV1(), make([]byte, 512), make([]byte, 512))
	if status != 0 || a != uint32(an) || d != uint32(dn) || binary.BigEndian.Uint64(facts[:8]) != want.Generation || !bytes.Equal(facts[8:40], want.PlanDigest[:]) || binary.BigEndian.Uint16(facts[40:42]) != want.EffectiveMTU || facts[42] != want.SignedRetryMaximum || facts[43] != want.EffectiveAutomaticReconnectMaximum || facts[44] != 99 {
		t.Fatal("production serialization parity", status)
	}
	for _, catalog := range [][]byte{active[:a], disconnected[:d]} {
		if string(catalog[:4]) != "KPA1" || binary.BigEndian.Uint64(catalog[12:20]) != want.Generation || !bytes.Equal(catalog[20:52], want.PlanDigest[:]) {
			t.Fatal("paired catalogue binding")
		}
	}
}

// The real bounded verifier supplies the complete graph; only its observed
// capacity diagnostic is corrupted to exercise the private boundary anomaly.
type bootstrapOverrunEnvironmentV1 struct{}

func (bootstrapOverrunEnvironmentV1) VerifyWithRecipientAt(a []byte, class envelope.ArtifactClass, c androidbridge.RecipientCredentials, now time.Time, limits selfhost.LiveMaintenanceLimits) (profile.OfflineVerifiedArtifact, selfhost.LiveMaintenanceBounds, error) {
	v, b, err := (selfHostedBridgeEnvironment{}).VerifyWithRecipientAt(a, class, c, now, limits)
	if err == nil {
		b.PeakReservedBytes = b.BudgetBytes + 1
	}
	return v, b, err
}

func TestBootstrapBindingV1PrivateSpanPreflightAndNoPublication(t *testing.T) {
	rows := [5][]byte{{1}, {1}, {1}, {1}, {1}}
	var inputs [5]bootstrapSpanV1
	for i := range rows {
		inputs[i] = bootstrapSpanV1{unsafe.Pointer(&rows[i][0]), uint32(len(rows[i]))}
	}
	facts := bytes.Repeat([]byte{0xa5}, 44)
	active := bytes.Repeat([]byte{0xb6}, 512)
	disconnected := bytes.Repeat([]byte{0xc7}, 512)
	a, d := uint32(99), uint32(99)
	factSpan := bootstrapSpanV1{unsafe.Pointer(&facts[0]), 44}
	activeSpan := bootstrapSpanV1{unsafe.Pointer(&active[0]), 512}
	disconnectedSpan := bootstrapSpanV1{unsafe.Pointer(&disconnected[0]), 512}
	for _, test := range []struct {
		name   string
		change func(*[5]bootstrapSpanV1, *bootstrapSpanV1, *bootstrapSpanV1)
		want   int32
	}{
		{"empty", func(in *[5]bootstrapSpanV1, _, _ *bootstrapSpanV1) { in[0].length = 0 }, 2},
		{"null", func(in *[5]bootstrapSpanV1, _, _ *bootstrapSpanV1) { in[0].pointer = nil }, 2},
		{"large", func(in *[5]bootstrapSpanV1, _, _ *bootstrapSpanV1) { in[0].length = 1405997 }, 4},
		{"short-facts", func(_ *[5]bootstrapSpanV1, f, _ *bootstrapSpanV1) { f.length = 43 }, 4},
		{"short-selector", func(_ *[5]bootstrapSpanV1, _, a *bootstrapSpanV1) { a.length = 511 }, 4},
		{"overlap", func(in *[5]bootstrapSpanV1, f, _ *bootstrapSpanV1) { in[0].pointer = f.pointer }, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			in, f, as := inputs, factSpan, activeSpan
			test.change(&in, &f, &as)
			s := bootstrapProductionBindingV1(in, f, as, &a, disconnectedSpan, &d)
			if s != test.want {
				t.Fatalf("status=%d want=%d", s, test.want)
			}
			if !bytes.Equal(facts, bytes.Repeat([]byte{0xa5}, 44)) || !bytes.Equal(active, bytes.Repeat([]byte{0xb6}, 512)) || !bytes.Equal(disconnected, bytes.Repeat([]byte{0xc7}, 512)) {
				t.Fatal("preflight wrote result")
			}
		})
	}
	if s := bootstrapProductionBindingV1(inputs, factSpan, activeSpan, &a, disconnectedSpan, &d); s == 0 || a != 0 || d != 0 {
		t.Fatalf("malformed material success/status=%d metadata=%d/%d", s, a, d)
	}
}

func TestBootstrapBindingV1PrivateDistinctRoleOutputs(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "recovery")
	now := time.Now().UTC().Truncate(time.Second)
	pass := []byte("local private boundary fixture recovery phrase")
	if _, err := selfhost.Initialize(selfhost.InitOptions{DataDir: dir, DeploymentName: "paired-roles", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: pass, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(dir, recovery, pass, now); err != nil {
		t.Fatal(err)
	}
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivateFixture(&private)
	rq, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := enrollment.EncodePrivateBundleV1(private)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pk)
	services := &runtimepolicy.ServicesV1{Version: 1, Probes: &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{
		{ID: 2, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{2}, TimeoutMillis: 1000},
		{ID: 10, Address: []byte{1, 1, 1, 1}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1}, TimeoutMillis: 1000},
	}, MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 10, MaxOperationMillis: 30000}}
	issued, err := selfhost.CreateProfile(dir, selfhost.CreateProfileOptions{Name: "paired-device", ValidFor: 12 * time.Hour, Now: now, RecipientRequest: rq, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: filepath.Join(base, "registry"), Services: services})
	if err != nil {
		t.Fatal(err)
	}
	session, err := selfhost.NewAndroidLiveActivationSessionForRecipient(issued.Artifact, now, lifecycle.VerifiedState{}, request, private)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()
	var staged profile.ActivationRecord
	for {
		command, ok := session.Next()
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
		if err := session.Submit(command, result); err != nil {
			t.Fatal(err)
		}
	}
	record, err := session.Result()
	if err != nil {
		t.Fatal(err)
	}
	activation, err := androidbridge.EncodeActivationRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	verify, err := androidbridge.EncodeVerifyRequest(androidbridge.VerifyRequest{Ingress: envelope.IngressFile, Class: envelope.ArtifactDeviceRecipient, Parts: [][]byte{issued.Artifact}})
	if err != nil {
		t.Fatal(err)
	}
	settings, err := hex.DecodeString("4b50533101000000000000510100000100000000000301010005dc0000000001000000000002000100010100030303012c0100008000500000000102012a382a390410012c0020001e0001000100000000")
	if err != nil {
		t.Fatal(err)
	}
	rows := [5][]byte{verify, activation, rq, pk, settings}
	var spans [5]bootstrapSpanV1
	for i, row := range rows {
		spans[i] = bootstrapSpanV1{unsafe.Pointer(&row[0]), uint32(len(row))}
	}
	facts := make([]byte, 44)
	active, disconnected := make([]byte, 512), make([]byte, 512)
	var an, dn uint32
	status := bootstrapProductionBindingV1(spans, bootstrapSpanV1{unsafe.Pointer(&facts[0]), 44}, bootstrapSpanV1{unsafe.Pointer(&active[0]), 512}, &an, bootstrapSpanV1{unsafe.Pointer(&disconnected[0]), 512}, &dn)
	if status != 0 {
		t.Fatal("genuine private role calculation", status)
	}
	// Independent literal catalogue tails distinguish lane placement. Both have
	// one signed strategy, then one probe; no helper computes these expectations.
	strategy := append([]byte{1, 23}, []byte("strategy-kurd-tls13-tcp")...)
	wantActive := append(bytes.Clone(strategy), 1, 7)
	wantActive = append(wantActive, []byte("probe-2")...)
	wantDisconnected := append(bytes.Clone(strategy), 1, 8)
	wantDisconnected = append(wantDisconnected, []byte("probe-10")...)
	if an != uint32(52+len(wantActive)) || dn != uint32(52+len(wantDisconnected)) || !bytes.Equal(active[52:an], wantActive) || !bytes.Equal(disconnected[52:dn], wantDisconnected) {
		t.Fatalf("private role lanes swapped/malformed: %x / %x", active[52:an], disconnected[52:dn])
	}
	for _, catalog := range [][]byte{active[:an], disconnected[:dn]} {
		if string(catalog[:4]) != "KPA1" || binary.BigEndian.Uint64(catalog[12:20]) != binary.BigEndian.Uint64(facts[:8]) || !bytes.Equal(catalog[20:52], facts[8:40]) {
			t.Fatal("private role facts binding")
		}
	}
}
