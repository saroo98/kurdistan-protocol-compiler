// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bytes"
	"crypto/rand"
	"errors"
	"github.com/fxamacker/cbor/v2"
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
	"kurdistan/internal/selfhost"
	"path/filepath"
	"testing"
	"time"
)

func TestDecodeLegacyBootstrapPolicyV1CanonicalSentinelsAndCallerPreservation(t *testing.T) {
	wire, err := encodeRuntimePolicyOnly(RuntimePolicyRequest{MTU: 1280, SelectionMode: RuntimeSelectionAutomatic, PerAppMode: RuntimePerAppAllApps, IPMode: RuntimeIPAuto, DNSMode: RuntimeDNSInternal})
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(wire)
	policy, err := DecodeLegacyBootstrapPolicyV1(wire)
	if err != nil || policy.MTU != 1280 || !bytes.Equal(wire, before) {
		t.Fatalf("policy parity: %v", err)
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[len(p)-1] = 2 }, func(p []byte) { p[len(p)-2] = 2 },
		func(p []byte) { p[21] = 2 }, func(p []byte) { p[25] = 2 },
		func(p []byte) { p[5] = 255 },
	} {
		bad := bytes.Clone(wire)
		mutate(bad)
		copyBefore := bytes.Clone(bad)
		if _, err := DecodeLegacyBootstrapPolicyV1(bad); err == nil {
			t.Fatal("invalid policy accepted")
		}
		if !bytes.Equal(bad, copyBefore) {
			t.Fatal("caller input changed")
		}
	}
	if _, err := DecodeLegacyBootstrapPolicyV1(make([]byte, 16778)); err == nil {
		t.Fatal("oversize accepted")
	}
}

type bootstrapLegacyEnvironmentV1 struct {
	now                             time.Time
	calls, boundedCalls, trustCalls int
	mutateBounds                    func(*selfhost.LiveMaintenanceBounds)
	ownedLeaves                     [][]byte
	failureAfter                    error
}

func (e *bootstrapLegacyEnvironmentV1) VerifyWithRecipientAt(a []byte, class envelope.ArtifactClass, c RecipientCredentials, now time.Time, limits selfhost.LiveMaintenanceLimits) (profile.OfflineVerifiedArtifact, selfhost.LiveMaintenanceBounds, error) {
	e.boundedCalls++
	defer c.Destroy()
	v, b, err := selfhost.VerifyLiveMaintenanceCurrentForRecipient(a, now, 1, c.Request, c.Private, limits)
	e.ownedLeaves = [][]byte{a, c.Request.RecipientPublic, c.Request.ClientAuthPublic, c.Request.Nonce, c.Request.Signature, c.Private.RecipientPrivate, c.Private.ClientAuthSeed, v.ExactArtifact, v.ExactSignedObject, v.Profile.Policy}
	if err == nil && e.mutateBounds != nil {
		e.mutateBounds(&b)
	}
	if err == nil && e.failureAfter != nil {
		err = e.failureAfter
	}
	return v, b, err
}
func (e *bootstrapLegacyEnvironmentV1) TrustPreviewWithRecipient(a []byte, class envelope.ArtifactClass, c RecipientCredentials) (TrustPreview, error) {
	e.trustCalls++
	defer c.Destroy()
	return TrustPreview{}, nil
}
func (e *bootstrapLegacyEnvironmentV1) VerifyWithRecipient(a []byte, class envelope.ArtifactClass, c RecipientCredentials) (profile.OfflineVerifiedArtifact, error) {
	e.calls++
	defer c.Destroy()
	_, v, err := selfhost.VerifyLiveBundleForRecipient(a, e.now, 1, c.Request, c.Private)
	return v, err
}
func TestReadLegacyRuntimeBootstrapBindingV1ObservedCapacityViolation(t *testing.T) {
	f := bootstrapSignedFixtureV1(t, nil)
	e := &bootstrapLegacyEnvironmentV1{mutateBounds: func(b *selfhost.LiveMaintenanceBounds) { b.PeakReservedBytes = b.BudgetBytes + 1 }}
	facts, code := ReadLegacyRuntimeBootstrapBindingV1(f.current, RuntimePolicyRequest{}, e, f.now, selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 128 << 20, MaxArtifactBytes: 1052763, MaxPublicationBytes: 1052763})
	if code != ErrorCode(-6401) || facts != (RuntimeBootstrapBindingV1{}) {
		t.Fatalf("capacity violation lost private signal: %d", code)
	}
	if e.boundedCalls != 1 || e.calls != 0 || e.trustCalls != 0 {
		t.Fatal("wrong verifier path")
	}
	for _, leaf := range e.ownedLeaves {
		if !bytes.Equal(leaf, make([]byte, len(leaf))) {
			t.Fatal("capacity failure retained owned material")
		}
	}
}

func TestBootstrapObservedPlanCapacityV1UsesBackingCapacity(t *testing.T) {
	f := bootstrapSignedFixtureV1(t, nil)
	policy, err := runtimepolicy.DecodeV2At(f.record.Profile.Policy, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Destroy()
	plan, err := sessionplan.BuildV2At(sessionplan.RequestV2{Profile: f.record.Profile, ActivationReceipt: f.record.State.Receipt, RuntimePolicy: policy}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Destroy()
	bounds, ok := sessionplan.AdmittedCalculationBoundsV2(envelope.MaxPayloadBytes)
	if !ok {
		t.Fatal("bound unavailable")
	}
	if bootstrapObservedPlanCapacityV1(&plan, bounds.PlanBytes) != 0 {
		t.Fatal("real plan rejected")
	}
	old := plan.Endpoints[0].Address
	plan.Endpoints[0].Address = make([]byte, len(old), int(bounds.PlanBytes)+1)
	copy(plan.Endpoints[0].Address, old)
	clear(old)
	if status := bootstrapObservedPlanCapacityV1(&plan, bounds.PlanBytes); status != -6401 {
		t.Fatal("actual plan capacity overrun did not signal", status)
	}
}

func TestReadLegacyRuntimeBootstrapBindingV1ExactFailuresAndOwnedCleanup(t *testing.T) {
	f := bootstrapSignedFixtureV1(t, nil)
	policy := RuntimePolicyRequest{SelectionMode: RuntimeSelectionAutomatic, PerAppMode: RuntimePerAppAllApps, IPMode: RuntimeIPV4Only, DNSMode: RuntimeDNSInternal, MTU: 1280}
	for _, test := range []struct {
		name  string
		want  ErrorCode
		calls int
	}{
		{"nil-environment", CodeTrustUnavailable, 0}, {"zero-time", CodeTrustUnavailable, 0},
		{"zero-budget", CodeResourceLimit, 0}, {"insufficient-budget", CodeResourceLimit, 0},
		{"empty-input", CodeInvalidArgument, 0}, {"artifact-limit", CodeSizeLimit, 0},
		{"bounds-identity", CodeInternalFailure, 1}, {"bounds-zero-retained", CodeInternalFailure, 1}, {"bounds-retained-over-peak", CodeInternalFailure, 1},
		{"unknown-error-with-graph", CodeInternalFailure, 1}, {"expired", CodeVerificationRejected, 1}, {"suffix-policy", CodePolicyRejected, 1}, {"typed-root-der-shape", CodeInvalidArgument, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := &bootstrapLegacyEnvironmentV1{}
			var environment RecipientVerificationEnvironmentAt = e
			input := f.current
			now := f.now
			p := policy
			limits := selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 128 << 20, MaxArtifactBytes: 1052763, MaxPublicationBytes: 1052763}
			switch test.name {
			case "nil-environment":
				environment = nil
			case "zero-time":
				now = time.Time{}
			case "zero-budget":
				limits.OwnedBudgetBytes = 0
			case "insufficient-budget":
				limits.OwnedBudgetBytes = 1
			case "empty-input":
				input.VerifyRequest = nil
			case "artifact-limit":
				limits.MaxArtifactBytes = uint32(len(f.artifact) - 1)
			case "bounds-identity":
				e.mutateBounds = func(b *selfhost.LiveMaintenanceBounds) { b.BudgetBytes-- }
			case "bounds-zero-retained":
				e.mutateBounds = func(b *selfhost.LiveMaintenanceBounds) { b.RetainedBytes = 0 }
			case "bounds-retained-over-peak":
				e.mutateBounds = func(b *selfhost.LiveMaintenanceBounds) { b.RetainedBytes = b.PeakReservedBytes + 1 }
			case "unknown-error-with-graph":
				e.failureAfter = errors.New("test unknown verifier failure")
			case "expired":
				now = now.Add(24 * time.Hour)
			case "suffix-policy":
				p.MTU = 1279
			case "typed-root-der-shape":
				// Keep the canonical 14-field bundle intact except its root DER row:
				// the bounded typed shape requires exactly 91 bytes, not 92.
				var fields []cbor.RawMessage
				if err := cbor.Unmarshal(f.artifact, &fields); err != nil || len(fields) != 14 {
					t.Fatal("bundle fixture", err)
				}
				fields[3], _ = cbor.Marshal(make([]byte, 92))
				mode, _ := cbor.CoreDetEncOptions().EncMode()
				bad, err := mode.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(bad)
				input.VerifyRequest, err = EncodeVerifyRequest(VerifyRequest{Ingress: envelope.IngressFile, Class: envelope.ArtifactDeviceRecipient, Parts: [][]byte{bad}})
				if err != nil {
					t.Fatal(err)
				}
				defer clear(input.VerifyRequest)
			}
			original := productionInputPartsV1(input)
			before := make([][]byte, len(original))
			for i := range original {
				before[i] = bytes.Clone(original[i])
			}
			facts, code := ReadLegacyRuntimeBootstrapBindingV1(input, p, environment, now, limits)
			if code != test.want || facts != (RuntimeBootstrapBindingV1{}) {
				t.Fatalf("got %d want %d, facts=%+v", code, test.want, facts)
			}
			if e.boundedCalls != test.calls || e.calls != 0 || e.trustCalls != 0 {
				t.Fatal("unexpected unbounded/trust work or preflight ordering")
			}
			for _, leaf := range e.ownedLeaves {
				if !bytes.Equal(leaf, make([]byte, len(leaf))) {
					t.Fatal("owned input/credential/verified leaf retained")
				}
			}
			for i := range original {
				if !bytes.Equal(original[i], before[i]) {
					t.Fatal("caller input changed")
				}
			}
		})
	}
}

func TestLegacyBootstrapMaintenanceStatusV1ClosedMapping(t *testing.T) {
	for _, test := range []struct {
		input MaintenanceResultV1
		want  ErrorCode
	}{
		{MaintenanceSuccess, CodeOK}, {MaintenanceInvalidRequest, CodeInvalidArgument}, {MaintenanceSizeLimit, CodeSizeLimit}, {MaintenanceResourceLimit, CodeResourceLimit},
		{MaintenanceNotAdmitted, CodeVerificationRejected}, {MaintenanceInvalidState, CodeVerificationRejected}, {MaintenanceSignatureInvalid, CodeVerificationRejected}, {MaintenanceWrongRecipient, CodeVerificationRejected}, {MaintenanceProfileMismatch, CodeVerificationRejected}, {MaintenanceRollback, CodeVerificationRejected}, {MaintenanceExpired, CodeVerificationRejected}, {MaintenanceRevoked, CodeVerificationRejected}, {MaintenanceIncompatible, CodeVerificationRejected}, {MaintenanceRootRotationRejected, CodeVerificationRejected},
		{MaintenanceRateLimited, CodeVerificationRejected}, {MaintenanceCancelled, CodeVerificationRejected}, {MaintenanceTimeout, CodeVerificationRejected}, {MaintenanceNetworkUnavailable, CodeVerificationRejected}, {MaintenanceDestinationDenied, CodeVerificationRejected}, {MaintenanceTLSTrustUnavailable, CodeVerificationRejected}, {MaintenanceTLSRejected, CodeVerificationRejected},
		{MaintenanceInternalFailure, CodeInternalFailure}, {MaintenanceNoChange, CodeInternalFailure}, {MaintenanceFetchRejected, CodeInternalFailure}, {MaintenanceResultV1(255), CodeInternalFailure},
	} {
		if got := legacyBootstrapMaintenanceStatusV1(test.input); got != test.want {
			t.Fatalf("%d => %d want %d", test.input, got, test.want)
		}
	}
}
func TestReadLegacyRuntimeBootstrapBindingV1ParityAndRejection(t *testing.T) {
	f := bootstrapSignedFixtureV1(t, nil)
	policy := RuntimePolicyRequest{SelectionMode: RuntimeSelectionAutomatic, PerAppMode: RuntimePerAppAllApps, IPMode: RuntimeIPV4Only, DNSMode: RuntimeDNSInternal, MTU: 1280}
	e := &bootstrapLegacyEnvironmentV1{now: f.now}
	input := f.current
	wire, err := EncodeRuntimeOpenRequestV2(RuntimeOpenRequestV2{input.VerifyRequest, input.ActivationRecord, input.RecipientRequest, input.RecipientPrivate, policy})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	registry := &HandleRegistry{}
	factory := &recordingRuntimeNetworkFactory{}
	h, snapshot, code := OpenRuntimeSessionV2(registry, wire, e, factory, f.now)
	if code != CodeOK {
		t.Fatal("legacy fixture", code)
	}
	defer RuntimeStop(registry, h)
	limits := selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 128 << 20, MaxArtifactBytes: 1052763, MaxPublicationBytes: 1052763}
	facts, code := ReadLegacyRuntimeBootstrapBindingV1(input, policy, e, f.now, limits)
	if code != CodeOK || facts.Generation != snapshot.Generation || facts.PlanDigest != snapshot.PlanDigest || facts.SignedRetryMaximum != snapshot.MaxReconnectAttempts {
		t.Fatal("binding differs from legacy open", code)
	}
	if snapshot.MTU != 1280 {
		t.Fatal("version-one bootstrap effective MTU constraint drift", snapshot.MTU)
	}
	if e.calls != 1 || e.boundedCalls != 1 || e.trustCalls != 1 || len(factory.network.calls()) != 0 {
		t.Fatal("unexpected calculation/transport work")
	}
	for _, leaf := range e.ownedLeaves {
		if !bytes.Equal(leaf, make([]byte, len(leaf))) {
			t.Fatal("successful read retained temporary owned material")
		}
	}
	for _, part := range []int{0, 1, 2, 3} {
		rows := productionInputPartsV1(input)
		rows[part] = bytes.Clone(rows[part])
		rows[part][len(rows[part])-1] ^= 1
		rejected, status := ReadLegacyRuntimeBootstrapBindingV1(MaintenanceCurrentInputV1{rows[0], rows[1], rows[2], rows[3]}, policy, e, f.now, limits)
		if status == CodeOK || rejected != (RuntimeBootstrapBindingV1{}) {
			t.Fatal("malformed material published facts", part, status)
		}
	}
	rejected, status := ReadLegacyRuntimeBootstrapBindingV1(input, policy, e, f.now.Add(24*time.Hour), limits)
	if status == CodeOK || rejected != (RuntimeBootstrapBindingV1{}) {
		t.Fatal("expired binding", status)
	}
}
func bootstrapSignedFixtureV1(t *testing.T, services *runtimepolicy.ServicesV1) maintenanceSignedFixture {
	t.Helper()
	base := t.TempDir()
	dir, recovery := filepath.Join(base, "node"), filepath.Join(base, "recovery")
	now := time.Unix(1780000062, 0).UTC()
	pass := []byte("local maintenance integration recovery phrase")
	if _, e := selfhost.Initialize(selfhost.InitOptions{DataDir: dir, DeploymentName: "maintenance-host", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: pass, Now: now.Add(-2 * time.Minute)}); e != nil {
		t.Fatal("initialize", e)
	}
	if e := selfhost.ConfirmRecovery(dir, recovery, pass, now.Add(-time.Minute)); e != nil {
		t.Fatal("confirm", e)
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
	wireProgram, e := liveprogram.EncodeV1(program)
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
	issued, e := selfhost.CreateProfile(dir, selfhost.CreateProfileOptions{Name: "host-device", ValidFor: 12 * time.Hour, Now: now, RecipientRequest: requestWire, LiveProgram: wireProgram, RegistryDir: filepath.Join(base, "registry"), Services: services})
	if e != nil {
		t.Fatal("create", e)
	}
	session, e := selfhost.NewAndroidLiveActivationSessionForRecipient(issued.Artifact, now, lifecycle.VerifiedState{}, request, private)
	if e != nil {
		t.Fatal("activation", e)
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
		if e = session.Submit(command, result); e != nil {
			t.Fatal(e)
		}
	}
	record, e := session.Result()
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
	next, e := selfhost.RotateProfile(dir, selfhost.RotateProfileOptions{ProfileID: issued.ProfileID, RecoveryPath: recovery, RecoveryPassphrase: pass, Now: now.Add(time.Minute), ValidFor: 12 * time.Hour, LiveProgram: wireProgram, RegistryDir: filepath.Join(base, "registry")})
	if e != nil {
		t.Fatal("rotate", e)
	}
	return maintenanceSignedFixture{now: now.Add(time.Minute), current: MaintenanceCurrentInputV1{VerifyRequest: verifyWire, ActivationRecord: recordWire, RecipientRequest: requestWire, RecipientPrivate: privateWire}, artifact: issued.Artifact, replacement: next.Artifact, record: record}
}
