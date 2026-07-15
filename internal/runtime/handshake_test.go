// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

type preEntropyTrustV1 struct {
	calls *int
	base  auth.TrustProvider
}

func (p preEntropyTrustV1) Peer(id string) (ed25519.PublicKey, error) {
	*p.calls++
	return p.base.Peer(id)
}

func TestPreEntropyVersionStructuredAdmission(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, "canonical_v1", "strict_suite_and_capabilities", "strict_required")
	tests := []struct {
		name   string
		mutate func(*ImplementationSupportV1)
	}{
		{"schema", func(v *ImplementationSupportV1) { v.schemaVersions = []string{"unsupported"} }},
		{"security", func(v *ImplementationSupportV1) { v.securityVersions = []string{"unsupported"} }},
		{"compiler-security", func(v *ImplementationSupportV1) { v.compilerSecurityVersions = []string{"unsupported"} }},
		{"minimum-runtime", func(v *ImplementationSupportV1) { v.minimumRuntimeVersions = []string{"unsupported"} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := reviewedClientImplementationSupportV1.clone()
			tc.mutate(&client)
			entropy := &countingEntropyV1{fail: true}
			runtime := strictRuntimeForFixtureV1(t, fixture, client, reviewedRelayImplementationSupportV1, entropy)
			identityCalls, trustCalls := 0, 0
			runtime.clientDependencies.Identity = &callbackIdentityV1{base: runtime.clientDependencies.Identity, call: func() { identityCalls++ }}
			runtime.clientDependencies.Trust = preEntropyTrustV1{&trustCalls, runtime.clientDependencies.Trust}
			runtime.serverDependencies.Identity = &callbackIdentityV1{base: runtime.serverDependencies.Identity, call: func() { identityCalls++ }}
			runtime.serverDependencies.Trust = preEntropyTrustV1{&trustCalls, runtime.serverDependencies.Trust}
			beforeGeneration, beforeSeen, beforeID, beforeHash, beforePending := runtime.profileGeneration, runtime.profileSeen, runtime.profileID, runtime.profileHash, len(runtime.pendingPairMaterials)
			result, err := runtime.FirstContact(fixture.input)
			if !errors.Is(err, ErrProfileIncompatible) || identityCalls != 0 || trustCalls != 0 || entropy.reads != 0 {
				t.Fatalf("err=%v identity=%d trust=%d entropy=%d", err, identityCalls, trustCalls, entropy.reads)
			}
			assertRuntimeClosed(t, result)
			if len(result.ChannelSecret) != 0 || result.TranscriptHash != ([32]byte{}) {
				t.Fatal("preflight failure exposed sensitive result")
			}
			if runtime.profileGeneration != beforeGeneration || runtime.profileSeen != beforeSeen || runtime.profileID != beforeID || runtime.profileHash != beforeHash || len(runtime.pendingPairMaterials) != beforePending || runtime.strictEntropyFailed {
				t.Fatal("preflight failure changed lifecycle/pending/observer-visible state")
			}
			// The same-runtime valid retry proves the rejected attempt neither entered
			// replay nor committed lifecycle/KDF state.
			entropy.fail = false
			identityCalls, trustCalls = 0, 0
			clientOK := reviewedClientImplementationSupportV1.clone()
			runtime.clientSupport = clientOK
			control, controlErr := runtime.FirstContact(fixture.input)
			if controlErr != nil || len(control.ChannelSecret) == 0 || identityCalls == 0 || trustCalls == 0 {
				t.Fatalf("valid retry err=%v secret=%d identity=%d trust=%d", controlErr, len(control.ChannelSecret), identityCalls, trustCalls)
			}
			clear(control.ChannelSecret)
		})
	}
}

func TestPreEntropyVersionSealedProfileProvenance(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, "canonical_v1", "strict_suite_and_capabilities", "strict_required")
	entropy := &countingEntropyV1{fail: true}
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
	identityCalls := 0
	trustCalls := 0
	runtime.clientDependencies.Identity = &callbackIdentityV1{base: runtime.clientDependencies.Identity, call: func() { identityCalls++ }}
	runtime.clientDependencies.Trust = preEntropyTrustV1{&trustCalls, runtime.clientDependencies.Trust}
	runtime.serverDependencies.Identity = &callbackIdentityV1{base: runtime.serverDependencies.Identity, call: func() { identityCalls++ }}
	runtime.serverDependencies.Trust = preEntropyTrustV1{&trustCalls, runtime.serverDependencies.Trust}
	mutated := fixture.input
	mutated.Client.ProfileHash[0] ^= 1
	result, err := runtime.FirstContact(mutated)
	if !errors.Is(err, ErrProfileMismatch) || identityCalls != 0 || trustCalls != 0 || entropy.reads != 0 {
		t.Fatalf("err=%v identity=%d trust=%d entropy=%d", err, identityCalls, trustCalls, entropy.reads)
	}
	assertRuntimeClosed(t, result)
	if len(result.ChannelSecret) != 0 || result.TranscriptHash != ([32]byte{}) || runtime.profileSeen || runtime.profileGeneration != 0 || len(runtime.pendingPairMaterials) != 0 || runtime.strictEntropyFailed {
		t.Fatal("provenance rejection entered KDF/replay/lifecycle/observer-visible state")
	}
	entropy.fail = false
	identityCalls, trustCalls = 0, 0
	retry, retryErr := runtime.FirstContact(fixture.input)
	if retryErr != nil || len(retry.ChannelSecret) == 0 || identityCalls == 0 || trustCalls == 0 {
		t.Fatalf("provenance valid retry err=%v secret=%d identity=%d trust=%d", retryErr, len(retry.ChannelSecret), identityCalls, trustCalls)
	}
	clear(retry.ChannelSecret)
	controlEntropy := &countingEntropyV1{}
	control := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, controlEntropy)
	result, err = control.FirstContact(fixture.input)
	if err != nil || controlEntropy.reads == 0 || len(result.ChannelSecret) == 0 {
		t.Fatalf("current control err=%v reads=%d secret=%d", err, controlEntropy.reads, len(result.ChannelSecret))
	}
	clear(result.ChannelSecret)
}

func TestPreEntropyVersionSourceOrderingAndNoObserverOwner(t *testing.T) {
	raw, err := os.ReadFile("handshake.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	preflight := strings.Index(text, "verifySupportAndAuthorizationPreflightV1(snapshot, view)")
	entropy := strings.Index(text, "ensureStrictEpochV1()")
	authCall := strings.Index(text, "auth.FirstContact(snapshot)")
	if preflight < 0 || entropy <= preflight || authCall <= entropy {
		t.Fatalf("strict ordering preflight=%d entropy=%d auth=%d", preflight, entropy, authCall)
	}
	if strings.Contains(text[:authCall], "observer") || strings.Contains(text[:authCall], "Observe(") {
		t.Fatal("observer reachable before auth admission")
	}
}

func TestPreEntropyVersionOwnerEvidenceClassification(t *testing.T) {
	// This frozen inventory prevents observable/transitive evidence from being
	// mislabeled as an injected counter. Observer is explicitly absent from the
	// scoped structured handshake path.
	want := map[string]string{
		"entropy":               "direct fail-if-called counter",
		"client identity/trust": "direct fail-if-called counter",
		"relay identity/trust":  "direct fail-if-called counter",
		"handshake KDF":         "transitively unreachable before auth.FirstContact",
		"replay":                "observable by same-runtime valid retry",
		"lifecycle":             "observable by pristine runtime state",
		"observer":              "not present on scoped path",
	}
	if len(want) != 7 {
		t.Fatal("owner evidence inventory cardinality")
	}
	for owner, evidence := range want {
		if owner == "" || evidence == "" {
			t.Fatal("empty owner evidence classification")
		}
	}
	raw, err := os.ReadFile("handshake.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start := strings.Index(text, "func (r *HandshakeRuntime) strictFirstContactWithContextV1")
	if start < 0 {
		t.Fatal("strict path source start")
	}
	end := strings.Index(text[start:], "func strictPreflightSentinelV1")
	if end < 0 {
		t.Fatal("strict path source end")
	}
	scoped := text[start : start+end]
	for _, observerCall := range []string{"observer.", "Observe(", "Notify(", "Emit("} {
		if strings.Contains(scoped, observerCall) {
			t.Fatalf("observer classification drifted: %s", observerCall)
		}
	}
}

type handshakeIdentity struct {
	id  string
	key ed25519.PrivateKey
}

func (p handshakeIdentity) Local(id string) (ed25519.PrivateKey, error) {
	if id != p.id {
		return nil, errors.New("unknown")
	}
	return append(ed25519.PrivateKey(nil), p.key...), nil
}

type handshakeTrust struct {
	id  string
	key ed25519.PublicKey
}

func (p handshakeTrust) Peer(id string) (ed25519.PublicKey, error) {
	if id != p.id {
		return nil, errors.New("unknown")
	}
	return append(ed25519.PublicKey(nil), p.key...), nil
}

func TestRuntimeAuthenticatedFirstContactOwnsReplayScopeAcrossConnections(t *testing.T) {
	p, err := compiler.Generate(6201)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = "canonical_full_binding_v1"
	p.Security.CapabilityNegotiationPolicy = "intersection_with_required"
	p.Security.DowngradePolicy = "strict_capabilities"
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	known := ir.SecurityCapabilities()
	floor := append([]string(nil), known[:1]...)
	selected := append([]string(nil), known[:3]...)
	policy, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, selected)
	if err != nil {
		t.Fatal(err)
	}
	client, err := auth.NewPeerParameters("runtime-client", p, policy, policy, selected, floor)
	if err != nil {
		t.Fatal(err)
	}
	server, err := auth.NewPeerParameters("runtime-server", p, policy, policy, selected, floor)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for i := range clientPrivate {
			clientPrivate[i] = 0
		}
		for i := range serverPrivate {
			serverPrivate[i] = 0
		}
	})
	input := auth.FirstContactInput{
		Client: client, Server: server, SelectedPolicy: policy, SelectedCapabilities: selected,
	}
	clientDependencies := auth.Dependencies{Identity: handshakeIdentity{"runtime-client", clientPrivate}, Trust: handshakeTrust{"runtime-server", serverPublic}}
	serverDependencies := auth.Dependencies{Identity: handshakeIdentity{"runtime-server", serverPrivate}, Trust: handshakeTrust{"runtime-client", clientPublic}}
	runtime, err := NewHandshakeRuntime(clientDependencies, serverDependencies)
	if err != nil {
		t.Fatal(err)
	}
	// Per-call identity/trust substitution is ignored by the normal runtime;
	// runtime construction owns these dependencies for its full lifetime.
	input.ClientDependencies = auth.Dependencies{Identity: handshakeIdentity{"wrong", serverPrivate}, Trust: handshakeTrust{"wrong", clientPublic}}
	input.ServerDependencies = auth.Dependencies{Identity: handshakeIdentity{"wrong", clientPrivate}, Trust: handshakeTrust{"wrong", serverPublic}}
	first, err := runtime.FirstContact(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runtime.FirstContact(input)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.ChannelSecret, second.ChannelSecret) || first.ClientNonce == second.ClientNonce || first.ServerNonce == second.ServerNonce {
		t.Fatal("runtime connection attempts did not receive independent authenticated session material")
	}
	if first.ClientPublic == second.ClientPublic || first.ServerPublic == second.ServerPublic || first.ClientPublic == first.ServerPublic || second.ClientPublic == second.ServerPublic {
		t.Fatal("runtime connections reused or cross-shared X25519 public contributions")
	}
	if runtime.replay == nil {
		t.Fatal("runtime did not retain its cross-connection replay scope")
	}
	replayed := input
	replayed.InboundClientHello = append([]byte(nil), first.Messages[0]...)
	replayResult, err := runtime.FirstContact(replayed)
	assertRuntimeHandshakeCode(t, err, auth.FailureReplay)
	assertRuntimeClosed(t, replayResult)

	restarted, err := NewHandshakeRuntime(clientDependencies, serverDependencies)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.epoch == restarted.epoch || zeroRuntimeEpoch(runtime.epoch) || zeroRuntimeEpoch(restarted.epoch) {
		t.Fatal("runtime restart reused or omitted the local replay epoch")
	}
	restartReplayResult, err := restarted.FirstContact(replayed)
	assertRuntimeHandshakeCode(t, err, auth.FailureProfileMismatch)
	assertRuntimeClosed(t, restartReplayResult)
	freshAfterRestart, err := restarted.FirstContact(input)
	if err != nil {
		t.Fatal(err)
	}
	if freshAfterRestart.ClientNonce == first.ClientNonce || freshAfterRestart.ServerNonce == first.ServerNonce {
		t.Fatal("restart did not require fresh contributions")
	}
	if freshAfterRestart.ClientPublic == first.ClientPublic || freshAfterRestart.ServerPublic == first.ServerPublic || freshAfterRestart.ClientPublic == freshAfterRestart.ServerPublic {
		t.Fatal("restart reused or cross-shared X25519 public contributions")
	}
}

func TestHandshakeRuntimeRejectsMissingZeroAndFailedEpochEntropy(t *testing.T) {
	fixture := runtimeDependenciesFixture(t)
	if _, err := newHandshakeRuntime(fixture.client, fixture.server, bytes.NewReader(make([]byte, 32))); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("zero runtime epoch error = %v", err)
	}
	if _, err := newHandshakeRuntime(fixture.client, fixture.server, bytes.NewReader(nil)); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("failed runtime entropy error = %v", err)
	}
	if _, err := NewHandshakeRuntime(auth.Dependencies{}, fixture.server); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("missing runtime dependency error = %v", err)
	}
}

type runtimeDependencyFixture struct {
	client auth.Dependencies
	server auth.Dependencies
}

func runtimeDependenciesFixture(t *testing.T) runtimeDependencyFixture {
	t.Helper()
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for i := range clientPrivate {
			clientPrivate[i] = 0
		}
		for i := range serverPrivate {
			serverPrivate[i] = 0
		}
	})
	return runtimeDependencyFixture{
		client: auth.Dependencies{Identity: handshakeIdentity{"runtime-client", clientPrivate}, Trust: handshakeTrust{"runtime-server", serverPublic}},
		server: auth.Dependencies{Identity: handshakeIdentity{"runtime-server", serverPrivate}, Trust: handshakeTrust{"runtime-client", clientPublic}},
	}
}

func assertRuntimeHandshakeCode(t *testing.T, err error, code auth.FailureCode) {
	t.Helper()
	var typed *auth.HandshakeError
	if !errors.Is(err, auth.ErrHandshake) || !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("runtime handshake error = %v, want %s", err, code)
	}
}

func TestRuntimeFirstContactRejectsMissingRuntime(t *testing.T) {
	var runtime *HandshakeRuntime
	result, err := runtime.FirstContact(auth.FirstContactInput{})
	if !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("nil runtime error = %v", err)
	}
	assertRuntimeClosed(t, result)
}

func assertRuntimeClosed(t *testing.T, result auth.FirstContactResult) {
	t.Helper()
	if result.ClientState != auth.StateClosed || result.ServerState != auth.StateClosed || len(result.ChannelSecret) != 0 {
		t.Fatalf("runtime failure state = %s/%s with %d secret bytes", result.ClientState, result.ServerState, len(result.ChannelSecret))
	}
}
