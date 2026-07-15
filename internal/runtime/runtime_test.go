// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/proxysem"
	"kurdistan/internal/runtime/labfault"
	"kurdistan/internal/transport/proxyadversary"
)

func TestRuntimeConfigValidationAndRedaction(t *testing.T) {
	cfg := DefaultConfig(RoleClient, "rt", []byte("secret"))
	if err := ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.SecuritySecret = make([]byte, 8)
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected all-zero secret rejection")
	}
	redacted := RedactConfig(DefaultConfig(RoleServer, "srv", []byte("supersecretvalue")))
	raw, _ := json.Marshal(redacted)
	if string(raw) == "" || strings.Contains(string(raw), "supersecretvalue") {
		t.Fatalf("redaction leaked secret: %s", raw)
	}
}

func TestProfileLoading(t *testing.T) {
	p := mustProfile(t, 13)
	path := filepath.Join(t.TempDir(), "profile.json")
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProfile(path, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != p.ID {
		t.Fatal("loaded wrong profile")
	}
	if _, err := LoadProfile(path, "wrong"); err == nil {
		t.Fatal("expected profile id mismatch")
	}
	if _, err := LoadProfile(filepath.Join(t.TempDir(), "missing.json"), ""); err == nil {
		t.Fatal("expected missing file failure")
	}
}

func TestMemoryLinkOrderingAndBounds(t *testing.T) {
	link := NewMemoryLink(1)
	frame := LinkFrame{Direction: "client_to_server", Sequence: 1, EnvelopeKind: "test"}
	if err := link.Send(frame); err != nil {
		t.Fatal(err)
	}
	if err := link.Send(frame); err != ErrLinkQueueFull {
		t.Fatalf("expected queue full, got %v", err)
	}
	got, err := link.Deliver("client_to_server")
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != 1 {
		t.Fatal("delivery order broken")
	}
	link.Close()
	if err := link.Send(frame); err != ErrLinkClosed {
		t.Fatalf("expected closed link rejection, got %v", err)
	}
}

func TestNormalBackpressureV1(t *testing.T) {
	link := NewMemoryLink(1)
	frames := []LinkFrame{{Direction: "client_to_server", Sequence: 1, EnvelopeKind: "synthetic_metadata"}, {Direction: "client_to_server", Sequence: 2, EnvelopeKind: "synthetic_metadata"}, {Direction: "client_to_server", Sequence: 3, EnvelopeKind: "synthetic_metadata"}}
	if err := link.Send(frames[0]); err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames[1:] {
		if err := link.Send(frame); err != ErrLinkQueueFull {
			t.Fatalf("normal send sentinel=%v", err)
		}
	}
	if link.QueueDepth("client_to_server") != 1 {
		t.Fatalf("normal depth=%d", link.QueueDepth("client_to_server"))
	}
	got, err := link.Deliver("client_to_server")
	if err != nil || got.Sequence != 1 || link.QueueDepth("client_to_server") != 0 {
		t.Fatalf("normal delivery=%+v depth=%d err=%v", got, link.QueueDepth("client_to_server"), err)
	}
}

func TestBackpressureFaultV1(t *testing.T) {
	token, _ := labfault.NewTokenV1("runtime_ignores_backpressure")
	link := newMemoryLinkWithLabFaultV1(1, token)
	if link == nil {
		t.Fatal("fault link rejected")
	}
	frames := []LinkFrame{{Direction: "client_to_server", Sequence: 1, EnvelopeKind: "synthetic_metadata"}, {Direction: "client_to_server", Sequence: 2, EnvelopeKind: "synthetic_metadata"}, {Direction: "client_to_server", Sequence: 3, EnvelopeKind: "synthetic_metadata"}}
	if err := link.Send(frames[0]); err != nil {
		t.Fatal(err)
	}
	if err := link.Send(frames[1]); err != nil {
		t.Fatal(err)
	}
	if err := link.Send(frames[2]); err != ErrLinkQueueFull {
		t.Fatalf("fault cap sentinel=%v", err)
	}
	if link.QueueDepth("client_to_server") != 2 {
		t.Fatalf("fault depth=%d", link.QueueDepth("client_to_server"))
	}
	for i := 1; i <= 2; i++ {
		got, err := link.Deliver("client_to_server")
		if err != nil || got.Sequence != uint64(i) {
			t.Fatalf("delivery %d=%+v err=%v", i, got, err)
		}
	}
	if link.QueueDepth("client_to_server") != 0 {
		t.Fatalf("terminal depth=%d", link.QueueDepth("client_to_server"))
	}
	if newMemoryLinkWithLabFaultV1(2, token) != nil {
		t.Fatal("invalid depth accepted")
	}
	wrong, _ := labfault.NewTokenV1("reused_nonce")
	if newMemoryLinkWithLabFaultV1(1, wrong) != nil || newMemoryLinkWithLabFaultV1(1, labfault.Token{}) != nil {
		t.Fatal("invalid token accepted")
	}
}

func TestBackpressureFaultPrecedenceV1(t *testing.T) {
	token, _ := labfault.NewTokenV1("runtime_ignores_backpressure")
	link := newMemoryLinkWithLabFaultV1(1, token)
	link.Close()
	link.InjectFailure()
	if err := link.Send(LinkFrame{}); err != ErrLinkClosed {
		t.Fatalf("closed precedence=%v", err)
	}
	if err := (*MemoryLink)(nil).Send(LinkFrame{}); !errors.Is(err, ErrLinkFailure) {
		t.Fatalf("nil precedence=%v", err)
	}
	link = newMemoryLinkWithLabFaultV1(1, token)
	link.InjectFailure()
	if err := link.Send(LinkFrame{}); err != ErrLinkFailure {
		t.Fatalf("injected precedence=%v", err)
	}
	if err := link.Send(LinkFrame{}); !errors.Is(err, ErrLinkFailure) {
		t.Fatalf("direction precedence=%v", err)
	}
	for _, direction := range []string{"client_to_server", "server_to_client"} {
		if err := link.Send(LinkFrame{Direction: direction, Sequence: 1, EnvelopeKind: "synthetic_metadata"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProtectedChannelLocalHarnessAndCompatibilityAllowlistV1(t *testing.T) {
	_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7850, "message_lifetime_bound", 16, 8)
	summary, err := runStrictCandidateHarnessV1(client, relay, []byte("local-strict-harness"))
	if err != nil {
		t.Fatal(err)
	}
	if summary.ApplicationRecords != 1 || summary.ControlRecords != 1 || summary.Deliveries != 1 ||
		summary.NonceDomains != 2 || summary.NonceAllocations != 2 || summary.NonceCollisions != 0 {
		t.Fatalf("strict harness summary=%+v", summary)
	}
	want := []string{"BuildSecurityContext", "NewSecureChannel", "Runtime", "Manager", "Session", "StreamManager", "RunAdapterBoundary", "TCP relay", "commands", "generated templates"}
	if strings.Join(strictCandidateCompatibilityAllowlistV1[:], "|") != strings.Join(want, "|") {
		t.Fatalf("strict candidate compatibility allowlist=%v", strictCandidateCompatibilityAllowlistV1)
	}
}

func TestNegotiationCompatibilityAndSecurityContext(t *testing.T) {
	p := mustProfile(t, 14)
	required := security.CapabilitySet{Features: p.Compatibility.RequiredCapabilities}
	result, err := NegotiateCapabilities(security.DefaultCapabilities(), security.DefaultCapabilities(), required)
	if err != nil {
		t.Fatal(err)
	}
	if result.CapabilityHash == "" {
		t.Fatal("missing capability hash")
	}
	if _, err := NegotiateCapabilities(security.DefaultCapabilities(), security.CapabilitySet{Features: []string{"multi_stream"}}, required); err == nil {
		t.Fatal("expected capability downgrade rejection")
	}
	ctx, _, err := BuildSecurityContext(p, result.Selected, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	other := *p
	other.CarrierPolicy.CarrierFamily = "message_carrier"
	other.GenerationHash = ""
	ctx2, _, err := BuildSecurityContext(&other, result.Selected, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if ctx.TranscriptHash == ctx2.TranscriptHash {
		t.Fatal("carrier policy mismatch did not change transcript hash")
	}
}

func TestBilateralNegotiationFloorsAndCanonicalSelection(t *testing.T) {
	base := BilateralNegotiationInput{
		LocalOffer:                  security.CapabilitySet{Features: []string{"proxy_semantics", "carrier_abstraction", "multi_stream"}},
		PeerOffer:                   security.CapabilitySet{Features: []string{"nonce_schedule", "multi_stream", "carrier_abstraction", "proxy_semantics"}},
		LocalFloor:                  security.CapabilitySet{Features: []string{"multi_stream"}},
		PeerFloor:                   security.CapabilitySet{Features: []string{"proxy_semantics"}},
		CapabilityNegotiationPolicy: "intersection_with_required",
		DowngradePolicy:             "strict_capabilities",
		LocalSuite:                  security.DefaultSuite(),
		PeerSuite:                   security.DefaultSuite(),
		LocalTranscriptMode:         "canonical_v1",
		PeerTranscriptMode:          "canonical_v1",
	}
	tests := []struct {
		policy string
		want   string
	}{
		{policy: "strict_required", want: "multi_stream,proxy_semantics"},
		{policy: "intersection_with_required", want: "carrier_abstraction,multi_stream,proxy_semantics"},
		{policy: "profile_declared_required", want: "carrier_abstraction,multi_stream,proxy_semantics"},
	}
	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			input := base
			input.CapabilityNegotiationPolicy = tt.policy
			result, err := NegotiateBilateralCapabilities(input)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(result.Selected.Features, ","); got != tt.want {
				t.Fatalf("selection = %q, want %q", got, tt.want)
			}
			input.LocalOffer, input.PeerOffer = input.PeerOffer, input.LocalOffer
			input.LocalFloor, input.PeerFloor = input.PeerFloor, input.LocalFloor
			swapped, err := NegotiateBilateralCapabilities(input)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(swapped.Selected.Features, ",") != tt.want || swapped.CapabilityHash != result.CapabilityHash {
				t.Fatal("client/server swap changed a symmetric selection")
			}
		})
	}
}

func TestBilateralNegotiationRejectsEitherFloorAndNoncanonicalInput(t *testing.T) {
	base := BilateralNegotiationInput{
		LocalOffer:                  security.CapabilitySet{Features: []string{"multi_stream", "proxy_semantics"}},
		PeerOffer:                   security.CapabilitySet{Features: []string{"multi_stream", "proxy_semantics"}},
		LocalFloor:                  security.CapabilitySet{Features: []string{"multi_stream"}},
		PeerFloor:                   security.CapabilitySet{Features: []string{"proxy_semantics"}},
		CapabilityNegotiationPolicy: "intersection_with_required",
		DowngradePolicy:             "strict_capabilities",
		LocalSuite:                  security.DefaultSuite(),
		PeerSuite:                   security.DefaultSuite(),
		LocalTranscriptMode:         "canonical_v1",
		PeerTranscriptMode:          "canonical_v1",
	}
	for name, mutate := range map[string]func(*BilateralNegotiationInput){
		"local omits peer floor": func(v *BilateralNegotiationInput) { v.LocalOffer.Features = []string{"multi_stream"} },
		"peer omits local floor": func(v *BilateralNegotiationInput) { v.PeerOffer.Features = []string{"proxy_semantics"} },
		"duplicate offer": func(v *BilateralNegotiationInput) {
			v.LocalOffer.Features = []string{"multi_stream", "multi_stream", "proxy_semantics"}
		},
		"empty local floor":        func(v *BilateralNegotiationInput) { v.LocalFloor.Features = nil },
		"unknown selection policy": func(v *BilateralNegotiationInput) { v.CapabilityNegotiationPolicy = "future" },
		"unknown downgrade policy": func(v *BilateralNegotiationInput) { v.DowngradePolicy = "future" },
		"suite bound transcript mismatch": func(v *BilateralNegotiationInput) {
			v.DowngradePolicy = "suite_bound_transcript"
			v.PeerTranscriptMode = "canonical_full_binding_v1"
		},
		"unsupported peer suite": func(v *BilateralNegotiationInput) { v.PeerSuite.KDF = "future" },
	} {
		t.Run(name, func(t *testing.T) {
			input := base
			mutate(&input)
			if _, err := NegotiateBilateralCapabilities(input); err == nil {
				t.Fatal("unsafe bilateral negotiation succeeded")
			}
		})
	}
}

func TestBilateralDowngradePoliciesPreserveSafeSelection(t *testing.T) {
	base := BilateralNegotiationInput{
		LocalOffer:                  security.CapabilitySet{Features: []string{"proxy_semantics", "multi_stream"}},
		PeerOffer:                   security.CapabilitySet{Features: []string{"multi_stream", "proxy_semantics"}},
		LocalFloor:                  security.CapabilitySet{Features: []string{"multi_stream"}},
		PeerFloor:                   security.CapabilitySet{Features: []string{"proxy_semantics"}},
		CapabilityNegotiationPolicy: "intersection_with_required",
		LocalSuite:                  security.DefaultSuite(),
		PeerSuite:                   security.DefaultSuite(),
		LocalTranscriptMode:         "canonical_full_binding_v1",
		PeerTranscriptMode:          "canonical_full_binding_v1",
	}
	for _, policy := range []string{"strict_suite_and_capabilities", "strict_capabilities", "suite_bound_transcript"} {
		t.Run(policy, func(t *testing.T) {
			input := base
			input.DowngradePolicy = policy
			result, err := NegotiateBilateralCapabilities(input)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(result.Selected.Features, ","); got != "multi_stream,proxy_semantics" {
				t.Fatalf("safe selection = %q", got)
			}
		})
	}
}

func TestLifecycleAndStreamManager(t *testing.T) {
	p := mustProfile(t, 15)
	cfg := DefaultConfig(RoleClient, "rt", []byte("secret"))
	rt, err := NewRuntime(cfg, p)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewManager(rt).CreateSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BeginNegotiation(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkOpen(); err == nil {
		t.Fatal("expected invalid transition rejection")
	}
	if err := s.BeginSecuring(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkOpen(); err != nil {
		t.Fatal(err)
	}
	sm, err := NewStreamManager(s, p)
	if err != nil {
		t.Fatal(err)
	}
	id, err := sm.OpenStream("interactive", zeroIntent())
	if err != nil {
		t.Fatal(err)
	}
	if err := sm.ResetStream(id, "test_reset"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close("done"); err != nil {
		t.Fatal(err)
	}
	if _, err := sm.OpenStream("bulk", zeroIntent()); err == nil {
		t.Fatal("expected stream open after close rejection")
	}
}

func TestSecureChannelAndHarness(t *testing.T) {
	p := mustProfile(t, 16)
	secret := []byte("client-secret-material")
	summary, events, err := RunLocalHarness(context.Background(), p, HarnessOptions{
		Scenario:     proxyadversary.DefaultScenario(proxyadversary.ScenarioMixedTargets),
		ReplayInject: true,
		ClientSecret: secret,
		ServerSecret: secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.ClientState != string(SessionClosed) || summary.ServerState != string(SessionClosed) {
		t.Fatalf("session not closed cleanly: %+v", summary)
	}
	if !summary.TranscriptMatched || !summary.CapabilityMatched || summary.ReplayRejected == 0 {
		t.Fatalf("security summary mismatch: %+v", summary)
	}
	if summary.PayloadLogged || summary.SecretLogged || TraceHasSensitive(events, []byte("runtime-local-bytes"), secret) {
		t.Fatal("runtime trace leaked payload or secret material")
	}
}

func TestStrictNormalNoFaultAuthorityV1(t *testing.T) {
	typ := reflect.TypeOf(NewSecureChannel)
	if typ.NumIn() != 3 || typ.NumOut() != 2 {
		t.Fatalf("normal secure channel signature=%v", typ)
	}
	p := mustProfile(t, 1601)
	ctx, keys, err := BuildSecurityContext(p, security.DefaultCapabilities(), []byte("strict-normal-no-fault"))
	if err != nil {
		t.Fatal(err)
	}
	sender, err := NewSecureChannel(ctx, keys, RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewSecureChannel(ctx, keys, RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := sender.Seal(security.EnvelopeMetadata{StreamID: 1, Semantic: "strict_normal", CarrierFamily: p.CarrierPolicy.CarrierFamily}, []byte("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Open(envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Open(envelope); !errors.Is(err, security.ErrReplay) {
		t.Fatalf("normal channel duplicate=%v want replay rejection", err)
	}
}

func TestHarnessRejectsProfileMismatch(t *testing.T) {
	a := mustProfile(t, 17)
	b := mustProfile(t, 18)
	_, _, err := RunLocalHarness(context.Background(), a, HarnessOptions{ProfileMismatch: b})
	if err == nil {
		t.Fatal("expected profile mismatch failure")
	}
}

func mustProfile(t testing.TB, seed int64) *ir.Profile {
	t.Helper()
	p, err := compiler.Generate(seed)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func zeroIntent() proxysem.RelayIntent {
	return proxysem.RelayIntent{}
}
