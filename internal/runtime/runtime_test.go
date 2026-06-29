// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	"kurdistan/internal/proxyadversary"
	"kurdistan/internal/proxysem"
	"kurdistan/internal/security"
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
