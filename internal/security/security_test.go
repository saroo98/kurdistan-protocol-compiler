// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"sync"
	"testing"

	"kurdistan/internal/compiler"
)

func sampleTranscriptInput(t *testing.T) TranscriptInput {
	t.Helper()
	p, err := compiler.Generate(12001)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := ProfileHash(p)
	if err != nil {
		t.Fatal(err)
	}
	return TranscriptInput{
		ProfileID:            p.ID,
		ProfileHash:          hash,
		CompilerHash:         "compiler-test-hash",
		SemanticMappingHash:  "semantic-map-test-hash",
		FSMPolicy:            "fsm-test",
		FramingPolicy:        p.FrameGrammar.LengthMode + "/" + p.FrameGrammar.TypeMode,
		SchedulerPolicy:      p.Scheduler.Mode,
		PaddingPolicy:        p.Padding.Mode,
		StreamPolicy:         p.Stream.IDStrategy + "/" + p.Stream.PriorityPolicy,
		ProxyPolicy:          p.ProxySemantics.TargetDescriptorEncoding,
		CarrierPolicy:        p.CarrierPolicy.CarrierFamily + "/" + p.CarrierPolicy.EnvelopeEncoding,
		Capabilities:         DefaultCapabilities().Features,
		SessionNonce:         []byte("0123456789abcdef"),
		Suite:                DefaultSuite(),
		OrderedStatePath:     []string{"start", "ready"},
		AdditionalPolicyData: map[string]string{"b": "two", "a": "one"},
	}
}

func TestTranscriptBindingAndCanonicalization(t *testing.T) {
	in := sampleTranscriptInput(t)
	rawA, err := CanonicalTranscript(in)
	if err != nil {
		t.Fatal(err)
	}
	hashA, err := TranscriptHash(in)
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := TranscriptHash(in)
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Fatalf("transcript hash was not deterministic: %s != %s", hashA, hashB)
	}
	reorderedMap := in
	reorderedMap.AdditionalPolicyData = map[string]string{"a": "one", "b": "two"}
	hashMap, err := TranscriptHash(reorderedMap)
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashMap {
		t.Fatalf("map key order changed transcript hash: %s != %s", hashA, hashMap)
	}
	reorderedCapabilities := in
	reorderedCapabilities.Capabilities = []string{"nonce_schedule", "multi_stream", "carrier_abstraction", "adapter_interface", "proxy_semantics", "generated_backend", "replay_window", "transcript_binding", "carrier_backpressure", "carrier_loss_recovery"}
	hashCaps, err := TranscriptHash(reorderedCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashCaps {
		t.Fatalf("capability order should canonicalize: %s != %s", hashA, hashCaps)
	}
	for name, mutate := range map[string]func(*TranscriptInput){
		"profile":     func(v *TranscriptInput) { v.ProfileHash = "changed-profile" },
		"carrier":     func(v *TranscriptInput) { v.CarrierPolicy = "changed-carrier" },
		"stream":      func(v *TranscriptInput) { v.StreamPolicy = "changed-stream" },
		"proxy":       func(v *TranscriptInput) { v.ProxyPolicy = "changed-proxy" },
		"capability":  func(v *TranscriptInput) { v.Capabilities = []string{"multi_stream"} },
		"suite":       func(v *TranscriptInput) { v.Suite.KDF = "other-kdf" },
		"orderedPath": func(v *TranscriptInput) { v.OrderedStatePath = []string{"ready", "start"} },
	} {
		changed := in
		mutate(&changed)
		got, err := TranscriptHash(changed)
		if err != nil {
			t.Fatalf("%s mutation: %v", name, err)
		}
		if got == hashA {
			t.Fatalf("%s mutation did not change transcript hash", name)
		}
	}
	if bytes.Contains(rawA, []byte("super-secret")) {
		t.Fatalf("canonical transcript included raw secret material")
	}
}

func TestKeyScheduleNonceReplayAndTraceHygiene(t *testing.T) {
	in := sampleTranscriptInput(t)
	transcript, err := TranscriptHash(in)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("deterministic test secret with enough entropy")
	a, err := DeriveKeySchedule(secret, transcript, DefaultSuite())
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKeySchedule(secret, transcript, DefaultSuite())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.ClientWriteKey, b.ClientWriteKey) || !bytes.Equal(a.ExporterSecret, b.ExporterSecret) {
		t.Fatalf("key schedule is not deterministic")
	}
	if bytes.Equal(a.ClientWriteKey, a.ServerWriteKey) {
		t.Fatalf("client and server write keys should differ")
	}
	if bytes.Equal(a.ClientNonceBase, a.ServerNonceBase) {
		t.Fatalf("client and server nonce bases should differ")
	}
	changed, err := DeriveKeySchedule(secret, strings.Repeat("1", len(transcript)), DefaultSuite())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.ClientWriteKey, changed.ClientWriteKey) {
		t.Fatalf("different transcript did not change derived keys")
	}
	if _, err := DeriveKeySchedule(nil, transcript, DefaultSuite()); err == nil {
		t.Fatalf("empty input secret accepted")
	}
	if _, err := DeriveKeySchedule(secret, "", DefaultSuite()); err == nil {
		t.Fatalf("missing transcript hash accepted")
	}
	if _, err := DeriveKeySchedule(secret, transcript, Suite{KDF: "unknown"}); err == nil {
		t.Fatalf("unknown suite accepted")
	}
	trace := KeyScheduleTrace(a)
	encoded, _ := json.Marshal(trace)
	if bytes.Contains(encoded, secret) || bytes.Contains(encoded, a.ClientWriteKey) || bytes.Contains(encoded, a.ClientNonceBase) {
		t.Fatalf("key schedule trace leaked secret material: %s", encoded)
	}

	client := NewNonceManager("client", a.ClientNonceBase, "directional_counter")
	server := NewNonceManager("server", a.ServerNonceBase, "directional_counter")
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		n, _, err := client.Next()
		if err != nil {
			t.Fatal(err)
		}
		key := hex.EncodeToString(n)
		if seen[key] {
			t.Fatalf("duplicate nonce generated at index %d", i)
		}
		seen[key] = true
	}
	serverNonce, _, err := server.Next()
	if err != nil {
		t.Fatal(err)
	}
	if seen[hex.EncodeToString(serverNonce)] {
		t.Fatalf("client and server nonce spaces overlapped")
	}
	client.SetCounterForTest(math.MaxUint64)
	if _, _, err := client.Next(); err == nil {
		t.Fatalf("nonce overflow accepted")
	}

	concurrent := NewNonceManager("client", a.ClientNonceBase, "directional_counter")
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen = map[string]bool{}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				n, _, err := concurrent.Next()
				if err != nil {
					t.Errorf("nonce error: %v", err)
					return
				}
				mu.Lock()
				key := hex.EncodeToString(n)
				if seen[key] {
					t.Errorf("duplicate concurrent nonce")
				}
				seen[key] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	window := NewReplayWindow("windowed_replay", 4)
	for _, seq := range []uint64{1, 3, 2, 4} {
		if err := window.Accept(seq); err != nil {
			t.Fatalf("sequence %d rejected: %v", seq, err)
		}
	}
	if err := window.Accept(3); err == nil {
		t.Fatalf("duplicate replay sequence accepted")
	}
	if err := NewReplayWindow("ordered_only", 4).Accept(2); err == nil {
		t.Fatalf("ordered-only replay window accepted out-of-order first sequence")
	}
	if err := NewReplayWindow("windowed_replay", 4).Accept(99); err == nil {
		t.Fatalf("too-far future sequence accepted")
	}
}

func TestCapabilitiesCompatibilityConfigAndSecureEnvelope(t *testing.T) {
	caps := CapabilitySet{Features: []string{"carrier_abstraction", "multi_stream", "proxy_semantics"}}
	hashA, err := caps.Hash()
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := (CapabilitySet{Features: []string{"proxy_semantics", "carrier_abstraction", "multi_stream"}}).Hash()
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Fatalf("capability hash should be stable under order changes")
	}
	if err := RequireCapabilities(DefaultCapabilities(), CapabilitySet{Features: []string{"multi_stream"}}); err == nil {
		t.Fatalf("missing required capability accepted")
	}
	if err := DetectSuiteDowngrade(DefaultSuite(), Suite{KDF: "kdf_hkdf_sha1"}, ""); err == nil {
		t.Fatalf("suite downgrade accepted")
	}
	p, err := compiler.Generate(12002)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckProfileCompatibility(p, DefaultRuntimeCompatibility()); err != nil {
		t.Fatalf("generated profile compatibility rejected: %v", err)
	}
	badRuntime := DefaultRuntimeCompatibility()
	badRuntime.SupportedCarrierFamilies = []string{"message_carrier"}
	p.CarrierPolicy.CarrierFamily = "stream_carrier"
	if err := CheckProfileCompatibility(p, badRuntime); err == nil {
		t.Fatalf("unsupported carrier family accepted")
	}

	cfg := SecurityConfig{
		ProfileID:        "profile",
		ProfileHash:      strings.Repeat("a", 64),
		InputSecret:      []byte("deterministic config secret"),
		Suite:            DefaultSuite(),
		ReplayWindow:     32,
		MaxEnvelopeBytes: 1024,
		QueueDepth:       8,
		Capabilities:     DefaultCapabilities().Features,
		TranscriptHash:   strings.Repeat("b", 64),
		CapabilityHash:   hashA,
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	redacted := RedactConfig(cfg)
	raw, _ := json.Marshal(redacted)
	if bytes.Contains(raw, cfg.InputSecret) || redacted["input_secret"] == nil {
		t.Fatalf("config redaction failed: %s", raw)
	}
	unsafe := cfg
	unsafe.InputSecret = make([]byte, len(cfg.InputSecret))
	if err := ValidateConfig(unsafe); err == nil {
		t.Fatalf("all-zero secret accepted")
	}

	in := sampleTranscriptInput(t)
	ctx, err := BuildContext(in)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := DeriveKeySchedule([]byte("secure envelope test secret"), ctx.TranscriptHash, ctx.Suite)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := NewEnvelopeCodec(ctx, ks, "client")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("plaintext payload must not appear in trace")
	env, err := codec.Seal(EnvelopeMetadata{StreamID: 7, Semantic: "target_response", CarrierFamily: "stream_carrier", MetadataClass: "test"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := codec.Open(env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("secure envelope round trip changed payload")
	}
	if _, err := codec.Open(env); err == nil {
		t.Fatalf("replayed secure envelope accepted")
	}
	trace := SecureEnvelopeTrace(ctx, env)
	traceRaw, _ := json.Marshal(trace)
	if bytes.Contains(traceRaw, payload) || bytes.Contains(traceRaw, ks.ClientWriteKey) || bytes.Contains(traceRaw, ks.ClientNonceBase) || bytes.Contains(traceRaw, env.Ciphertext) {
		t.Fatalf("secure envelope trace leaked sensitive material: %s", traceRaw)
	}
	mismatched := env
	mismatched.TranscriptHash = strings.Repeat("c", 64)
	fresh, err := NewEnvelopeCodec(ctx, ks, "client")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Open(mismatched); err == nil {
		t.Fatalf("transcript mismatch accepted")
	}
	mismatched = env
	mismatched.CapabilityHash = strings.Repeat("d", 64)
	fresh, err = NewEnvelopeCodec(ctx, ks, "client")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Open(mismatched); err == nil {
		t.Fatalf("capability mismatch accepted")
	}
}
