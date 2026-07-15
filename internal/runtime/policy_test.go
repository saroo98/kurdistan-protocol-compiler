// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"reflect"
	"testing"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

func TestEffectivePolicyConstructionAndPlumbing(t *testing.T) {
	p, err := compiler.Generate(510)
	if err != nil {
		t.Fatal(err)
	}
	floor := append([]string(nil), p.Compatibility.RequiredCapabilities...)
	policy, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	if err := ir.ValidateEffectiveSecurityPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if policy.ProfileID != p.ID || policy.ProfileHash != p.GenerationHash || policy.SecurityVersion != p.Security.SecurityVersion {
		t.Fatal("effective policy lost profile or security identity")
	}
	if policy.NonceMode != p.Security.NonceMode || policy.ReplayPolicy != p.Security.ReplayPolicy || policy.ReplayWindowSize != p.Security.ReplayWindowSize {
		t.Fatal("effective policy rebuilt runtime fields ad hoc")
	}

	securityBase := securityConfigFixture(t, p, policy)
	boundSecurity, err := security.BindEffectivePolicy(securityBase, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := ir.ValidateEffectiveSecurityPolicy(boundSecurity.EffectivePolicy()); err != nil {
		t.Fatal(err)
	}

	runtimeBase := DefaultConfig(RoleClient, "policy-runtime", []byte("policy-runtime-secret"))
	boundRuntime, err := BindEffectivePolicy(runtimeBase, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePolicyBoundConfig(boundRuntime); err != nil {
		t.Fatal(err)
	}
	if err := ir.ValidateEffectiveSecurityPolicy(boundRuntime.EffectivePolicy()); err != nil {
		t.Fatal(err)
	}
	returned := boundRuntime.EffectivePolicy()
	returned.SelectedCapabilities[0] = "mutated"
	if err := ValidatePolicyBoundConfig(boundRuntime); err != nil {
		t.Fatalf("caller mutation escaped the immutable policy carrier: %v", err)
	}
}

func TestEffectivePolicyRejectsMissingPartialUnknownAndBelowFloor(t *testing.T) {
	p, err := compiler.Generate(511)
	if err != nil {
		t.Fatal(err)
	}
	floor := append([]string(nil), p.Compatibility.RequiredCapabilities...)
	valid, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, floor)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		policy ir.EffectiveSecurityPolicy
	}{
		{name: "missing", policy: ir.EffectiveSecurityPolicy{}},
		{name: "partial raw", policy: ir.EffectiveSecurityPolicy{ProfileID: p.ID}},
		{name: "mutated after validation", policy: func() ir.EffectiveSecurityPolicy { v := valid; v.ReplayPolicy = "unknown"; return v }()},
		{name: "mutated selected floor", policy: func() ir.EffectiveSecurityPolicy { v := valid.Clone(); v.SelectedCapabilities = nil; return v }()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ir.ValidateEffectiveSecurityPolicy(tt.policy); err == nil {
				t.Fatal("invalid effective policy validated")
			}
			if _, err := BindEffectivePolicy(DefaultConfig(RoleClient, "policy", []byte("secret")), tt.policy); err == nil {
				t.Fatal("runtime config accepted invalid effective policy")
			}
			if _, err := security.BindEffectivePolicy(securityConfigFixture(t, p, valid), tt.policy); err == nil {
				t.Fatal("security config accepted invalid effective policy")
			}
		})
	}

	if _, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, floor[1:]); err == nil {
		t.Fatal("selection below a mandatory floor was accepted")
	}
	unknown := *p
	unknown.GenerationHash = ""
	unknown.Security.NonceMode = "future_nonce_mode"
	if _, err := ir.BuildEffectiveSecurityPolicy(&unknown, floor, floor, floor); err == nil {
		t.Fatal("unknown raw profile policy was accepted")
	}
}

func TestEffectivePolicyGeneratedSerializationParity(t *testing.T) {
	p, err := compiler.Generate(512)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/profile.json"
	if err := ir.SaveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	loaded, err := ir.LoadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	floor := append([]string(nil), p.Compatibility.RequiredCapabilities...)
	interpreted, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := ir.BuildEffectiveSecurityPolicy(loaded, floor, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(interpreted, serialized) {
		t.Fatal("generated/serialized profile produced different effective policy")
	}
}

func securityConfigFixture(t *testing.T, p *ir.Profile, policy ir.EffectiveSecurityPolicy) security.SecurityConfig {
	t.Helper()
	return security.SecurityConfig{
		ProfileID:        p.ID,
		ProfileHash:      policy.ProfileHash,
		InputSecret:      []byte("policy-security-secret"),
		Suite:            security.DefaultSuite(),
		ReplayWindow:     policy.ReplayWindowSize,
		MaxEnvelopeBytes: p.Compatibility.MaxEnvelopeBytes,
		QueueDepth:       8,
		Capabilities:     append([]string(nil), policy.SelectedCapabilities...),
		TranscriptHash:   policy.ProfileHash,
		CapabilityHash:   policy.ProfileHash,
	}
}
