// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package ir_test

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func TestGeneratedProfilesIncludeProxySemanticsPolicy(t *testing.T) {
	p, err := compiler.Generate(12345)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProxySemantics.RelayIntentEncoding == "" {
		t.Fatalf("missing relay intent encoding")
	}
	if p.ProxySemantics.MaxRequestBytes <= 0 || p.ProxySemantics.MaxResponseBytes <= 0 {
		t.Fatalf("missing proxy semantics size limits: %+v", p.ProxySemantics)
	}
	for _, semantic := range ir.ProxySemantics() {
		if _, ok := ir.MessageBySemantic(p, semantic); !ok {
			t.Fatalf("missing proxy semantic wire mapping %q", semantic)
		}
	}
}

func TestProxySemanticsPolicyDiversityAcrossSeeds(t *testing.T) {
	seen := map[string]bool{}
	for seed := int64(1); seed <= 40; seed++ {
		p, err := compiler.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		seen[p.ProxySemantics.RelayIntentEncoding+"|"+p.ProxySemantics.TargetDescriptorEncoding+"|"+p.ProxySemantics.TargetErrorPolicy+"|"+p.ProxySemantics.TargetResetPolicy] = true
	}
	if len(seen) < 8 {
		t.Fatalf("proxy semantics combinations = %d, want at least 8", len(seen))
	}
}

func TestValidateRejectsInvalidProxySemanticsPolicy(t *testing.T) {
	p, err := compiler.Generate(77)
	if err != nil {
		t.Fatal(err)
	}
	p.GenerationHash = ""
	p.ProxySemantics.TargetDescriptorEncoding = "fixed_external_hostname"
	if err := ir.Validate(p); err == nil {
		t.Fatalf("expected invalid target descriptor encoding to fail")
	}
}
