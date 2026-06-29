// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package ir_test

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func TestSecurityPolicyValidationAndGeneration(t *testing.T) {
	p, err := compiler.Generate(12100)
	if err != nil {
		t.Fatal(err)
	}
	if p.Security.SecurityVersion == "" || p.Security.KDFSuite == "" || p.Compatibility.CompilerSecurityVersion == "" {
		t.Fatalf("security policy or compatibility metadata missing: %+v %+v", p.Security, p.Compatibility)
	}
	if err := ir.Validate(p); err != nil {
		t.Fatal(err)
	}

	bad := *p
	bad.GenerationHash = ""
	bad.Security.KDFSuite = "kdf_none"
	if err := ir.Validate(&bad); err == nil {
		t.Fatalf("invalid KDF suite accepted")
	}

	bad = *p
	bad.GenerationHash = ""
	bad.Security.ReplayWindowSize = 1 << 20
	if err := ir.Validate(&bad); err == nil {
		t.Fatalf("unsafe replay window accepted")
	}

	bad = *p
	bad.GenerationHash = ""
	bad.Compatibility.RequiredCapabilities = []string{"unknown_future_feature"}
	if err := ir.Validate(&bad); err == nil {
		t.Fatalf("unknown required capability accepted")
	}
}

func TestSecurityPolicyVariesAcrossSeeds(t *testing.T) {
	combinations := map[string]bool{}
	transcriptModes := map[string]bool{}
	nonceModes := map[string]bool{}
	replayPolicies := map[string]bool{}
	for seed := int64(12100); seed < 12220; seed++ {
		p, err := compiler.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		if err := ir.Validate(p); err != nil {
			t.Fatal(err)
		}
		key := p.Security.TranscriptMode + "|" + p.Security.NonceMode + "|" + p.Security.ReplayPolicy + "|" + p.Security.SecureEnvelopeMode
		combinations[key] = true
		transcriptModes[p.Security.TranscriptMode] = true
		nonceModes[p.Security.NonceMode] = true
		replayPolicies[p.Security.ReplayPolicy] = true
	}
	if len(combinations) < 20 || len(transcriptModes) < 3 || len(nonceModes) < 3 || len(replayPolicies) < 3 {
		t.Fatalf("insufficient security diversity: combinations=%d transcript=%d nonce=%d replay=%d", len(combinations), len(transcriptModes), len(nonceModes), len(replayPolicies))
	}
}
