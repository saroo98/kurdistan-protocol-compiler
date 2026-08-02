// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package assurance

import (
	"strings"
	"testing"
)

func TestDecodeProofPolicyRejectsUnknownAndTrailingJSON(t *testing.T) {
	valid := `{"schema":"kurdistan-proof-policy-v1","proofs":[{"id":"go-core","commands":[["go","test","-count=1","./..."]],"operatingSystems":["linux","windows"],"cachePolicy":"CACHE_INDEPENDENT","deterministic":true,"invalidatedBy":["go.mod"],"authorizedPhase":16}]}`
	if _, err := DecodeProofPolicy(strings.NewReader(valid)); err != nil {
		t.Fatalf("decode valid policy: %v", err)
	}
	if _, err := DecodeProofPolicy(strings.NewReader(strings.Replace(valid, `"proofs"`, `"unknown":true,"proofs"`, 1))); err == nil {
		t.Fatal("expected unknown field rejection")
	}
	if _, err := DecodeProofPolicy(strings.NewReader(valid + `{}`)); err == nil {
		t.Fatal("expected trailing JSON rejection")
	}
}

func TestProofPolicyRejectsDuplicateProofAndUnboundedCommand(t *testing.T) {
	policy := ProofPolicy{
		Schema: ProofPolicySchema,
		Proofs: []Proof{
			{ID: "go-core", Commands: [][]string{{"go", "test", "-count=1", "./..."}}, OperatingSystems: []string{"linux"}, CachePolicy: CacheIndependent, Deterministic: true, InvalidatedBy: []string{"go.mod"}, AuthorizedPhase: 16},
			{ID: "go-core", Commands: [][]string{{"go", "test", "./..."}}, OperatingSystems: []string{"linux"}, CachePolicy: CacheIndependent, Deterministic: true, InvalidatedBy: []string{"go.sum"}, AuthorizedPhase: 16},
		},
	}
	if err := policy.Validate(); err == nil {
		t.Fatal("expected duplicate proof rejection")
	}
	policy.Proofs = policy.Proofs[:1]
	policy.Proofs[0].Commands[0][1] = strings.Repeat("x", 2049)
	if err := policy.Validate(); err == nil {
		t.Fatal("expected oversized argument rejection")
	}
}

func TestImpactPolicyIsDenyByDefault(t *testing.T) {
	policy := ImpactPolicy{
		Schema:        ImpactPolicySchema,
		DefaultProofs: []string{"full-assurance"},
		Rules:         []ImpactRule{{Pattern: "docs/**", Proofs: []string{"docs"}}},
	}
	proofs, err := policy.ProofsForPaths([]string{"new/unknown/file.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(proofs) != 1 || proofs[0] != "full-assurance" {
		t.Fatalf("unknown path proofs = %v", proofs)
	}
}

func TestValidateImpactProofReferencesRejectsUnknownProof(t *testing.T) {
	proofs := ProofPolicy{
		Schema: ProofPolicySchema,
		Proofs: []Proof{{
			ID:               "go-core",
			Commands:         [][]string{{"go", "test", "-count=1", "./..."}},
			OperatingSystems: []string{"linux"},
			CachePolicy:      CacheIndependent,
			Deterministic:    true,
			InvalidatedBy:    []string{"go.mod"},
			AuthorizedPhase:  16,
		}},
	}
	impact := ImpactPolicy{
		Schema:        ImpactPolicySchema,
		DefaultProofs: []string{"missing"},
		Rules:         []ImpactRule{{Pattern: "docs/**", Proofs: []string{"go-core"}}},
	}
	if err := ValidateImpactProofReferences(impact, proofs); err == nil {
		t.Fatal("expected unknown impact proof rejection")
	}
	impact.DefaultProofs = []string{"go-core"}
	if err := ValidateImpactProofReferences(impact, proofs); err != nil {
		t.Fatalf("validate known impact proofs: %v", err)
	}
}

func TestValidateImpactProofReferencesRejectsInvalidationBypass(t *testing.T) {
	proofs := ProofPolicy{
		Schema: ProofPolicySchema,
		Proofs: []Proof{
			{ID: "go-core", Commands: [][]string{{"go", "test", "./..."}}, OperatingSystems: []string{"linux"}, CachePolicy: CacheIndependent, Deterministic: true, InvalidatedBy: []string{"testdata/**"}, AuthorizedPhase: 16},
			{ID: "docs-evidence", Commands: [][]string{{"go", "test", "./docs"}}, OperatingSystems: []string{"linux"}, CachePolicy: CacheIndependent, Deterministic: true, InvalidatedBy: []string{"testdata/evidence/**"}, AuthorizedPhase: 16},
		},
	}
	impact := ImpactPolicy{
		Schema:        ImpactPolicySchema,
		DefaultProofs: []string{"go-core", "docs-evidence"},
		Rules:         []ImpactRule{{Pattern: "testdata/evidence/**", Proofs: []string{"docs-evidence"}}},
	}
	if err := ValidateImpactProofReferences(impact, proofs); err == nil || !strings.Contains(err.Error(), "go-core") {
		t.Fatalf("error = %v, want go-core invalidation bypass rejection", err)
	}
	impact.Rules[0].Proofs = []string{"docs-evidence", "go-core"}
	if err := ValidateImpactProofReferences(impact, proofs); err != nil {
		t.Fatalf("validate covered invalidation: %v", err)
	}
}
