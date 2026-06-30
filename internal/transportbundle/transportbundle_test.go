// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import (
	"context"
	"testing"

	"kurdistan/internal/adaptivepath"
)

func TestCompileBundleModesValidateAndGateRisk(t *testing.T) {
	for _, mode := range RequiredBundleModes() {
		bundle, err := Compile(context.Background(), DefaultPolicy(12345, mode))
		if err != nil {
			t.Fatalf("Compile(%s) error = %v", mode, err)
		}
		if err := ValidateManifest(bundle.Manifest); err != nil {
			t.Fatalf("ValidateManifest(%s) error = %v", mode, err)
		}
		for _, candidate := range bundle.Manifest.Candidates {
			if candidate.Family == adaptivepath.CandidateDomesticMediaRisk && candidate.Role != CandidateRoleHighRiskGated {
				t.Fatalf("domestic/media candidate not high-risk gated: %#v", candidate)
			}
			if candidate.Family == adaptivepath.CandidateExperimentalUDP && candidate.Role != CandidateRoleExperimental {
				t.Fatalf("experimental UDP candidate not experimental gated: %#v", candidate)
			}
			if candidate.Role == CandidateRolePrimaryEligible && (candidate.HighRisk || candidate.Experimental) {
				t.Fatalf("risky candidate primary eligible: %#v", candidate)
			}
		}
	}
}

func TestBalancedBundleCoverageAndSeedStability(t *testing.T) {
	policy := DefaultPolicy(12345, BundleModeBalancedAdaptive)
	a, err := Compile(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compile(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if a.Manifest.BundleHash != b.Manifest.BundleHash {
		t.Fatalf("same seed produced different hashes: %s != %s", a.Manifest.BundleHash, b.Manifest.BundleHash)
	}
	for _, family := range []adaptivepath.CandidateFamily{
		adaptivepath.CandidateHTTPSLikeTCP,
		adaptivepath.CandidateDNSSurvival,
		adaptivepath.CandidateExperimentalUDP,
		adaptivepath.CandidateRelayRotation,
	} {
		if a.Manifest.FamilyCounts[string(family)] == 0 {
			t.Fatalf("balanced bundle missing family %s", family)
		}
	}
	if a.SeedPlan.UniqueProfileSeeds < policy.MinUniqueProfileSeeds {
		t.Fatalf("unique profile seeds = %d, want >= %d", a.SeedPlan.UniqueProfileSeeds, policy.MinUniqueProfileSeeds)
	}
	if a.Manifest.FallbackPlan.FinalWinnerSelected {
		t.Fatalf("M28 fallback plan selected a final winner")
	}
}

func TestBundleMappingRelayFallbackCollapseAndParity(t *testing.T) {
	set, err := GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(set.AdaptivePathCandidates) != len(set.Manifest.Candidates) {
		t.Fatalf("adaptivepath mapping count mismatch")
	}
	if set.RelayBinding.CandidateCount != len(set.Manifest.Candidates) {
		t.Fatalf("relay binding candidate count mismatch")
	}
	if len(set.FallbackHints) != len(set.Manifest.Candidates) {
		t.Fatalf("fallback hint count mismatch")
	}
	if set.CollapseReport.Conclusion != "passed" {
		t.Fatalf("healthy bundle collapsed: %+v", set.CollapseReport)
	}
	if set.ControlCollapseReport.Conclusion != "failed" {
		t.Fatalf("collapsed control was not detected: %+v", set.ControlCollapseReport)
	}
	if set.Parity.Conclusion != "passed" {
		t.Fatalf("parity failed: %+v", set.Parity)
	}
	if err := ScanForLeak(set); err != nil {
		t.Fatalf("fixture leaked unsafe metadata: %v", err)
	}
}

func TestCollapseScannerAndLeakDetection(t *testing.T) {
	bundle, err := Compile(context.Background(), DefaultPolicy(12345, BundleModeBalancedAdaptive))
	if err != nil {
		t.Fatal(err)
	}
	collapsed := bundle.Manifest
	for i := range collapsed.Candidates {
		collapsed.Candidates[i].Family = adaptivepath.CandidateHTTPSLikeTCP
		collapsed.Candidates[i].WirePolicyHash = "same_wire_policy"
		collapsed.Candidates[i].ProfileSeed = 12345
	}
	report := ScanCollapse(collapsed)
	if report.Conclusion != "failed" {
		t.Fatalf("collapsed manifest not detected: %+v", report)
	}
	for _, unsafe := range []map[string]string{
		{"endpoint": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"dns_query": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
	} {
		if err := ScanForLeak(unsafe); err == nil {
			t.Fatalf("unsafe field accepted: %#v", unsafe)
		}
	}
}

func FuzzValidateManifest(f *testing.F) {
	f.Add([]byte(`{"version":"transportbundle-v1"}`))
	f.Add([]byte(`{"payload":"x"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = ValidateManifestJSON(raw)
	})
}

func BenchmarkCompileBundle(b *testing.B) {
	policy := DefaultPolicy(12345, BundleModeBalancedAdaptive)
	for i := 0; i < b.N; i++ {
		if _, err := Compile(context.Background(), policy); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCollapseScanner(b *testing.B) {
	compiled, err := Compile(context.Background(), DefaultPolicy(12345, BundleModeBalancedAdaptive))
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		_ = ScanCollapse(compiled.Manifest)
	}
}
