// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import (
	"testing"

	"kurdistan/internal/protocorpus"
)

func TestSamplePolicyIsDeterministicAndValid(t *testing.T) {
	corpus := protocorpus.DefaultCorpus()
	a, err := SamplePolicy(12345, corpus)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SamplePolicy(12345, corpus)
	if err != nil {
		t.Fatal(err)
	}
	if a.PolicyHash != b.PolicyHash || a.PolicyID != b.PolicyID {
		t.Fatalf("same seed produced different policy: %s vs %s", a.PolicyHash, b.PolicyHash)
	}
	if err := ValidatePolicy(a, corpus); err != nil {
		t.Fatal(err)
	}
}

func TestSamplePolicyVariesAcrossSeeds(t *testing.T) {
	corpus := protocorpus.DefaultCorpus()
	hashes := map[string]bool{}
	families := map[protocorpus.ProtocolFamily]bool{}
	for seed := int64(1); seed <= 20; seed++ {
		policy, err := SamplePolicy(seed, corpus)
		if err != nil {
			t.Fatal(err)
		}
		hashes[policy.PolicyHash] = true
		families[policy.SelectedFamily] = true
	}
	if len(hashes) < 12 {
		t.Fatalf("expected policy hash variation, got %d", len(hashes))
	}
	if len(families) < 4 {
		t.Fatalf("expected family variation, got %d", len(families))
	}
}

func TestPolicyIRRoundTripPreservesHash(t *testing.T) {
	corpus := protocorpus.DefaultCorpus()
	policy, err := SamplePolicy(77, corpus)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip := FromIRPolicy(ToIRPolicy(policy))
	if roundTrip.PolicyHash != policy.PolicyHash {
		t.Fatalf("policy hash drifted: %s vs %s", roundTrip.PolicyHash, policy.PolicyHash)
	}
	if err := ValidatePolicy(roundTrip, corpus); err != nil {
		t.Fatal(err)
	}
}

func TestRedactionRejectsUnsafePolicyMaterial(t *testing.T) {
	policy, err := SamplePolicy(5, protocorpus.DefaultCorpus())
	if err != nil {
		t.Fatal(err)
	}
	policy.PolicyID = "raw_payload_marker"
	report := ValidateRedaction(policy)
	if report.Passed {
		t.Fatal("expected unsafe policy material to be rejected")
	}
}
