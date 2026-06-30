// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

import (
	"context"
	"encoding/json"
	"testing"
)

func TestFamilyTaxonomyValidation(t *testing.T) {
	for _, desc := range FamilyDescriptors() {
		if err := ValidateFamilyDescriptor(desc); err != nil {
			t.Fatalf("family %s invalid: %v", desc.Family, err)
		}
		if (desc.HighRisk || desc.Experimental || desc.Family == CandidateDNSSurvival) && !desc.Gated {
			t.Fatalf("risky family not gated: %s", desc.Family)
		}
		if desc.Family == CandidateDomesticMediaRisk && desc.DefaultEligible {
			t.Fatalf("domestic media risk default eligible")
		}
		if desc.DescriptorHash != HashValue(familyHashInput(desc)) {
			t.Fatalf("family hash unstable")
		}
	}
}

func TestSyntheticConditionsValidation(t *testing.T) {
	for _, condition := range DefaultConditions() {
		if err := ValidateCondition(condition); err != nil {
			t.Fatalf("condition %s invalid: %v", condition.ConditionClass, err)
		}
		if condition.ConditionHash != HashValue(conditionHashInput(condition)) {
			t.Fatalf("condition hash unstable")
		}
	}
}

func TestFreshnessAndUncertainty(t *testing.T) {
	if FreshnessAtTick(1, TTLSeconds, 2) != FreshSeconds {
		t.Fatalf("fresh seconds not fresh")
	}
	if FreshnessAtTick(1, TTLSeconds, 12) != Expired {
		t.Fatalf("expired short TTL not expired")
	}
	if UncertaintyBucket(1, 2, 0) != HighUncertainty {
		t.Fatalf("recent failures did not increase uncertainty")
	}
}

func TestViabilityRules(t *testing.T) {
	candidates := DefaultCandidates()
	observations := DefaultObservations(candidates)
	byFamily := map[CandidateFamily]CandidateViabilityReport{}
	for _, candidate := range candidates {
		report := EvaluateViability(candidate, observations)
		if err := ValidateViabilityReport(report); err != nil {
			t.Fatalf("viability report invalid: %v", err)
		}
		byFamily[candidate.Family] = report
	}
	if byFamily[CandidateDNSSurvival].CurrentState != string(CandidateRejected) {
		t.Fatalf("dns poisoning did not reject dns survival: %+v", byFamily[CandidateDNSSurvival])
	}
	if byFamily[CandidateHTTPSLikeTCP].CurrentState != string(CandidateBlocked) {
		t.Fatalf("tcp blackhole did not block https-like tcp")
	}
	if byFamily[CandidateExperimentalUDP].CurrentState != string(CandidateDegraded) {
		t.Fatalf("udp block did not degrade experimental udp")
	}
	if byFamily[CandidateRelayRotation].CurrentState != string(CandidateBurned) {
		t.Fatalf("relay burn did not burn relay rotation")
	}
}

func TestDecisionInputsAndMisuse(t *testing.T) {
	candidates := DefaultCandidates()
	observations := DefaultObservations(candidates)
	set := BuildDecisionSet(candidates, observations)
	if err := ValidateDecisionSet(set); err != nil {
		t.Fatalf("decision set invalid: %v", err)
	}
	if set.DecisionSetHash != HashValue(decisionSetHashInput(set)) {
		t.Fatalf("decision set hash unstable")
	}
	if ScanMisuse(candidates, observations, nil).Conclusion != "passed" {
		t.Fatalf("healthy candidates flagged")
	}
	if CollapsedControlReport(candidates, observations).Conclusion != "failed" {
		t.Fatalf("collapsed control not detected")
	}
	unsafeCandidate := candidates[0]
	unsafeCandidate.PayloadLogged = true
	if ScanMisuse([]PathCandidate{unsafeCandidate}, observations, nil).Conclusion != "failed" {
		t.Fatalf("payload misuse not detected")
	}
}

func TestFixtureSetAndParity(t *testing.T) {
	set, err := GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if CompareFixtureSets(set, set).Conclusion != "passed" {
		t.Fatalf("fixture self-compare failed")
	}
	if set.Parity.Conclusion != "passed" || set.Parity.ComparedCandidates == 0 {
		t.Fatalf("parity failed: %+v", set.Parity)
	}
	if err := ScanForLeak(map[string]string{"endpoint": "synthetic"}); err == nil {
		t.Fatalf("endpoint marker accepted")
	}
	if err := ScanForLeak(map[string]string{"dns_query": "synthetic"}); err == nil {
		t.Fatalf("dns query marker accepted")
	}
	if err := ScanForLeak(map[string]string{"secret": "synthetic"}); err == nil {
		t.Fatalf("secret marker accepted")
	}
}

func FuzzCandidateParser(f *testing.F) {
	f.Add(`{"candidate_id":"x","family":"unknown"}`)
	f.Add(`{"endpoint":"x"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		var candidate PathCandidate
		_ = json.Unmarshal([]byte(raw), &candidate)
		_ = ValidateCandidate(candidate)
		_ = ScanForLeak(map[string]string{"value": raw})
	})
}

func FuzzConditionParser(f *testing.F) {
	f.Add(`{"condition_class":"unknown"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		var condition SyntheticPathCondition
		_ = json.Unmarshal([]byte(raw), &condition)
		_ = ValidateCondition(condition)
	})
}

func BenchmarkCandidateValidation(b *testing.B) {
	candidates := DefaultCandidates()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, candidate := range candidates {
			_ = ValidateCandidate(candidate)
		}
	}
}

func BenchmarkViabilityEvaluation(b *testing.B) {
	candidates := DefaultCandidates()
	observations := DefaultObservations(candidates)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EvaluateAll(candidates, observations)
	}
}

func BenchmarkDecisionInputGeneration(b *testing.B) {
	candidates := DefaultCandidates()
	observations := DefaultObservations(candidates)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildDecisionSet(candidates, observations)
	}
}

func BenchmarkMisuseScanner(b *testing.B) {
	candidates := DefaultCandidates()
	observations := DefaultObservations(candidates)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScanMisuse(candidates, observations, nil)
	}
}
