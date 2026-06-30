// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

import (
	"context"
	"encoding/json"
	"testing"
)

func TestAdversarialCorpusValidation(t *testing.T) {
	corpus, err := BuildAdversarialCorpus()
	if err != nil {
		t.Fatal(err)
	}
	if corpus.ScenarioCount != len(RequiredScenarioIDs()) {
		t.Fatalf("scenario count mismatch: %d", corpus.ScenarioCount)
	}
	if err := ValidateCorpus(corpus); err != nil {
		t.Fatal(err)
	}
	again, _ := BuildAdversarialCorpus()
	if corpus.CorpusHash != again.CorpusHash {
		t.Fatal("corpus hash drifted")
	}
}

func TestDescriptorAbuseHardening(t *testing.T) {
	report := RunDescriptorAbuseHardening()
	if err := ValidateDescriptorAbuseReport(report); err != nil {
		t.Fatal(err)
	}
	for _, tc := range DescriptorAbuseCases() {
		if !tc.ExpectedReject {
			t.Fatalf("descriptor abuse case not configured to reject: %s", tc.Name)
		}
		if _, err := descriptorAbuseCaseByName(tc.Name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLifecyclePressureResetAndMappingReports(t *testing.T) {
	lifecycle := RunLifecycleHardening()
	if err := ValidateLifecycleHardeningReport(lifecycle); err != nil {
		t.Fatal(err)
	}
	pressure := RunPressureHardening()
	if err := ValidatePressureHardeningReport(pressure); err != nil {
		t.Fatal(err)
	}
	resetError := RunResetErrorIsolation()
	if err := ValidateResetErrorIsolationReport(resetError); err != nil {
		t.Fatal(err)
	}
	set, err := GenerateAdversarialFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingCollapseReport(set.MappingCollapse, true); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingCollapseReport(set.CollapsedControl, false); err != nil {
		t.Fatal(err)
	}
}

func TestParityAndReadiness(t *testing.T) {
	set, err := GenerateAdversarialFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateParityReport(set.Parity); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReadinessReport(set.Readiness); err != nil {
		t.Fatal(err)
	}
	if set.Readiness.GoNoGoDecision != DecisionGoForLocalProxyEgress {
		t.Fatalf("unexpected readiness decision: %s", set.Readiness.GoNoGoDecision)
	}
}

func TestReadinessBlocksFailures(t *testing.T) {
	set, err := GenerateAdversarialFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	descriptor := set.DescriptorAbuse
	descriptor.Conclusion = "failed"
	blocked := BuildM27ReadinessReport(descriptor, set.Lifecycle, set.Pressure, set.ResetError, set.MappingCollapse, set.Parity)
	if blocked.GoNoGoDecision != DecisionBlockedDescriptor {
		t.Fatalf("descriptor failure did not block readiness: %s", blocked.GoNoGoDecision)
	}
	parity := set.Parity
	parity.Conclusion = "failed"
	blocked = BuildM27ReadinessReport(set.DescriptorAbuse, set.Lifecycle, set.Pressure, set.ResetError, set.MappingCollapse, parity)
	if blocked.GoNoGoDecision != DecisionBlockedParity {
		t.Fatalf("parity failure did not block readiness: %s", blocked.GoNoGoDecision)
	}
}

func TestAdversarialFixtureComparisonAndHygiene(t *testing.T) {
	set, err := GenerateAdversarialFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAdversarialFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if cmp := CompareAdversarialFixtureSets(set, set); cmp.Conclusion != "passed" {
		t.Fatalf("self comparison failed: %#v", cmp)
	}
	if err := ScanFixtureHygiene(map[string]string{"endpoint": "synthetic"}); err == nil {
		t.Fatal("endpoint fixture field accepted")
	}
	if err := ScanFixtureHygiene(map[string]string{"payload": "synthetic"}); err == nil {
		t.Fatal("payload fixture field accepted")
	}
	if err := ScanFixtureHygiene(map[string]string{"secret": "synthetic"}); err == nil {
		t.Fatal("secret fixture field accepted")
	}
}

func FuzzAdversarialCorpusParser(f *testing.F) {
	set, err := GenerateAdversarialFixtureSet(context.Background())
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := StableJSON(set.Corpus)
	f.Add(raw)
	f.Add([]byte(`{"version":"bad"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		var corpus AdversarialIngressCorpus
		if err := json.Unmarshal(data, &corpus); err != nil {
			return
		}
		_ = ValidateCorpus(corpus)
	})
}

func BenchmarkAdversarialCorpusValidation(b *testing.B) {
	corpus, err := BuildAdversarialCorpus()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ValidateCorpus(corpus); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDescriptorAbuseValidation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if err := ValidateDescriptorAbuseReport(RunDescriptorAbuseHardening()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadinessReport(b *testing.B) {
	set, err := GenerateAdversarialFixtureSet(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report := BuildM27ReadinessReport(set.DescriptorAbuse, set.Lifecycle, set.Pressure, set.ResetError, set.MappingCollapse, set.Parity)
		if report.GoNoGoDecision != DecisionGoForLocalProxyEgress {
			b.Fatal(report.GoNoGoDecision)
		}
	}
}
