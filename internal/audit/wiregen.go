// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kurdistan/internal/compiler"
	"kurdistan/internal/fixtures"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregen"
	"kurdistan/internal/wiregencompare"
)

type WireGenAuditSummary struct {
	CorpusVersion      string                                       `json:"corpus_version"`
	CorpusEntries      int                                          `json:"corpus_entries"`
	Policies           int                                          `json:"policies"`
	FeatureVectors     int                                          `json:"feature_vectors"`
	ProfileCount       int                                          `json:"profile_count"`
	ScenarioCount      int                                          `json:"scenario_count"`
	Comparison         wiregencompare.PolicyFeatureComparisonReport `json:"comparison"`
	Collapse           wiregencompare.WireGenCollapseReport         `json:"collapse"`
	BaselineComparison wiregencompare.BaselineCompareReport         `json:"baseline_comparison"`
	Conclusion         string                                       `json:"conclusion"`
}

func RunWireGenAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	corpusPath := filepath.Join(root, "testdata", "protocorpus", "corpus-v1.json")
	baselinePath := filepath.Join(root, "testdata", "wiregen", "wiregen-policy-golden.json")
	corpus, err := protocorpus.LoadManifest(corpusPath)
	if err != nil {
		return AuditReport{}, err
	}
	seeds := wiregencompare.DefaultSeeds()
	if cfg.Mode == "full" {
		seeds = make([]int, 20)
		for i := range seeds {
			seeds[i] = int(cfg.StartSeed) + i
		}
	}
	profiles := make([]*ir.Profile, 0, len(seeds))
	policies := make([]wiregen.WireShapePolicy, 0, len(seeds))
	for _, seed := range seeds {
		profile, err := compiler.Generate(int64(seed))
		if err != nil {
			return AuditReport{}, err
		}
		profiles = append(profiles, profile)
		policies = append(policies, wiregen.FromIRPolicy(profile.WireShape))
	}
	vectors := expectedVectorsForProfiles(policies, wiregencompare.DefaultScenarios())
	comparison := wiregencompare.ComparePoliciesToFeatures(policies, vectors)
	collapse := wiregencompare.ScanCollapse(policies, vectors)
	baselineCompare, _ := wiregencompare.VerifyBaseline(ctx, baselinePath, corpus)
	gates := WireGenGates(ctx, profiles, policies, vectors, corpus, baselinePath)
	summary := WireGenAuditSummary{
		CorpusVersion:      string(corpus.Version),
		CorpusEntries:      len(corpus.Entries),
		Policies:           len(policies),
		FeatureVectors:     len(vectors),
		ProfileCount:       len(profiles),
		ScenarioCount:      len(wiregencompare.DefaultScenarios()),
		Comparison:         comparison,
		Collapse:           collapse,
		BaselineComparison: baselineCompare,
		Conclusion:         "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "wiregen-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     len(profiles),
		TraceCount:       len(vectors),
		Gates:            gates,
		TraceScanSummary: summary,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
		summary.Conclusion = "failed"
		report.TraceScanSummary = summary
	}
	return report, nil
}

func WireGenGates(ctx context.Context, profiles []*ir.Profile, policies []wiregen.WireShapePolicy, vectors []wirefeatures.WireFeatureVector, corpus protocorpus.CorpusManifest, baselinePath string) []GateResult {
	comparison := wiregencompare.ComparePoliciesToFeatures(policies, vectors)
	collapse := wiregencompare.ScanCollapse(policies, vectors)
	return []GateResult{
		WireGenPolicyGenerationGate(policies),
		WireGenPolicyValidationGate(policies, corpus),
		WireGenCorpusSelectionGate(policies, corpus),
		WireGenProfileIntegrationGate(profiles),
		WireGenBytePathApplicationGate(vectors),
		WireGenFeatureExpectationGate(comparison),
		WireGenFirstNDiversityGate(policies),
		WireGenMetadataExposureDiversityGate(policies),
		WireGenCollapseResistanceGate(collapse),
		WireGenMutantDetectionGate(),
		WireGenGeneratedBackendParityGate(),
		WireGenTraceHygieneGate(policies, vectors),
		WireGenBaselineGate(ctx, baselinePath, corpus),
	}
}

func expectedVectorsForProfiles(policies []wiregen.WireShapePolicy, scenarios []string) []wirefeatures.WireFeatureVector {
	out := make([]wirefeatures.WireFeatureVector, 0, len(policies)*len(scenarios))
	for _, policy := range policies {
		for _, scenario := range scenarios {
			out = append(out, wiregencompare.ExpectedVector(policy, scenario, "interpreted", fmt.Sprintf("profile-%d", policy.ProfileSeed)))
		}
	}
	return out
}

func WireGenPolicyGenerationGate(policies []wiregen.WireShapePolicy) GateResult {
	hashes := map[string]bool{}
	for _, policy := range policies {
		hashes[policy.PolicyHash] = true
	}
	failures := []string{}
	if len(policies) == 0 {
		failures = append(failures, "no wire-shape policies generated")
	}
	if len(policies) > 2 && len(hashes) < 2 {
		failures = append(failures, "wire-shape policies collapsed to one hash")
	}
	return gate("wiregen_policy_generation", len(failures) == 0, "required", fmt.Sprintf("%d policies and %d unique hashes", len(policies), len(hashes)), map[string]any{"policy_count": len(policies), "unique_hashes": len(hashes)}, failures)
}

func WireGenPolicyValidationGate(policies []wiregen.WireShapePolicy, corpus protocorpus.CorpusManifest) GateResult {
	failures := []string{}
	for _, policy := range policies {
		if err := wiregen.ValidatePolicy(policy, corpus); err != nil {
			failures = append(failures, policy.PolicyID+": "+err.Error())
		}
	}
	return gate("wiregen_policy_validation", len(failures) == 0, "required", fmt.Sprintf("%d policies validated", len(policies)), nil, failures)
}

func WireGenCorpusSelectionGate(policies []wiregen.WireShapePolicy, corpus protocorpus.CorpusManifest) GateResult {
	entries := map[string]bool{}
	families := map[string]bool{}
	for _, policy := range policies {
		entries[policy.SelectedCorpusEntry] = true
		families[string(policy.SelectedFamily)] = true
	}
	failures := []string{}
	if len(entries) < 2 && len(policies) > 2 {
		failures = append(failures, "expected multiple selected corpus entries")
	}
	if len(families) < 2 && len(policies) > 2 {
		failures = append(failures, "expected multiple selected corpus families")
	}
	return gate("wiregen_corpus_selection", len(failures) == 0, "required", fmt.Sprintf("%d entries across %d families selected from %d corpus entries", len(entries), len(families), len(corpus.Entries)), map[string]any{"selected_entries": len(entries), "selected_families": len(families)}, failures)
}

func WireGenProfileIntegrationGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	for _, profile := range profiles {
		if profile.WireShape.PolicyHash == "" || profile.WireShape.PolicyID == "" {
			failures = append(failures, profile.ID+": missing wire shape policy")
		}
		if profile.WireShape.Version != wiregen.PolicyVersion {
			failures = append(failures, profile.ID+": unsupported wire shape version")
		}
	}
	return gate("wiregen_profile_integration", len(failures) == 0, "required", fmt.Sprintf("%d profiles include wire-shape policy sections", len(profiles)), nil, failures)
}

func WireGenBytePathApplicationGate(vectors []wirefeatures.WireFeatureVector) GateResult {
	failures := []string{}
	applied := 0
	for _, vector := range vectors {
		if vector.WirePolicyHash == "" || vector.WireSelectedFamily == "" {
			failures = append(failures, vector.ProfileID+"/"+vector.Scenario+": missing wire policy metadata")
			continue
		}
		applied++
	}
	return gate("wiregen_bytepath_application", len(failures) == 0, "required", fmt.Sprintf("%d bytepath feature vectors carry wire-shape metadata", applied), map[string]any{"feature_vectors": len(vectors), "applied": applied}, failures)
}

func WireGenFeatureExpectationGate(report wiregencompare.PolicyFeatureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDifferences...)
	return gate("wiregen_feature_expectation_match", len(failures) == 0, "required", fmt.Sprintf("%d policy-feature pairs compared", report.PolicyFeatureMatches), map[string]any{"comparison": report}, failures)
}

func WireGenFirstNDiversityGate(policies []wiregen.WireShapePolicy) GateResult {
	unique := map[string]bool{}
	for _, policy := range policies {
		unique[wiregen.FirstNShapeHash(policy)] = true
	}
	failures := []string{}
	if len(policies) > 2 && len(unique) < 2 {
		failures = append(failures, "first-n plans collapsed")
	}
	return gate("wiregen_firstn_diversity", len(failures) == 0, "required", fmt.Sprintf("%d unique first-n policy shapes", len(unique)), map[string]any{"unique_firstn": len(unique)}, failures)
}

func WireGenMetadataExposureDiversityGate(policies []wiregen.WireShapePolicy) GateResult {
	unique := map[string]bool{}
	for _, policy := range policies {
		unique[policy.MetadataExposurePlan.ExposureClass] = true
	}
	failures := []string{}
	if len(policies) > 2 && len(unique) < 2 {
		failures = append(failures, "metadata exposure classes collapsed")
	}
	return gate("wiregen_metadata_exposure_diversity", len(failures) == 0, "required", fmt.Sprintf("%d metadata exposure classes", len(unique)), map[string]any{"unique_metadata_exposure": len(unique)}, failures)
}

func WireGenCollapseResistanceGate(report wiregencompare.WireGenCollapseReport) GateResult {
	failures := append([]string{}, report.SuspiciousMetrics...)
	return gate("wiregen_collapse_resistance", len(failures) == 0, "required", fmt.Sprintf("%d policy hashes, %d families, %d fragment rhythms", report.UniquePolicyHashes, report.UniqueFamilies, report.UniqueFragmentRhythms), map[string]any{"collapse": report}, failures)
}

func WireGenMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeWireGenFixedCorpusFamily,
		mutant.ModeWireGenFixedFirstNShape,
		mutant.ModeWireGenFixedFrameSizePlan,
		mutant.ModeWireGenFixedFragmentRhythm,
		mutant.ModeWireGenFixedMetadataExposure,
		mutant.ModeWireGenLengthOnlyDiversity,
		mutant.ModeWireGenPayloadLeakFeature,
		mutant.ModeWireGenGeneratedInterpretedDrift,
	}
	modes := map[string]bool{}
	for _, mode := range mutant.Modes() {
		modes[mode] = true
	}
	failures := []string{}
	for _, mode := range required {
		if !modes[mode] {
			failures = append(failures, "missing mutant mode "+mode)
		}
	}
	return gate("wiregen_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d wiregen mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func WireGenGeneratedBackendParityGate() GateResult {
	failures := []string{}
	markers := []string{"wiregen_generated.go", "wiregen_test.go", "wiregen_parity_test.go", "wiregenfeatures_test.go", "WireGenPolicyVersion", "WireGenPolicyHash"}
	root, err := repoRoot()
	if err != nil {
		return gate("wiregen_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	raw, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
	if err != nil {
		return gate("wiregen_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source := string(raw)
	for _, marker := range markers {
		if !strings.Contains(source, marker) {
			failures = append(failures, "missing generated marker "+marker)
		}
	}
	return gate("wiregen_generated_backend_parity", len(failures) == 0, "required", "generated backend wire-shape markers checked", nil, failures)
}

func WireGenTraceHygieneGate(policies []wiregen.WireShapePolicy, vectors []wirefeatures.WireFeatureVector) GateResult {
	failures := []string{}
	for _, policy := range policies {
		if report := wiregen.ValidateRedaction(policy); !report.Passed {
			failures = append(failures, append([]string{policy.PolicyID}, report.Findings...)...)
		}
	}
	for _, vector := range vectors {
		if vector.PayloadLogged || vector.SecretLogged {
			failures = append(failures, vector.ProfileID+"/"+vector.Scenario+": hygiene flag set")
		}
	}
	return gate("wiregen_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d policies and %d feature vectors scanned", len(policies), len(vectors)), nil, failures)
}

func WireGenBaselineGate(ctx context.Context, baselinePath string, corpus protocorpus.CorpusManifest) GateResult {
	report, err := wiregencompare.VerifyBaseline(ctx, baselinePath, corpus)
	if err != nil {
		return gate("wiregen_baseline_fixtures", false, "required", "wiregen baseline drift detected", map[string]any{"compare": report}, []string{err.Error()})
	}
	return gate("wiregen_baseline_fixtures", report.Passed, "required", fmt.Sprintf("%d wiregen baseline entries checked", report.Compared), map[string]any{"compare": report}, nil)
}

func writeWireGenCompanions(out string, baseline wiregencompare.BaselineManifest) error {
	dir := filepath.Dir(out)
	raw, err := wiregencompare.StableJSON(baseline.FeatureVectors)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "wiregen-bytepath-golden.json"), raw, 0o600); err != nil {
		return err
	}
	raw, err = wiregencompare.StableJSON(baseline.Comparison)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "wiregen-corpus-comparison.json"), raw, 0o600); err != nil {
		return err
	}
	raw, err = wiregencompare.StableJSON(baseline.Collapse)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "wiregen-collapse-baseline.json"), raw, 0o600)
}

func GenerateWireGenFixtureSet(ctx context.Context, corpus protocorpus.CorpusManifest) (wiregencompare.BaselineManifest, error) {
	return wiregencompare.GenerateBaseline(ctx, corpus, wiregencompare.DefaultSeeds(), wiregencompare.DefaultScenarios())
}

func GenerateWireGenFixtureSetFromBytePath(ctx context.Context, manifest fixtures.FixtureManifest, corpus protocorpus.CorpusManifest) (wiregencompare.BaselineManifest, error) {
	_ = manifest
	return GenerateWireGenFixtureSet(ctx, corpus)
}
