// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"kurdistan/internal/adaptivepath"
	"kurdistan/internal/mutant"
)

type AdaptivePathAuditSummary struct {
	Version             string                                    `json:"version"`
	CandidateFamilies   int                                       `json:"candidate_families"`
	ConditionClasses    int                                       `json:"condition_classes"`
	CandidateCount      int                                       `json:"candidate_count"`
	ObservationCount    int                                       `json:"observation_count"`
	RejectedCandidates  int                                       `json:"rejected_candidates"`
	HighRiskCandidates  int                                       `json:"high_risk_candidates"`
	StaleObservations   int                                       `json:"stale_observations"`
	ExpiredObservations int                                       `json:"expired_observations"`
	FixtureComparison   adaptivepath.AdaptivePathComparisonReport `json:"fixture_comparison"`
	MisuseConclusion    string                                    `json:"misuse_conclusion"`
	GeneratedParity     string                                    `json:"generated_parity"`
	PublicDocsCleanup   string                                    `json:"public_docs_cleanup"`
	Conclusion          string                                    `json:"conclusion"`
}

func RunAdaptivePathAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := adaptivepath.GenerateFixtureSet(ctx)
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := adaptivePathFixtureComparison(ctx, filepath.Join(root, "testdata", "adaptivepath", "path-candidates-golden.json"), set)
	gates := AdaptivePathGates(set, comparison)
	docsGate := AdaptivePathRoadmapPublicDocsGate()
	gates = append(gates, docsGate)
	summary := AdaptivePathAuditSummary{
		Version:             string(adaptivepath.Version),
		CandidateFamilies:   len(set.Families),
		ConditionClasses:    len(set.Conditions),
		CandidateCount:      len(set.Candidates),
		ObservationCount:    len(set.Observations),
		RejectedCandidates:  set.DecisionInputs.RejectedCandidates,
		HighRiskCandidates:  set.DecisionInputs.HighRiskCandidates,
		StaleObservations:   set.Freshness.StaleObservations,
		ExpiredObservations: set.Freshness.ExpiredObservations,
		FixtureComparison:   comparison,
		MisuseConclusion:    set.MisuseReport.Conclusion,
		GeneratedParity:     set.Parity.Conclusion,
		PublicDocsCleanup:   gateStatus(docsGate),
		Conclusion:          "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "adaptivepath-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
		TraceCount:       0,
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

func AdaptivePathGates(set adaptivepath.AdaptivePathFixtureSet, comparison adaptivepath.AdaptivePathComparisonReport) []GateResult {
	return []GateResult{
		AdaptivePathCandidateTaxonomyGate(set),
		AdaptivePathConditionModelGate(set),
		AdaptivePathFreshnessUncertaintyGate(set),
		AdaptivePathViabilityEvaluationGate(set),
		AdaptivePathDecisionInputsGate(set),
		AdaptivePathMisuseDetectionGate(set),
		AdaptivePathGeneratedBackendParityGate(set),
		AdaptivePathTraceHygieneGate(set),
		AdaptivePathMutantDetectionGate(set),
		AdaptivePathFixtureDriftGate(comparison),
	}
}

func AdaptivePathCandidateTaxonomyGate(set adaptivepath.AdaptivePathFixtureSet) GateResult {
	failures := []string{}
	for _, desc := range set.Families {
		if err := adaptivepath.ValidateFamilyDescriptor(desc); err != nil {
			failures = append(failures, err.Error())
		}
		if (desc.HighRisk || desc.Experimental) && !desc.Gated {
			failures = append(failures, string(desc.Family)+" risky family not gated")
		}
		if desc.Family == adaptivepath.CandidateDomesticMediaRisk && desc.DefaultEligible {
			failures = append(failures, "domestic media risk default eligible")
		}
	}
	if len(set.Families) < 7 {
		failures = append(failures, "missing required candidate families")
	}
	return gate("adaptivepath_candidate_taxonomy", len(failures) == 0, "required", fmt.Sprintf("%d candidate families checked", len(set.Families)), map[string]any{
		"version":  string(adaptivepath.Version),
		"families": len(set.Families),
	}, failures)
}

func AdaptivePathConditionModelGate(set adaptivepath.AdaptivePathFixtureSet) GateResult {
	failures := []string{}
	for _, condition := range set.Conditions {
		if err := adaptivepath.ValidateCondition(condition); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(set.Conditions) < 21 {
		failures = append(failures, "missing required synthetic condition classes")
	}
	return gate("adaptivepath_condition_model", len(failures) == 0, "required", fmt.Sprintf("%d synthetic conditions checked", len(set.Conditions)), nil, failures)
}

func AdaptivePathFreshnessUncertaintyGate(set adaptivepath.AdaptivePathFixtureSet) GateResult {
	failures := []string{}
	if set.Freshness.ObservationCount != len(set.Observations) {
		failures = append(failures, "freshness observation count mismatch")
	}
	if set.Freshness.StaleObservations == 0 || set.Freshness.ExpiredObservations == 0 {
		failures = append(failures, "stale/expired observation controls missing")
	}
	if set.Freshness.UncertaintyBucket == "" || set.Freshness.Conclusion != "passed" {
		failures = append(failures, "freshness uncertainty report failed")
	}
	return gate("adaptivepath_freshness_uncertainty", len(failures) == 0, "required", fmt.Sprintf("%d fresh, %d stale, %d expired observations", set.Freshness.FreshObservations, set.Freshness.StaleObservations, set.Freshness.ExpiredObservations), map[string]any{"freshness": set.Freshness}, failures)
}

func AdaptivePathViabilityEvaluationGate(set adaptivepath.AdaptivePathFixtureSet) GateResult {
	failures := []string{}
	stateByFamily := map[string]string{}
	for _, report := range set.ViabilityReports {
		if err := adaptivepath.ValidateViabilityReport(report); err != nil {
			failures = append(failures, err.Error())
		}
		stateByFamily[report.Family] = report.CurrentState
	}
	expect := map[string]string{
		string(adaptivepath.CandidateDNSSurvival):      string(adaptivepath.CandidateRejected),
		string(adaptivepath.CandidateHTTPSLikeTCP):     string(adaptivepath.CandidateBlocked),
		string(adaptivepath.CandidateExperimentalUDP):  string(adaptivepath.CandidateDegraded),
		string(adaptivepath.CandidateRelayRotation):    string(adaptivepath.CandidateBurned),
		string(adaptivepath.CandidateCollapsedControl): string(adaptivepath.CandidateRejected),
	}
	for family, state := range expect {
		if stateByFamily[family] != state {
			failures = append(failures, fmt.Sprintf("%s state=%s want %s", family, stateByFamily[family], state))
		}
	}
	return gate("adaptivepath_viability_evaluation", len(failures) == 0, "required", fmt.Sprintf("%d viability reports generated", len(set.ViabilityReports)), map[string]any{"states": stateByFamily}, failures)
}

func AdaptivePathDecisionInputsGate(set adaptivepath.AdaptivePathFixtureSet) GateResult {
	failures := []string{}
	if err := adaptivepath.ValidateDecisionSet(set.DecisionInputs); err != nil {
		failures = append(failures, err.Error())
	}
	if set.DecisionInputs.CandidateCount != len(set.Candidates) || len(set.DecisionInputs.Inputs) != len(set.Candidates) {
		failures = append(failures, "decision input count mismatch")
	}
	if set.DecisionInputs.HighRiskCandidates == 0 || set.DecisionInputs.RejectedCandidates == 0 {
		failures = append(failures, "decision inputs missing high-risk or rejected candidate controls")
	}
	return gate("adaptivepath_decision_inputs", len(failures) == 0, "required", fmt.Sprintf("%d decision inputs built; no winner selected", len(set.DecisionInputs.Inputs)), map[string]any{"decision_set_hash": set.DecisionInputs.DecisionSetHash}, failures)
}

func AdaptivePathMisuseDetectionGate(set adaptivepath.AdaptivePathFixtureSet) GateResult {
	failures := []string{}
	if set.MisuseReport.Conclusion != "passed" {
		failures = append(failures, set.MisuseReport.MisuseFindings...)
	}
	if set.CollapsedControl.Conclusion != "failed" || len(set.CollapsedControl.MisuseFindings) == 0 {
		failures = append(failures, "collapsed control not detected")
	}
	return gate("adaptivepath_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("healthy findings=%d; control findings=%d", len(set.MisuseReport.MisuseFindings), len(set.CollapsedControl.MisuseFindings)), map[string]any{"collapsed_control": set.CollapsedControl}, failures)
}

func AdaptivePathGeneratedBackendParityGate(set adaptivepath.AdaptivePathFixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.PayloadLogged || set.Parity.SecretLogged {
		failures = append(failures, set.Parity.UnexpectedDifferences...)
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"adaptivepath_generated.go", "adaptivepath_test.go", "adaptivepath_parity_test.go", "adaptivepath_hygiene_test.go", "AdaptivePathSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated adaptivepath marker "+marker)
				}
			}
		}
	}
	return gate("adaptivepath_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d candidates and %d conditions compared", set.Parity.ComparedCandidates, set.Parity.ComparedConditions), nil, failures)
}

func AdaptivePathTraceHygieneGate(set adaptivepath.AdaptivePathFixtureSet) GateResult {
	failures := []string{}
	if err := adaptivepath.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	for _, tc := range []map[string]string{
		{"endpoint": "synthetic"},
		{"dns_query": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
		{"cloud_provider": "synthetic"},
	} {
		if err := adaptivepath.ScanForLeak(tc); err == nil {
			failures = append(failures, "unsafe adaptivepath metadata accepted")
		}
	}
	return gate("adaptivepath_trace_hygiene", len(failures) == 0, "required", "adaptive path fixtures contain safe metadata only", nil, failures)
}

func AdaptivePathMutantDetectionGate(set adaptivepath.AdaptivePathFixtureSet) GateResult {
	required := []string{
		mutant.ModeAdaptivePathAllCandidatesSameFamily,
		mutant.ModeAdaptivePathStaleSuccessIsFresh,
		mutant.ModeAdaptivePathIgnoresRecentFailure,
		mutant.ModeAdaptivePathIgnoresRelayBurn,
		mutant.ModeAdaptivePathIgnoresDNSPoisoning,
		mutant.ModeAdaptivePathIgnoresTCPBlackhole,
		mutant.ModeAdaptivePathIgnoresUDPBlock,
		mutant.ModeAdaptivePathHighRiskDefaultEligible,
		mutant.ModeAdaptivePathUnknownMarkedUsable,
		mutant.ModeAdaptivePathEndpointLeak,
		mutant.ModeAdaptivePathPayloadLeak,
		mutant.ModeAdaptivePathSecretLeak,
		mutant.ModeAdaptivePathGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	if set.CollapsedControl.Conclusion != "failed" {
		failures = append(failures, "adaptivepath collapsed control not detected")
	}
	if err := adaptivepath.ScanForLeak(map[string]string{"endpoint": "synthetic"}); err == nil {
		failures = append(failures, "endpoint leak mutant not detected")
	}
	return gate("adaptivepath_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d mutants represented", len(required)-len(failures)), nil, failures)
}

func AdaptivePathFixtureDriftGate(report adaptivepath.AdaptivePathComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("adaptivepath_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func AdaptivePathRoadmapPublicDocsGate() GateResult {
	failures := []string{}
	root, err := repoRoot()
	if err != nil {
		failures = append(failures, err.Error())
		return gate("adaptivepath_roadmap_public_docs", false, "required", "repository root unavailable", nil, failures)
	}
	read := func(rel string) string {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			failures = append(failures, rel+": "+err.Error())
			return ""
		}
		return string(raw)
	}
	readme := read("README.md")
	index := read("docs/index.html")
	indexText := htmlText(index)
	siteJS := read("docs/site.js")
	kip34 := read("docs/KIP-0034-generated-transport-bundle-compiler.md")
	kip34Lower := strings.ToLower(kip34)
	if strings.Contains(readme, "## Current Status") || strings.Contains(readme, "| Milestone | Status |") {
		failures = append(failures, "README still contains public current-status table")
	}
	if strings.Contains(index, "Current Status") || strings.Contains(index, `id="milestones"`) || strings.Contains(index, "<h2>Milestones</h2>") || strings.Contains(index, "| Milestone | Status |") {
		failures = append(failures, "docs site still contains public milestone/status table")
	}
	for _, required := range []string{
		"M27: adaptive path model and candidate taxonomy",
		"M28: generated transport bundle compiler",
		"M33: local proxy egress and relay bridge model",
		"M36: concrete local socket adapter",
	} {
		if !strings.Contains(readme, required) && !strings.Contains(index, required) {
			failures = append(failures, "roadmap missing "+required)
		}
	}
	for _, required := range []string{
		"Polymorphic transport compiler",
		"adaptive censorship-resistance",
		"Adaptive runtime direction",
		"Boundaries and safety",
		"Compiler lane",
		"Adaptive lane",
		"Safety lane",
	} {
		if !strings.Contains(indexText, required) {
			failures = append(failures, "docs site missing "+required)
		}
	}
	if !strings.Contains(index, "KIP-0034-generated-transport-bundle-compiler.md") {
		failures = append(failures, "docs site missing KIP-0034-generated-transport-bundle-compiler.md")
	}
	for _, required := range []string{"M27", "M28", "M29", "M30", "M31", "M32", "M33", "M34", "M35", "M36"} {
		if !strings.Contains(index, required) {
			failures = append(failures, "docs site missing roadmap marker "+required)
		}
	}
	for _, required := range []string{
		"generated transport bundle compiler",
		"transportbundle_policy_validation",
		"path racing and short-lived revalidation",
	} {
		if !strings.Contains(kip34Lower, required) {
			failures = append(failures, "KIP-0034 missing "+required)
		}
	}
	if strings.Contains(readme, "M27: local proxy egress") || strings.Contains(index, "M27: local proxy egress") {
		failures = append(failures, "old M27 local proxy egress roadmap remains")
	}
	failures = append(failures, publicClaimFailures("README.md", readme)...)
	failures = append(failures, publicClaimFailures("docs/index.html", index)...)
	failures = append(failures, siteStructureFailures(root, index)...)
	if strings.Contains(readme, "AGENTS.md") || strings.Contains(index, "AGENTS.md") {
		failures = append(failures, "public docs reference local-only instruction file")
	}
	for _, forbidden := range []string{"src=\"http://", "src=\"https://", "googletagmanager", "google-analytics", "analytics", "cdn.jsdelivr", "unpkg.com", "fonts.googleapis", "fonts.gstatic"} {
		if strings.Contains(strings.ToLower(index), forbidden) || strings.Contains(strings.ToLower(siteJS), forbidden) {
			failures = append(failures, "public site includes external dependency or analytics marker "+forbidden)
		}
	}
	for _, forbidden := range []string{"raw payload", "raw bytes", "endpoint", "resolver", "dns query"} {
		if strings.Contains(strings.ToLower(index), forbidden) {
			failures = append(failures, "public site includes unsafe fixture-like term "+forbidden)
		}
	}
	return gate("adaptivepath_roadmap_public_docs", len(failures) == 0, "required", "public adaptive site, roadmap, links, and claim-safety checked", nil, failures)
}

func publicClaimFailures(name, content string) []string {
	failures := []string{}
	for _, line := range strings.Split(content, "\n") {
		lower := strings.ToLower(line)
		for _, phrase := range []string{
			"guaranteed bypass",
			"undetectable",
			"impossible to detect",
			"field-ready",
			"production vpn",
			"working vpn app",
			"live probing",
			"real dns probing",
			"real https probing",
			"real udp probing",
		} {
			if strings.Contains(lower, phrase) && !negatesUnsafeClaim(lower) {
				failures = append(failures, name+" contains unsafe public claim phrase "+phrase)
			}
		}
	}
	return failures
}

func negatesUnsafeClaim(line string) bool {
	for _, marker := range []string{"no ", "not ", "does not ", "without ", "distinct from ", "doesn't "} {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

func htmlText(content string) string {
	withoutTags := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(content, " ")
	return strings.Join(strings.Fields(withoutTags), " ")
}

func siteStructureFailures(root, index string) []string {
	failures := []string{}
	ids := map[string]int{}
	for _, match := range regexp.MustCompile(`\sid="([^"]+)"`).FindAllStringSubmatch(index, -1) {
		ids[match[1]]++
	}
	for id, count := range ids {
		if count > 1 {
			failures = append(failures, "docs site has duplicate id "+id)
		}
	}
	hrefRE := regexp.MustCompile(`href="([^"]+)"`)
	for _, match := range hrefRE.FindAllStringSubmatch(index, -1) {
		href := match[1]
		if strings.HasPrefix(href, "#") {
			id := strings.TrimPrefix(href, "#")
			if id != "" && ids[id] == 0 {
				failures = append(failures, "nav/local anchor missing section id "+href)
			}
			continue
		}
		if strings.HasPrefix(href, "https://github.com/saroo98/kurdistan-protocol-compiler/blob/main/") {
			rel := strings.TrimPrefix(href, "https://github.com/saroo98/kurdistan-protocol-compiler/blob/main/")
			if !fileExists(root, rel) {
				failures = append(failures, "GitHub docs link target missing "+rel)
			}
			continue
		}
		if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") || strings.HasPrefix(href, "mailto:") {
			continue
		}
		clean := strings.Split(strings.Split(href, "#")[0], "?")[0]
		if clean == "" || strings.HasPrefix(clean, "assets/") {
			continue
		}
		rel := filepath.ToSlash(filepath.Join("docs", filepath.FromSlash(clean)))
		if !fileExists(root, rel) {
			failures = append(failures, "docs site link target missing "+clean)
		}
	}
	return failures
}

func fileExists(root, rel string) bool {
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil && !info.IsDir()
}

func adaptivePathFixtureComparison(ctx context.Context, path string, current adaptivepath.AdaptivePathFixtureSet) adaptivepath.AdaptivePathComparisonReport {
	oldSet, err := adaptivepath.LoadFixtureSet(path)
	if err != nil {
		return adaptivepath.AdaptivePathComparisonReport{Version: string(adaptivepath.Version), NewHash: current.FixtureSetHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	regenerated, err := adaptivepath.GenerateFixtureSet(ctx)
	if err != nil {
		return adaptivepath.AdaptivePathComparisonReport{Version: string(adaptivepath.Version), OldHash: oldSet.FixtureSetHash, NewHash: current.FixtureSetHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return adaptivepath.CompareFixtureSets(oldSet, regenerated)
}

func gateStatus(g GateResult) string {
	if g.Passed {
		return "passed"
	}
	return "failed"
}
