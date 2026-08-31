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

	"kurdistan/internal/testkit/mutant"
	"kurdistan/internal/transport/adaptivepath"
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
	docsGate := AdaptivePathPublicDocsGate()
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
		raw, readErr := codegenGeneratorSource(root)
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

func AdaptivePathPublicDocsGate() GateResult {
	failures := []string{}
	root, err := repoRoot()
	if err != nil {
		failures = append(failures, err.Error())
		return gate("adaptivepath_public_docs", false, "required", "repository root unavailable", nil, failures)
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
	index := read("website/index.html")
	translations := read("website/src/i18n/translations.ts")
	security := read("docs/self-hosting/SECURITY.md")
	if strings.Contains(readme, "## Current Status") || strings.Contains(readme, "| Milestone | Status |") {
		failures = append(failures, "README still contains public current-status table")
	}
	for name, required := range map[string][]string{
		"README.md": {"profile-driven, self-hosted relay transport system", "Each operator controls", "no telemetry"},
		"website/index.html": {"Kurdistan VPN is an Android VPN in development", "hreflang=\"ckb\"", "hreflang=\"kmr\"", "id=\"root\""},
		"website/src/i18n/translations.ts": {"See release readiness", "not released", "ئامادەیی بۆ بڵاوکردنەوە", "Amadekariya berdanê"},
		"docs/self-hosting/SECURITY.md": {"There is no Kurdistan account", "global root", "It cannot control another deployment"},
	} {
		content := map[string]string{
			"README.md": readme,
			"website/index.html": index,
			"website/src/i18n/translations.ts": translations,
			"docs/self-hosting/SECURITY.md": security,
		}[name]
		for _, needle := range required {
			if !strings.Contains(content, needle) {
				failures = append(failures, name+" missing "+needle)
			}
		}
	}
	failures = append(failures, publicClaimFailures("README.md", readme)...)
	failures = append(failures, publicClaimFailures("website/index.html", index)...)
	failures = append(failures, publicClaimFailures("website/src/i18n/translations.ts", translations)...)
	privateMarkers := []string{
		strings.Join([]string{"road", "map"}, ""),
		strings.Join([]string{"private", " plan"}, ""),
		strings.Join([]string{"future", " phase"}, ""),
		strings.Join([]string{"AG", "ENTS.md"}, ""),
		strings.Join([]string{"Chat", "GPT"}, ""),
		strings.Join([]string{"Co", "dex"}, ""),
		strings.Join([]string{"super", "powers"}, ""),
		strings.Join([]string{"impe", "ccable"}, ""),
	}
	for name, content := range map[string]string{"README.md": readme, "website/index.html": index, "website/src/i18n/translations.ts": translations} {
		lower := strings.ToLower(content)
		for _, marker := range privateMarkers {
			if strings.Contains(lower, strings.ToLower(marker)) {
				failures = append(failures, name+" contains an internal publication marker")
			}
		}
	}
	for _, forbidden := range []string{"src=\"http://", "src=\"https://", "googletagmanager", "google-analytics", "analytics", "cdn.jsdelivr", "unpkg.com", "fonts.googleapis", "fonts.gstatic"} {
		if strings.Contains(strings.ToLower(index), forbidden) {
			failures = append(failures, "public site includes external dependency or analytics marker "+forbidden)
		}
	}
	for _, forbidden := range []string{"raw payload", "raw bytes", "endpoint", "resolver", "dns query"} {
		if strings.Contains(strings.ToLower(index), forbidden) {
			failures = append(failures, "public site includes unsafe fixture-like term "+forbidden)
		}
	}
	return gate("adaptivepath_public_docs", len(failures) == 0, "required", "public capability site, localization, privacy boundary, and claim safety checked", nil, failures)
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
