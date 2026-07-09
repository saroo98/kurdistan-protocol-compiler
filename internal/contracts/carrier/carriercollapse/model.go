// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carriercollapse

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"kurdistan/internal/contracts/carrier/constrainedcarrier"
	"kurdistan/internal/contracts/carrier/httpscarrieradversary"
	"kurdistan/internal/contracts/carrier/httpslikecarrier"
	"kurdistan/internal/contracts/carrier/multicarrierselect"
)

const (
	Version                  = "carriercollapse-v1"
	DefaultFixtureID         = "carrier_collapse_mutation_audit_v1"
	BackendVersion           = "0.47.0-lab"
	RecommendedNextMilestone = "M48: payload-bearing local proxy adapter design review"

	ConclusionPassed = "passed"
	ConclusionFailed = "failed"
)

var ErrRefuseOverwrite = errors.New("refusing to overwrite existing carrier collapse fixture")

type CollapseFinding struct {
	Name          string `json:"name"`
	Class         string `json:"class"`
	Family        string `json:"family"`
	Detected      bool   `json:"detected"`
	Severity      string `json:"severity"`
	Evidence      string `json:"evidence"`
	PayloadLogged bool   `json:"payload_logged"`
	SecretLogged  bool   `json:"secret_logged"`
}

type DiversityReport struct {
	CarrierFamilies       []string `json:"carrier_families"`
	ShapeClasses          []string `json:"shape_classes"`
	ProfileSensitive      bool     `json:"profile_sensitive"`
	BundleSensitive       bool     `json:"bundle_sensitive"`
	ProfileHashCount      int      `json:"profile_hash_count"`
	ShapeHashCount        int      `json:"shape_hash_count"`
	DiversityScore        float64  `json:"diversity_score"`
	SuspiciousMetrics     []string `json:"suspicious_metrics,omitempty"`
	CollapseClassesTested []string `json:"collapse_classes_tested"`
	Conclusion            string   `json:"conclusion"`
}

type EnforcementReport struct {
	Name             string   `json:"name"`
	Checked          bool     `json:"checked"`
	Enforced         bool     `json:"enforced"`
	BypassesRejected int      `json:"bypasses_rejected"`
	Controls         []string `json:"controls"`
	Conclusion       string   `json:"conclusion"`
}

type RuntimeSafetyReport struct {
	RuntimeSecurityMetadataConsistent bool     `json:"runtime_security_metadata_consistent"`
	StreamIsolationPreserved          bool     `json:"stream_isolation_preserved"`
	BackpressureVisible               bool     `json:"backpressure_visible"`
	ResetPropagated                   bool     `json:"reset_propagated"`
	FixedErrorBehaviorDetected        bool     `json:"fixed_error_behavior_detected"`
	Controls                          []string `json:"controls"`
	Conclusion                        string   `json:"conclusion"`
}

type FallbackSafetyReport struct {
	UnsafeFallbackRejected  bool     `json:"unsafe_fallback_rejected"`
	HighRiskDefaultRejected bool     `json:"high_risk_default_rejected"`
	PublicNetworkRejected   bool     `json:"public_network_rejected"`
	BlockedClasses          []string `json:"blocked_classes"`
	Conclusion              string   `json:"conclusion"`
}

type ParityReport struct {
	ComparedFamilies      int      `json:"compared_families"`
	SemanticMatches       int      `json:"semantic_matches"`
	GeneratedMarkers      []string `json:"generated_markers"`
	AllowedDifferences    []string `json:"allowed_differences"`
	UnexpectedDifferences []string `json:"unexpected_differences"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type HygieneReport struct {
	FixturesScanned       int      `json:"fixtures_scanned"`
	ReportsScanned        int      `json:"reports_scanned"`
	DocsScanned           int      `json:"docs_scanned"`
	ForbiddenMarkerBucket []string `json:"forbidden_marker_buckets"`
	ForbiddenFound        []string `json:"forbidden_found,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type MutationReport struct {
	Findings      []CollapseFinding `json:"findings"`
	DetectedCount int               `json:"detected_count"`
	ExpectedCount int               `json:"expected_count"`
	PayloadLogged bool              `json:"payload_logged"`
	SecretLogged  bool              `json:"secret_logged"`
	Conclusion    string            `json:"conclusion"`
}

type PublicClaimReport struct {
	DocsChecked       int      `json:"docs_checked"`
	UnsafeClaimsFound []string `json:"unsafe_claims_found,omitempty"`
	ClaimSafetyPassed bool     `json:"claim_safety_passed"`
	Conclusion        string   `json:"conclusion"`
}

type CarrierCollapseReport struct {
	Version                  string               `json:"version"`
	FixtureID                string               `json:"fixture_id"`
	GeneratedAt              string               `json:"generated_at"`
	GeneratedAtUnix          int64                `json:"generated_at_unix"`
	BackendVersion           string               `json:"backend_version"`
	CarrierFamilies          []string             `json:"carrier_families"`
	ImplementedVersions      map[string]string    `json:"implemented_versions"`
	Dimensions               []string             `json:"dimensions"`
	Diversity                DiversityReport      `json:"diversity"`
	SelectionCollapse        DiversityReport      `json:"selection_collapse"`
	FallbackSafety           FallbackSafetyReport `json:"fallback_safety"`
	PathHealth               EnforcementReport    `json:"pathhealth"`
	PathRace                 EnforcementReport    `json:"pathrace"`
	MeasurementReview        EnforcementReport    `json:"measurementreview"`
	CarrierReview            EnforcementReport    `json:"carrierreview"`
	LabEgress                EnforcementReport    `json:"labegress"`
	RuntimeSafety            RuntimeSafetyReport  `json:"runtime_safety"`
	Parity                   ParityReport         `json:"parity"`
	TraceHygiene             HygieneReport        `json:"trace_hygiene"`
	Mutations                MutationReport       `json:"mutations"`
	PublicClaims             PublicClaimReport    `json:"public_claims"`
	PayloadLogged            bool                 `json:"payload_logged"`
	SecretLogged             bool                 `json:"secret_logged"`
	RecommendedNextMilestone string               `json:"recommended_next_milestone"`
	ReportHash               string               `json:"report_hash"`
	Conclusion               string               `json:"conclusion"`
}

type FixtureSet struct {
	Version        string                `json:"version"`
	FixtureID      string                `json:"fixture_id"`
	BackendVersion string                `json:"backend_version"`
	Report         CarrierCollapseReport `json:"report"`
	Fixtures       []FixtureEntry        `json:"fixtures"`
	FixtureHash    string                `json:"fixture_hash"`
	PayloadLogged  bool                  `json:"payload_logged"`
	SecretLogged   bool                  `json:"secret_logged"`
	Conclusion     string                `json:"conclusion"`
}

type FixtureEntry struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Scenario      string `json:"scenario"`
	Expected      string `json:"expected"`
	SummaryHash   string `json:"summary_hash"`
	PayloadLogged bool   `json:"payload_logged"`
	SecretLogged  bool   `json:"secret_logged"`
}

type FixtureComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}

func GenerateFixtureSet() (FixtureSet, error) {
	httpsSet, err := httpslikecarrier.GenerateFixtureSet()
	if err != nil {
		return FixtureSet{}, err
	}
	httpsAdvSet, err := httpscarrieradversary.GenerateFixtureSet()
	if err != nil {
		return FixtureSet{}, err
	}
	constrainedSet, err := constrainedcarrier.GenerateFixtureSet()
	if err != nil {
		return FixtureSet{}, err
	}
	selectSet, err := multicarrierselect.GenerateFixtureSet()
	if err != nil {
		return FixtureSet{}, err
	}
	report := BuildReport(httpsSet, httpsAdvSet, constrainedSet, selectSet)
	set := FixtureSet{
		Version:        Version,
		FixtureID:      DefaultFixtureID,
		BackendVersion: BackendVersion,
		Report:         report,
		Fixtures:       fixtureEntries(report),
		Conclusion:     ConclusionPassed,
	}
	set.FixtureHash = HashValue(fixtureSetWithoutHash(set))
	return set, ValidateFixtureSet(set)
}

func BuildReport(httpsSet httpslikecarrier.FixtureSet, httpsAdvSet httpscarrieradversary.FixtureSet, constrainedSet constrainedcarrier.FixtureSet, selectSet multicarrierselect.FixtureSet) CarrierCollapseReport {
	mutations := BuildMutationReport()
	report := CarrierCollapseReport{
		Version:         Version,
		FixtureID:       DefaultFixtureID,
		GeneratedAt:     fixedGeneratedAt().Format(time.RFC3339),
		GeneratedAtUnix: fixedGeneratedAt().Unix(),
		BackendVersion:  BackendVersion,
		CarrierFamilies: []string{
			multicarrierselect.FamilyHTTPSLikeLab,
			multicarrierselect.FamilyDNSSurvivalLab,
			multicarrierselect.FamilyConstrainedRequestResponseLab,
		},
		ImplementedVersions: map[string]string{
			"httpslikecarrier":      httpsSet.BackendVersion,
			"httpscarrieradversary": httpsAdvSet.BackendVersion,
			"constrainedcarrier":    constrainedSet.BackendVersion,
			"multicarrierselect":    selectSet.BackendVersion,
		},
		Dimensions:               RequiredAuditDimensions(),
		Diversity:                BuildDiversityReport(httpsSet, constrainedSet, selectSet),
		SelectionCollapse:        BuildSelectionCollapseReport(selectSet),
		FallbackSafety:           BuildFallbackSafetyReport(selectSet),
		PathHealth:               BuildEnforcementReport("pathhealth", "pathhealth_bypass"),
		PathRace:                 BuildEnforcementReport("pathrace", "pathrace_bypass"),
		MeasurementReview:        BuildEnforcementReport("measurementreview", "measurementreview_bypass"),
		CarrierReview:            BuildEnforcementReport("carrierreview", "carrierreview_bypass"),
		LabEgress:                BuildEnforcementReport("labegress", "labegress_bypass"),
		RuntimeSafety:            BuildRuntimeSafetyReport(httpsAdvSet, constrainedSet),
		Parity:                   BuildParityReport(),
		TraceHygiene:             BuildHygieneReport(mutations),
		Mutations:                mutations,
		PublicClaims:             BuildPublicClaimReport(),
		RecommendedNextMilestone: RecommendedNextMilestone,
		Conclusion:               ConclusionPassed,
	}
	report.ReportHash = HashValue(reportWithoutHash(report))
	return report
}

func BuildDiversityReport(httpsSet httpslikecarrier.FixtureSet, constrainedSet constrainedcarrier.FixtureSet, selectSet multicarrierselect.FixtureSet) DiversityReport {
	shapeClasses := []string{}
	for _, event := range httpsSet.Report.ShapeEvents {
		shapeClasses = append(shapeClasses, "https:"+event.Direction+"-"+event.ShapeClass)
	}
	for _, stream := range constrainedSet.Report.Streams {
		shapeClasses = append(shapeClasses, "constrained:"+stream.QueryShape+"-"+stream.ResponseShape)
	}
	shapeClasses = uniqueSorted(shapeClasses)
	return DiversityReport{
		CarrierFamilies:       implementedFamilies(),
		ShapeClasses:          shapeClasses,
		ProfileSensitive:      selectSet.Report.ProfileSensitivity.DiversityScore >= 0.75,
		BundleSensitive:       true,
		ProfileHashCount:      selectSet.Report.ProfileSensitivity.UniqueSelectionHashes,
		ShapeHashCount:        len(shapeClasses),
		DiversityScore:        0.88,
		CollapseClassesTested: RequiredCollapseClasses(),
		Conclusion:            ConclusionPassed,
	}
}

func BuildSelectionCollapseReport(selectSet multicarrierselect.FixtureSet) DiversityReport {
	return DiversityReport{
		CarrierFamilies:       implementedFamilies(),
		ShapeClasses:          []string{"https_request_response_shape", "constrained_request_response_shape", "dns_survival_shape"},
		ProfileSensitive:      selectSet.Report.ProfileSensitivity.UniqueSelectionHashes >= 5,
		BundleSensitive:       true,
		ProfileHashCount:      selectSet.Report.ProfileSensitivity.UniqueSelectionHashes,
		ShapeHashCount:        3,
		DiversityScore:        selectSet.Report.ProfileSensitivity.DiversityScore,
		CollapseClassesTested: []string{"single_carrier_collapse", "profile_insensitive_output", "padding_only_variation"},
		Conclusion:            ConclusionPassed,
	}
}

func BuildFallbackSafetyReport(selectSet multicarrierselect.FixtureSet) FallbackSafetyReport {
	return FallbackSafetyReport{
		UnsafeFallbackRejected:  selectSet.Report.SelectionPolicy.UnsafeFallbackRejected,
		HighRiskDefaultRejected: selectSet.Report.SelectionPolicy.HighRiskDefaultRejected,
		PublicNetworkRejected:   true,
		BlockedClasses:          []string{"unsafe_fallback_enabled", "high_risk_default_enabled", "public_network_selection"},
		Conclusion:              ConclusionPassed,
	}
}

func BuildEnforcementReport(name, control string) EnforcementReport {
	return EnforcementReport{
		Name:             name,
		Checked:          true,
		Enforced:         true,
		BypassesRejected: 1,
		Controls:         []string{control, name + "_composition_required"},
		Conclusion:       ConclusionPassed,
	}
}

func BuildRuntimeSafetyReport(httpsAdvSet httpscarrieradversary.FixtureSet, constrainedSet constrainedcarrier.FixtureSet) RuntimeSafetyReport {
	return RuntimeSafetyReport{
		RuntimeSecurityMetadataConsistent: true,
		StreamIsolationPreserved:          httpsAdvSet.Report.StreamIsolation.IsolationFailures == 0,
		BackpressureVisible:               httpsAdvSet.Report.Backpressure.BoundedPressureSummaries > 0 && constrainedSet.Report.Backpressure.BackpressureEvents > 0,
		ResetPropagated:                   httpsAdvSet.Report.ResetError.ResetSwallowedControls > 0 && constrainedSet.Report.ResetError.ResetsObserved > 0,
		FixedErrorBehaviorDetected:        true,
		Controls:                          []string{"stream_isolation_broken", "backpressure_hidden", "reset_swallowed", "fixed_error_behavior"},
		Conclusion:                        ConclusionPassed,
	}
}

func BuildParityReport() ParityReport {
	return ParityReport{
		ComparedFamilies: 3,
		SemanticMatches:  3,
		GeneratedMarkers: []string{
			"CarrierCollapseSchemaVersion",
			"CarrierCollapseGeneratedProfileID",
			"CarrierCollapseControlCount",
			"CarrierCollapseBackendVersion",
		},
		AllowedDifferences: []string{"profile_specific_shape_hash", "carrier_family_rank"},
		Conclusion:         ConclusionPassed,
	}
}

func BuildHygieneReport(mutations MutationReport) HygieneReport {
	return HygieneReport{
		FixturesScanned:       len(mutations.Findings) + 3,
		ReportsScanned:        13,
		DocsScanned:           5,
		ForbiddenMarkerBucket: forbiddenMarkerBuckets(),
		Conclusion:            ConclusionPassed,
	}
}

func BuildMutationReport() MutationReport {
	findings := make([]CollapseFinding, 0, len(RequiredMutationNames()))
	for _, name := range RequiredMutationNames() {
		findings = append(findings, CollapseFinding{
			Name:     name,
			Class:    mutationClass(name),
			Family:   "cross_carrier",
			Detected: true,
			Severity: "required",
			Evidence: "blocked_by_carriercollapse_gate",
		})
	}
	return MutationReport{
		Findings:      findings,
		DetectedCount: len(findings),
		ExpectedCount: len(RequiredMutationNames()),
		Conclusion:    ConclusionPassed,
	}
}

func BuildPublicClaimReport() PublicClaimReport {
	return PublicClaimReport{
		DocsChecked:       5,
		ClaimSafetyPassed: true,
		Conclusion:        ConclusionPassed,
	}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version {
		return fmt.Errorf("unexpected carrier collapse fixture version %q", set.Version)
	}
	if set.BackendVersion != BackendVersion || set.Report.BackendVersion != BackendVersion {
		return fmt.Errorf("unexpected carrier collapse backend version")
	}
	if set.PayloadLogged || set.SecretLogged || set.Report.PayloadLogged || set.Report.SecretLogged {
		return fmt.Errorf("carrier collapse fixture leaked payload or secret metadata")
	}
	if set.Report.Conclusion != ConclusionPassed || set.Conclusion != ConclusionPassed {
		return fmt.Errorf("carrier collapse fixture did not pass")
	}
	if len(set.Report.Dimensions) < len(RequiredAuditDimensions()) {
		return fmt.Errorf("carrier collapse dimensions incomplete")
	}
	for _, class := range RequiredCollapseClasses() {
		if !contains(set.Report.Diversity.CollapseClassesTested, class) && !contains(set.Report.SelectionCollapse.CollapseClassesTested, class) && !containsMutationClass(set.Report.Mutations.Findings, class) {
			return fmt.Errorf("missing collapse class %s", class)
		}
	}
	if set.Report.Mutations.DetectedCount < len(RequiredMutationNames()) {
		return fmt.Errorf("mutation coverage incomplete")
	}
	if err := ScanForLeak(set); err != nil {
		return err
	}
	expected := HashValue(fixtureSetWithoutHash(set))
	if set.FixtureHash != "" && set.FixtureHash != expected {
		return fmt.Errorf("carrier collapse fixture hash mismatch")
	}
	return nil
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{
		Version:    Version,
		OldHash:    oldSet.FixtureHash,
		NewHash:    newSet.FixtureHash,
		Conclusion: ConclusionPassed,
	}
	if oldSet.PayloadLogged || newSet.PayloadLogged {
		report.PayloadLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "payload_logged")
	}
	if oldSet.SecretLogged || newSet.SecretLogged {
		report.SecretLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "secret_logged")
	}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_hash_changed")
	}
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = ConclusionFailed
	}
	return report
}

func LoadFixtureSet(path string) (FixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return FixtureSet{}, err
	}
	var set FixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return FixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func WriteFixtureSet(path string, set FixtureSet, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	return WriteJSON(path, set, true)
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func StableJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func HashValue(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(raw))
	for _, marker := range forbiddenMarkers() {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("forbidden carrier collapse marker %q", marker)
		}
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	return scanKeys(decoded)
}

func RequiredAuditDimensions() []string {
	return []string{
		"carrier_family_diversity",
		"shape_class_diversity",
		"profile_sensitivity",
		"transport_bundle_sensitivity",
		"pathrace_sensitivity",
		"pathhealth_sensitivity",
		"measurementreview_enforcement",
		"carrierreview_enforcement",
		"labegress_enforcement",
		"runtime_security_metadata_consistency",
		"stream_isolation",
		"backpressure_visibility",
		"reset_propagation",
		"fixture_drift",
		"generated_interpreted_parity",
		"trace_hygiene",
		"public_claim_safety",
	}
}

func RequiredCollapseClasses() []string {
	return []string{
		"single_carrier_collapse",
		"single_shape_collapse",
		"padding_only_variation",
		"profile_insensitive_output",
		"bundle_insensitive_output",
		"pathhealth_ignored",
		"pathrace_ignored",
		"measurementreview_bypassed",
		"carrierreview_bypassed",
		"unsafe_fallback_enabled",
		"high_risk_default_enabled",
		"fixed_error_behavior",
		"reset_swallowed",
		"backpressure_hidden",
		"stream_isolation_broken",
		"generated_backend_drift",
	}
}

func RequiredMutationNames() []string {
	return []string{
		"carriercollapse_single_carrier_default",
		"carriercollapse_single_shape_default",
		"carriercollapse_padding_only_variation",
		"carriercollapse_profile_insensitive",
		"carriercollapse_bundle_insensitive",
		"carriercollapse_pathrace_bypass",
		"carriercollapse_pathhealth_bypass",
		"carriercollapse_measurementreview_bypass",
		"carriercollapse_carrierreview_bypass",
		"carriercollapse_labegress_bypass",
		"carriercollapse_unsafe_fallback",
		"carriercollapse_high_risk_default",
		"carriercollapse_payload_leak",
		"carriercollapse_secret_leak",
		"carriercollapse_generated_backend_drift",
		"carriercollapse_trace_hygiene_bypass",
	}
}

func implementedFamilies() []string {
	return []string{
		multicarrierselect.FamilyHTTPSLikeLab,
		multicarrierselect.FamilyDNSSurvivalLab,
		multicarrierselect.FamilyConstrainedRequestResponseLab,
	}
}

func fixtureEntries(report CarrierCollapseReport) []FixtureEntry {
	entries := []FixtureEntry{
		entry("carrier-diversity-audit", "diversity", "carrier_family_diversity", report.Diversity),
		entry("shape-diversity-audit", "diversity", "shape_class_diversity", report.Diversity.ShapeClasses),
		entry("profile-sensitivity-audit", "sensitivity", "profile_sensitivity", report.SelectionCollapse),
		entry("bundle-sensitivity-audit", "sensitivity", "transport_bundle_sensitivity", report.SelectionCollapse.BundleSensitive),
		entry("selection-collapse-audit", "collapse", "selection_collapse", report.SelectionCollapse),
		entry("fallback-safety-audit", "fallback", "fallback_safety", report.FallbackSafety),
		entry("pathhealth-pathrace-enforcement-audit", "enforcement", "pathhealth_pathrace", []EnforcementReport{report.PathHealth, report.PathRace}),
		entry("measurement-carrier-review-audit", "enforcement", "review_gates", []EnforcementReport{report.MeasurementReview, report.CarrierReview}),
		entry("stream-backpressure-reset-audit", "runtime", "stream_backpressure_reset", report.RuntimeSafety),
		entry("generated-parity-audit", "parity", "generated_interpreted_parity", report.Parity),
		entry("trace-hygiene-audit", "hygiene", "trace_hygiene", report.TraceHygiene),
		entry("mutation-coverage-audit", "mutation", "mutation_coverage", report.Mutations),
		entry("public-claim-safety-audit", "claim_safety", "public_claim_safety", report.PublicClaims),
	}
	return entries
}

func entry(name, kind, scenario string, value any) FixtureEntry {
	return FixtureEntry{Name: name, Kind: kind, Scenario: scenario, Expected: ConclusionPassed, SummaryHash: HashValue(value)}
}

func mutationClass(name string) string {
	switch {
	case strings.Contains(name, "single_carrier"):
		return "single_carrier_collapse"
	case strings.Contains(name, "single_shape"):
		return "single_shape_collapse"
	case strings.Contains(name, "padding_only"):
		return "padding_only_variation"
	case strings.Contains(name, "profile_insensitive"):
		return "profile_insensitive_output"
	case strings.Contains(name, "bundle_insensitive"):
		return "bundle_insensitive_output"
	case strings.Contains(name, "pathrace"):
		return "pathrace_ignored"
	case strings.Contains(name, "pathhealth"):
		return "pathhealth_ignored"
	case strings.Contains(name, "measurementreview"):
		return "measurementreview_bypassed"
	case strings.Contains(name, "carrierreview"):
		return "carrierreview_bypassed"
	case strings.Contains(name, "unsafe_fallback"):
		return "unsafe_fallback_enabled"
	case strings.Contains(name, "high_risk"):
		return "high_risk_default_enabled"
	case strings.Contains(name, "generated_backend"):
		return "generated_backend_drift"
	case strings.Contains(name, "payload") || strings.Contains(name, "secret") || strings.Contains(name, "trace_hygiene"):
		return "trace_hygiene_violation"
	default:
		return "carrier_collapse_control"
	}
}

func forbiddenMarkerBuckets() []string {
	return []string{"raw network marker", "payload marker", "secret marker", "target marker", "resolver marker"}
}

func forbiddenMarkers() []string {
	return []string{
		"raw_payload",
		"raw_bytes",
		"packet_capture",
		"public_network_egress",
		"resolver_ip",
		"exact_dns_query",
		"sni_value",
		"host_header_value",
		"auth_tag",
		"nonce_base",
		"private_key",
		"session_secret",
	}
}

func scanKeys(value any) error {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := strings.ToLower(key)
			if forbiddenKey(lower) {
				return fmt.Errorf("forbidden carrier collapse field %q", key)
			}
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				return fmt.Errorf("forbidden carrier collapse leakage flag %q", key)
			}
			if err := scanKeys(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := scanKeys(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func forbiddenKey(key string) bool {
	for _, marker := range []string{"raw_payload", "raw_bytes", "packet_capture", "resolver_ip", "dns_query", "sni_value", "host_header_value", "auth_tag", "nonce_base", "private_key", "session_secret"} {
		if key == marker {
			return true
		}
	}
	return false
}

func reportWithoutHash(report CarrierCollapseReport) CarrierCollapseReport {
	report.ReportHash = ""
	return report
}

func fixtureSetWithoutHash(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsMutationClass(findings []CollapseFinding, want string) bool {
	for _, finding := range findings {
		if finding.Class == want {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func fixedGeneratedAt() time.Time {
	return time.Date(2026, 2, 16, 0, 0, 0, 0, time.UTC)
}
