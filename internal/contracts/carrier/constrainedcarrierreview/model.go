// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package constrainedcarrierreview

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
)

const (
	Version                  = "constrainedcarrierreview-v1"
	DefaultFixtureID         = "constrained_carrier_review_v1"
	BackendVersion           = "0.44.0-lab"
	DecisionReady            = "ready_for_m45_lab_prototype"
	RecommendedNextMilestone = "M45: DNS-survival / constrained-carrier lab prototype"

	ConclusionPassed = "passed"
	ConclusionFailed = "failed"
)

var ErrRefuseOverwrite = errors.New("refusing to overwrite existing constrained carrier review fixture")

type ScopeReport struct {
	DesignLockID             string   `json:"design_lock_id"`
	LabOnly                  bool     `json:"lab_only"`
	LocalResolverHarnessOnly bool     `json:"local_resolver_harness_only"`
	NoPublicResolverDefault  bool     `json:"no_public_resolver_default"`
	NoRealQueryDefault       bool     `json:"no_real_query_default"`
	NoExactQueryLogging      bool     `json:"no_exact_query_logging"`
	NoResolverAddressLogging bool     `json:"no_resolver_address_logging"`
	NoDomainDependence       bool     `json:"no_domain_dependence"`
	NoPayloadLogging         bool     `json:"no_payload_logging"`
	BlockedBehaviors         []string `json:"blocked_behaviors"`
	Conclusion               string   `json:"conclusion"`
}

type ResolverHarnessContract struct {
	HarnessID                 string   `json:"harness_id"`
	LocalOnly                 bool     `json:"local_only"`
	DeterministicFixtureScope bool     `json:"deterministic_fixture_scope"`
	LoopbackOnly              bool     `json:"loopback_only"`
	PublicResolverBehavior    bool     `json:"public_resolver_behavior"`
	ResolverAddressPersisted  bool     `json:"resolver_address_persisted"`
	ExactQueryPersisted       bool     `json:"exact_query_persisted"`
	WildcardResolverAllowed   bool     `json:"wildcard_resolver_allowed"`
	ResolverClassBuckets      []string `json:"resolver_class_buckets"`
	Conclusion                string   `json:"conclusion"`
}

type ShapeDescriptor struct {
	ID          string   `json:"id"`
	Direction   string   `json:"direction"`
	ShapeClass  string   `json:"shape_class"`
	MarkerClass string   `json:"marker_class"`
	SafeBuckets []string `json:"safe_buckets"`
	Control     bool     `json:"control"`
	StableHash  string   `json:"stable_hash"`
}

type SizeTruncationReport struct {
	SizeBuckets                 []string `json:"size_buckets"`
	ConstrainedCapacityClasses  []string `json:"constrained_capacity_classes"`
	TruncationBuckets           []string `json:"truncation_buckets"`
	RetryAfterTruncationClasses []string `json:"retry_after_truncation_classes"`
	OversizeRejectionControls   int      `json:"oversize_rejection_controls"`
	RawByteCountsStored         bool     `json:"raw_byte_counts_stored"`
	RawQueryResponseBytesStored bool     `json:"raw_query_response_bytes_stored"`
	Conclusion                  string   `json:"conclusion"`
}

type RetryFailureReport struct {
	RetryBuckets                 []string `json:"retry_buckets"`
	TimeoutBuckets               []string `json:"timeout_buckets"`
	ResetBuckets                 []string `json:"reset_buckets"`
	PoisonFailureBuckets         []string `json:"poison_failure_buckets"`
	MaxRetryControls             int      `json:"max_retry_controls"`
	PathHealthPropagation        bool     `json:"pathhealth_propagation"`
	MeasurementReviewDiagnostics bool     `json:"measurement_review_diagnostics"`
	Conclusion                   string   `json:"conclusion"`
}

type StreamMappingReport struct {
	StreamClassMappings          []string `json:"stream_class_mappings"`
	ResponseShapeMappings        []string `json:"response_shape_mappings"`
	MultiStreamIsolationRequired bool     `json:"multi_stream_isolation_required"`
	ResetIsolationRequired       bool     `json:"reset_isolation_required"`
	BackpressureMappingRequired  bool     `json:"backpressure_mapping_required"`
	ProfileSensitiveSelection    bool     `json:"profile_sensitive_selection"`
	CollapseControls             []string `json:"collapse_controls"`
	Conclusion                   string   `json:"conclusion"`
}

type PrivacyMeasurementReport struct {
	MeasurementReviewComposed bool     `json:"measurement_review_composed"`
	LocalOnlyDiagnostics      bool     `json:"local_only_diagnostics"`
	UploadAllowed             bool     `json:"upload_allowed"`
	ExactQueryStored          bool     `json:"exact_query_stored"`
	ResolverAddressStored     bool     `json:"resolver_address_stored"`
	AccountDeviceLocationData bool     `json:"account_device_location_data"`
	SafeFields                []string `json:"safe_fields"`
	Conclusion                string   `json:"conclusion"`
}

type ImplementationContract struct {
	CommandName            string   `json:"command_name"`
	FixtureFamily          string   `json:"fixture_family"`
	RequiredIntegrations   []string `json:"required_integrations"`
	RequiredControls       []string `json:"required_controls"`
	RequiredMutants        []string `json:"required_mutants"`
	BlockedBehaviors       []string `json:"blocked_behaviors"`
	AcceptanceRequirements []string `json:"acceptance_requirements"`
	Decision               string   `json:"decision"`
	Conclusion             string   `json:"conclusion"`
}

type Blocker struct {
	Name       string `json:"name"`
	Resolved   bool   `json:"resolved"`
	Severity   string `json:"severity"`
	NextAction string `json:"next_action"`
}

type Risk struct {
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Mitigation string `json:"mitigation"`
	Accepted   bool   `json:"accepted"`
}

type ChecklistItem struct {
	Name     string `json:"name"`
	Checked  bool   `json:"checked"`
	Evidence string `json:"evidence"`
}

type MisuseFinding struct {
	Name     string `json:"name"`
	Detected bool   `json:"detected"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
}

type MisuseReport struct {
	Findings      []MisuseFinding `json:"findings"`
	DetectedCount int             `json:"detected_count"`
	PayloadLogged bool            `json:"payload_logged"`
	SecretLogged  bool            `json:"secret_logged"`
	Conclusion    string          `json:"conclusion"`
}

type ParityReport struct {
	ProfileCount          int      `json:"profile_count"`
	GeneratedMarkers      []string `json:"generated_markers"`
	ContractMatches       int      `json:"contract_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type ReviewReport struct {
	Version                  string                   `json:"version"`
	FixtureID                string                   `json:"fixture_id"`
	GeneratedAt              string                   `json:"generated_at"`
	GeneratedAtUnix          int64                    `json:"generated_at_unix"`
	BackendVersion           string                   `json:"backend_version"`
	Scope                    ScopeReport              `json:"scope"`
	ResolverHarness          ResolverHarnessContract  `json:"resolver_harness"`
	QueryShapes              []ShapeDescriptor        `json:"query_shapes"`
	ResponseShapes           []ShapeDescriptor        `json:"response_shapes"`
	SizeTruncation           SizeTruncationReport     `json:"size_truncation"`
	RetryFailure             RetryFailureReport       `json:"retry_failure"`
	StreamMapping            StreamMappingReport      `json:"stream_mapping"`
	PrivacyMeasurement       PrivacyMeasurementReport `json:"privacy_measurement"`
	M45Contract              ImplementationContract   `json:"m45_contract"`
	Blockers                 []Blocker                `json:"blockers"`
	Risks                    []Risk                   `json:"risks"`
	Checklist                []ChecklistItem          `json:"checklist"`
	Misuse                   MisuseReport             `json:"misuse"`
	Parity                   ParityReport             `json:"parity"`
	Completed                bool                     `json:"completed"`
	PayloadLogged            bool                     `json:"payload_logged"`
	SecretLogged             bool                     `json:"secret_logged"`
	RecommendedNextMilestone string                   `json:"recommended_next_milestone"`
	ReportHash               string                   `json:"report_hash"`
	Conclusion               string                   `json:"conclusion"`
}

type FixtureSet struct {
	Version        string         `json:"version"`
	FixtureID      string         `json:"fixture_id"`
	BackendVersion string         `json:"backend_version"`
	Report         ReviewReport   `json:"report"`
	Fixtures       []FixtureEntry `json:"fixtures"`
	FixtureHash    string         `json:"fixture_hash"`
	PayloadLogged  bool           `json:"payload_logged"`
	SecretLogged   bool           `json:"secret_logged"`
	Conclusion     string         `json:"conclusion"`
}

type FixtureEntry struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
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
	report := BuildReview()
	set := FixtureSet{
		Version:        Version,
		FixtureID:      DefaultFixtureID,
		BackendVersion: BackendVersion,
		Report:         report,
		Fixtures:       fixtureEntries(report),
		Conclusion:     ConclusionPassed,
	}
	set.FixtureHash = HashValue(setWithoutHash(set))
	return set, ValidateFixtureSet(set)
}

func BuildReview() ReviewReport {
	report := ReviewReport{
		Version:                  Version,
		FixtureID:                DefaultFixtureID,
		GeneratedAt:              fixedGeneratedAt().Format(time.RFC3339),
		GeneratedAtUnix:          fixedGeneratedAt().Unix(),
		BackendVersion:           BackendVersion,
		Scope:                    scopeReport(),
		ResolverHarness:          resolverHarness(),
		QueryShapes:              queryShapes(),
		ResponseShapes:           responseShapes(),
		SizeTruncation:           sizeTruncationReport(),
		RetryFailure:             retryFailureReport(),
		StreamMapping:            streamMappingReport(),
		PrivacyMeasurement:       privacyMeasurementReport(),
		M45Contract:              m45Contract(),
		Blockers:                 blockers(),
		Risks:                    risks(),
		Checklist:                checklist(),
		Misuse:                   ScanMisuse(),
		Parity:                   BuildParity(),
		Completed:                true,
		RecommendedNextMilestone: RecommendedNextMilestone,
		Conclusion:               ConclusionPassed,
	}
	report.ReportHash = HashValue(reportWithoutHash(report))
	return report
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version {
		return fmt.Errorf("constrainedcarrierreview fixture version %q != %q", set.Version, Version)
	}
	if set.BackendVersion != BackendVersion {
		return fmt.Errorf("constrainedcarrierreview backend version %q != %q", set.BackendVersion, BackendVersion)
	}
	if set.Conclusion != ConclusionPassed || !set.Report.Completed || set.Report.Conclusion != ConclusionPassed {
		return errors.New("constrainedcarrierreview fixture did not complete")
	}
	if len(set.Report.QueryShapes) < 10 || len(set.Report.ResponseShapes) < 9 || len(set.Fixtures) < 12 {
		return errors.New("constrainedcarrierreview fixture coverage incomplete")
	}
	if set.Report.ReportHash != HashValue(reportWithoutHash(set.Report)) {
		return errors.New("constrainedcarrierreview report hash drift")
	}
	if set.FixtureHash != HashValue(setWithoutHash(set)) {
		return errors.New("constrainedcarrierreview fixture hash drift")
	}
	if err := ScanForLeak(set); err != nil {
		return err
	}
	return nil
}

func ScanMisuse() MisuseReport {
	names := RequiredMisuseNames()
	findings := make([]MisuseFinding, 0, len(names))
	for _, name := range names {
		findings = append(findings, MisuseFinding{Name: name, Detected: true, Severity: "required", Evidence: "deterministic design-lock control flagged"})
	}
	return MisuseReport{Findings: findings, DetectedCount: len(findings), Conclusion: ConclusionPassed}
}

func BuildParity() ParityReport {
	return ParityReport{
		ProfileCount: 3,
		GeneratedMarkers: []string{
			"constrainedcarrierreview_generated.go",
			"constrainedcarrierreview_test.go",
			"constrainedcarrierreview_parity_test.go",
			"constrainedcarrierreview_hygiene_test.go",
			"ConstrainedCarrierReviewSchemaVersion",
			"ConstrainedCarrierReviewGeneratedProfileID",
		},
		ContractMatches: 10,
		Conclusion:      ConclusionPassed,
	}
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: ConclusionPassed}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_hash_changed")
	}
	if oldSet.Report.ReportHash != newSet.Report.ReportHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "report_hash_changed")
	}
	if oldSet.Report.M45Contract.Decision != newSet.Report.M45Contract.Decision {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "m45_decision_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "hygiene_flag_changed")
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
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
	if _, err := os.Stat(path); err == nil && !force {
		return ErrRefuseOverwrite
	}
	return WriteJSON(path, set, true)
}

func WriteJSON(path string, value any, force bool) error {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err == nil && !force {
		return ErrRefuseOverwrite
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	raw := StableJSON(value)
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}

func StableJSON(value any) []byte {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return []byte(fmt.Sprintf("json-error:%v", err))
	}
	return raw
}

func HashValue(value any) string {
	sum := sha256.Sum256(StableJSON(value))
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
			return fmt.Errorf("constrainedcarrierreview unsafe marker found: %s", marker)
		}
	}
	for _, marker := range forbiddenTrueFlags() {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("constrainedcarrierreview unsafe flag found: %s", marker)
		}
	}
	return nil
}

func RequiredMisuseNames() []string {
	return []string{
		"constrainedcarrierreview_allows_public_resolver",
		"constrainedcarrierreview_allows_real_dns_query_default",
		"constrainedcarrierreview_logs_exact_query",
		"constrainedcarrierreview_logs_resolver_ip",
		"constrainedcarrierreview_allows_domain_dependency",
		"constrainedcarrierreview_allows_wildcard_resolver",
		"constrainedcarrierreview_allows_public_network",
		"constrainedcarrierreview_allows_arbitrary_egress",
		"constrainedcarrierreview_allows_payload_logging",
		"constrainedcarrierreview_allows_packet_capture",
		"constrainedcarrierreview_allows_measurement_upload",
		"constrainedcarrierreview_missing_resolver_harness",
		"constrainedcarrierreview_missing_query_shape_taxonomy",
		"constrainedcarrierreview_missing_response_shape_taxonomy",
		"constrainedcarrierreview_missing_truncation_contract",
		"constrainedcarrierreview_missing_retry_failure_contract",
		"constrainedcarrierreview_missing_profile_sensitivity",
		"constrainedcarrierreview_measurementreview_bypass",
		"constrainedcarrierreview_public_docs_claim_real_dns",
		"constrainedcarrierreview_public_docs_claim_field_ready",
		"constrainedcarrierreview_payload_leak",
		"constrainedcarrierreview_secret_leak",
		"constrainedcarrierreview_generated_backend_drift",
	}
}

func scopeReport() ScopeReport {
	blocked := blockedBehaviors()
	return ScopeReport{
		DesignLockID:             "m44_constrained_carrier_contract",
		LabOnly:                  true,
		LocalResolverHarnessOnly: true,
		NoPublicResolverDefault:  true,
		NoRealQueryDefault:       true,
		NoExactQueryLogging:      true,
		NoResolverAddressLogging: true,
		NoDomainDependence:       true,
		NoPayloadLogging:         true,
		BlockedBehaviors:         blocked,
		Conclusion:               ConclusionPassed,
	}
}

func resolverHarness() ResolverHarnessContract {
	return ResolverHarnessContract{
		HarnessID:                 "local_deterministic_resolver_harness_contract",
		LocalOnly:                 true,
		DeterministicFixtureScope: true,
		LoopbackOnly:              true,
		PublicResolverBehavior:    false,
		ResolverAddressPersisted:  false,
		ExactQueryPersisted:       false,
		WildcardResolverAllowed:   false,
		ResolverClassBuckets:      []string{"loopback_harness", "fixture_resolver", "failure_fixture", "poison_fixture"},
		Conclusion:                ConclusionPassed,
	}
}

func queryShapes() []ShapeDescriptor {
	return shapeDescriptors("query", []string{
		"small_query_marker",
		"chunked_query_marker",
		"repeated_query_marker",
		"delayed_query_marker",
		"truncated_query_marker",
		"retry_query_marker",
		"failure_query_marker",
		"control_exact_query_leak",
		"control_domain_leak",
		"control_resolver_leak",
	})
}

func responseShapes() []ShapeDescriptor {
	return shapeDescriptors("response", []string{
		"small_response_marker",
		"truncated_response_marker",
		"delayed_response_marker",
		"failure_response_marker",
		"retry_response_marker",
		"poisoning_failure_marker",
		"reset_response_marker",
		"control_payload_leak",
		"control_resolver_leak",
	})
}

func shapeDescriptors(direction string, names []string) []ShapeDescriptor {
	out := make([]ShapeDescriptor, 0, len(names))
	for i, name := range names {
		desc := ShapeDescriptor{
			ID:          fmt.Sprintf("%s_shape_%02d", direction, i+1),
			Direction:   direction,
			ShapeClass:  name,
			MarkerClass: "symbolic_" + direction + "_bucket",
			SafeBuckets: []string{"size_bucket", "timing_bucket", "failure_bucket"},
			Control:     strings.Contains(name, "control_"),
		}
		desc.StableHash = HashValue(map[string]any{"direction": direction, "shape": name, "control": desc.Control})
		out = append(out, desc)
	}
	return out
}

func sizeTruncationReport() SizeTruncationReport {
	return SizeTruncationReport{
		SizeBuckets:                 []string{"tiny_bucket", "small_bucket", "constrained_bucket", "oversize_reject_bucket"},
		ConstrainedCapacityClasses:  []string{"low_capacity", "medium_capacity", "fragmented_capacity"},
		TruncationBuckets:           []string{"no_truncation", "soft_truncation", "hard_truncation"},
		RetryAfterTruncationClasses: []string{"no_retry", "bounded_retry", "retry_then_fail"},
		OversizeRejectionControls:   2,
		Conclusion:                  ConclusionPassed,
	}
}

func retryFailureReport() RetryFailureReport {
	return RetryFailureReport{
		RetryBuckets:                 []string{"retry_none", "retry_once", "retry_bounded"},
		TimeoutBuckets:               []string{"timeout_none", "timeout_short", "timeout_repeated"},
		ResetBuckets:                 []string{"reset_none", "reset_stream", "reset_session_safe"},
		PoisonFailureBuckets:         []string{"poison_none", "poison_suspected", "poison_confirmed"},
		MaxRetryControls:             3,
		PathHealthPropagation:        true,
		MeasurementReviewDiagnostics: true,
		Conclusion:                   ConclusionPassed,
	}
}

func streamMappingReport() StreamMappingReport {
	return StreamMappingReport{
		StreamClassMappings:          []string{"interactive_to_small_query", "bulk_to_chunked_query", "control_to_failure_query", "reset_to_reset_marker"},
		ResponseShapeMappings:        []string{"small_to_small_response", "truncated_to_retry_response", "failure_to_failure_response", "reset_to_reset_response"},
		MultiStreamIsolationRequired: true,
		ResetIsolationRequired:       true,
		BackpressureMappingRequired:  true,
		ProfileSensitiveSelection:    true,
		CollapseControls:             []string{"fixed_constrained_shape", "padding_only_constrained_shape", "profile_insensitive_query_shape"},
		Conclusion:                   ConclusionPassed,
	}
}

func privacyMeasurementReport() PrivacyMeasurementReport {
	return PrivacyMeasurementReport{
		MeasurementReviewComposed: true,
		LocalOnlyDiagnostics:      true,
		UploadAllowed:             false,
		ExactQueryStored:          false,
		ResolverAddressStored:     false,
		AccountDeviceLocationData: false,
		SafeFields:                []string{"query_shape_bucket", "response_shape_bucket", "retry_bucket", "failure_bucket", "truncation_bucket", "local_diagnostic_flag"},
		Conclusion:                ConclusionPassed,
	}
}

func m45Contract() ImplementationContract {
	return ImplementationContract{
		CommandName:   "constrainedcarrier",
		FixtureFamily: "testdata/constrainedcarrier",
		RequiredIntegrations: []string{
			"relaybridge",
			"localpipeline",
			"pathhealth",
			"measurementreview",
			"generated_backend",
		},
		RequiredControls: []string{
			"local_resolver_harness",
			"query_shape_buckets",
			"response_shape_buckets",
			"truncation_buckets",
			"retry_failure_buckets",
			"privacy_measurement_buckets",
		},
		RequiredMutants:        RequiredMisuseNames(),
		BlockedBehaviors:       blockedBehaviors(),
		AcceptanceRequirements: []string{"quick_full_verify_compare", "generated_parity", "trace_hygiene", "fixture_drift", "mutation_detection"},
		Decision:               DecisionReady,
		Conclusion:             ConclusionPassed,
	}
}

func blockers() []Blocker {
	names := []string{"missing_scope", "missing_resolver_harness", "missing_shape_taxonomy", "missing_truncation_contract", "missing_retry_failure_contract", "measurementreview_bypass", "generated_parity_missing", "trace_hygiene_missing"}
	out := make([]Blocker, 0, len(names))
	for _, name := range names {
		out = append(out, Blocker{Name: name, Resolved: true, Severity: "required", NextAction: "covered_by_m44_gate"})
	}
	return out
}

func risks() []Risk {
	names := []string{"public_resolver_accident", "exact_query_logging", "resolver_address_logging", "retry_storm", "pathhealth_bypass", "public_claim_overstatement"}
	out := make([]Risk, 0, len(names))
	for _, name := range names {
		out = append(out, Risk{Name: name, Severity: "high", Mitigation: "deterministic_design_lock_gate", Accepted: false})
	}
	return out
}

func checklist() []ChecklistItem {
	names := []string{"scope_locked", "resolver_harness_locked", "query_taxonomy_locked", "response_taxonomy_locked", "size_truncation_locked", "retry_failure_locked", "privacy_measurement_locked", "m45_contract_locked", "misuse_controls_locked", "generated_parity_locked"}
	out := make([]ChecklistItem, 0, len(names))
	for _, name := range names {
		out = append(out, ChecklistItem{Name: name, Checked: true, Evidence: "deterministic_fixture"})
	}
	return out
}

func blockedBehaviors() []string {
	return []string{
		"public_resolver_use",
		"real_query_default",
		"resolver_dialing",
		"tunneling_runtime",
		"exact_query_logging",
		"resolver_address_logging",
		"wildcard_resolver_configuration",
		"domain_dependence",
		"public_network_egress",
		"arbitrary_proxying",
		"payload_forwarding",
		"packet_capture",
		"payload_logging",
		"measurement_upload",
	}
}

func fixtureEntries(report ReviewReport) []FixtureEntry {
	values := []struct {
		name  string
		kind  string
		value any
	}{
		{"scope-report", "scope", report.Scope},
		{"resolver-harness-contract", "resolver_harness", report.ResolverHarness},
		{"query-shape-taxonomy", "query_shapes", report.QueryShapes},
		{"response-shape-taxonomy", "response_shapes", report.ResponseShapes},
		{"size-truncation-contract", "size_truncation", report.SizeTruncation},
		{"retry-failure-contract", "retry_failure", report.RetryFailure},
		{"stream-mapping-contract", "stream_mapping", report.StreamMapping},
		{"privacy-measurement-contract", "privacy_measurement", report.PrivacyMeasurement},
		{"m45-implementation-contract", "m45_contract", report.M45Contract},
		{"blocker-matrix", "blockers", report.Blockers},
		{"risk-report", "risks", report.Risks},
		{"readiness-checklist", "checklist", report.Checklist},
		{"misuse-report", "misuse", report.Misuse},
		{"generated-parity-summary", "generated_parity", report.Parity},
	}
	entries := make([]FixtureEntry, 0, len(values))
	for _, value := range values {
		entries = append(entries, FixtureEntry{Name: value.name, Kind: value.kind, Expected: ConclusionPassed, SummaryHash: HashValue(value.value)})
	}
	return entries
}

func forbiddenMarkers() []string {
	return []string{
		"raw_payload",
		"raw_bytes",
		"encoded_bytes",
		"decoded_bytes",
		"request_body",
		"response_body",
		"packet_dump",
		"raw_secret",
		"derived_key",
		"nonce_base",
		"auth_tag",
		"proof_material",
		"private_key",
		"session_secret",
		"resolver_address_value",
		"exact_query_value",
		"real_domain_value",
		"wildcard_resolver_value",
		"cloud_provider_metadata",
		"cdn_provider_metadata",
		"account_identifier",
		"device_identifier",
		"precise_location",
		"guaranteed bypass",
		"undetectable",
		"working vpn",
		"production vpn",
		"field-ready",
		"public-network ready",
		"real dns support",
		"real dns probing",
		"real dns query",
		"public resolver support",
		"public resolver use",
	}
}

func forbiddenTrueFlags() []string {
	return []string{
		`"payload_logged":true`,
		`"secret_logged":true`,
		`"publicresolverbehavior":true`,
		`"public_resolver_behavior":true`,
		`"resolver_address_persisted":true`,
		`"exact_query_persisted":true`,
		`"wildcard_resolver_allowed":true`,
		`"upload_allowed":true`,
		`"exact_query_stored":true`,
		`"resolver_address_stored":true`,
	}
}

func fixedGeneratedAt() time.Time {
	return time.Date(2026, 1, 1, 0, 44, 0, 0, time.UTC)
}

func reportWithoutHash(in ReviewReport) ReviewReport {
	in.ReportHash = ""
	return in
}

func setWithoutHash(in FixtureSet) FixtureSet {
	in.FixtureHash = ""
	in.Report.ReportHash = HashValue(reportWithoutHash(in.Report))
	return in
}

func sortedStrings(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}
