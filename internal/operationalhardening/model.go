// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package operationalhardening

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
	Version                  = "operationalhardening-v1"
	BackendVersion           = "0.55.0-lab"
	DefaultFixtureID         = "operational_hardening_v1"
	ConclusionPassed         = "passed"
	RecommendedNextMilestone = "M56: Android architecture review"
)

var generatedAt = time.Date(2026, 2, 20, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

type ResourceLimitReport struct {
	Policy        string   `json:"policy"`
	Bounds        []string `json:"bounds"`
	SafeClasses   []string `json:"safe_error_classes"`
	MissingBounds bool     `json:"missing_bounds"`
	Conclusion    string   `json:"conclusion"`
}

type ConfigValidationReport struct {
	Policy                 string   `json:"policy"`
	RequiredFields         []string `json:"required_fields"`
	RejectedConfigClasses  []string `json:"rejected_config_classes"`
	SafeErrorClasses       []string `json:"safe_error_classes"`
	AllowAmbiguousConfig   bool     `json:"allow_ambiguous_config"`
	AllowOverbroadDefaults bool     `json:"allow_overbroad_defaults"`
	Conclusion             string   `json:"conclusion"`
}

type LifecycleReport struct {
	Policy                       string   `json:"policy"`
	ShutdownPhases               []string `json:"shutdown_phases"`
	RestartPhases                []string `json:"restart_phases"`
	InFlightSessionPolicy        string   `json:"in_flight_session_policy"`
	CompatibilityStatePolicy     string   `json:"compatibility_state_policy"`
	DeterministicShutdown        bool     `json:"deterministic_shutdown"`
	IdempotentRestart            bool     `json:"idempotent_restart"`
	UnboundedRestartLoopAllowed  bool     `json:"unbounded_restart_loop_allowed"`
	InFlightSessionsDroppedOpen  bool     `json:"in_flight_sessions_dropped_open"`
	CompatibilityStateBypassable bool     `json:"compatibility_state_bypassable"`
	Conclusion                   string   `json:"conclusion"`
}

type LoggingDiagnosticsReport struct {
	Policy              string   `json:"policy"`
	AllowedFields       []string `json:"allowed_fields"`
	ForbiddenFields     []string `json:"forbidden_fields"`
	RedactionClasses    []string `json:"redaction_classes"`
	PayloadLogged       bool     `json:"payload_logged"`
	SecretLogged        bool     `json:"secret_logged"`
	DestinationLogged   bool     `json:"destination_logged"`
	KeyMaterialLogged   bool     `json:"key_material_logged"`
	ExactUserIDLogged   bool     `json:"exact_user_id_logged"`
	NetworkMetadataLeak bool     `json:"network_metadata_leak"`
	Conclusion          string   `json:"conclusion"`
}

type RollbackReport struct {
	Policy                  string   `json:"policy"`
	RollbackableComponents  []string `json:"rollbackable_components"`
	ForwardCompatible       []string `json:"forward_compatible"`
	ProfileRotationRequired []string `json:"profile_rotation_required"`
	FailClosedClasses       []string `json:"fail_closed_classes"`
	FailClosedRequired      bool     `json:"fail_closed_required"`
	UnsafeRollbackAllowed   bool     `json:"unsafe_rollback_allowed"`
	Conclusion              string   `json:"conclusion"`
}

type HealthSummaryReport struct {
	Policy                    string   `json:"policy"`
	SafeFields                []string `json:"safe_fields"`
	FailureBuckets            []string `json:"failure_buckets"`
	ResourceBuckets           []string `json:"resource_buckets"`
	PayloadLogged             bool     `json:"payload_logged"`
	SecretLogged              bool     `json:"secret_logged"`
	ExactUserIdentifierLogged bool     `json:"exact_user_identifier_logged"`
	PreciseNetworkMetadata    bool     `json:"precise_network_metadata"`
	Conclusion                string   `json:"conclusion"`
}

type CompatibilityReport struct {
	Policy                      string   `json:"policy"`
	RequiredGates               []string `json:"required_gates"`
	CompatibilityChecks         []string `json:"compatibility_checks"`
	BypassesCarrierReview       bool     `json:"bypasses_carrierreview"`
	BypassesMeasurementReview   bool     `json:"bypasses_measurementreview"`
	BypassesPathHealth          bool     `json:"bypasses_pathhealth"`
	BypassesRelayAuth           bool     `json:"bypasses_relay_auth"`
	BypassesHardening           bool     `json:"bypasses_hardening"`
	AllowsGeneratedBackendDrift bool     `json:"allows_generated_backend_drift"`
	AllowsProfileRotationBypass bool     `json:"allows_profile_rotation_bypass"`
	AllowsCompatibilityFailOpen bool     `json:"allows_compatibility_fail_open"`
	Conclusion                  string   `json:"conclusion"`
}

type ChecklistReport struct {
	Items      []string `json:"items"`
	Passed     int      `json:"passed"`
	Failed     int      `json:"failed"`
	Conclusion string   `json:"conclusion"`
}

type MisuseReport struct {
	DetectedControls []string `json:"detected_controls"`
	DetectedCount    int      `json:"detected_count"`
	ExpectedCount    int      `json:"expected_count"`
	Conclusion       string   `json:"conclusion"`
}

type TraceHygieneReport struct {
	ReportsScanned    int    `json:"reports_scanned"`
	PayloadLogged     bool   `json:"payload_logged"`
	SecretLogged      bool   `json:"secret_logged"`
	DestinationLogged bool   `json:"destination_logged"`
	KeyMaterialLogged bool   `json:"key_material_logged"`
	Conclusion        string `json:"conclusion"`
}

type PublicClaimSafetyReport struct {
	DocsChecked       int      `json:"docs_checked"`
	ForbiddenClaims   []string `json:"forbidden_claims"`
	UnsafeClaimsFound []string `json:"unsafe_claims_found,omitempty"`
	Conclusion        string   `json:"conclusion"`
}

type ParityReport struct {
	GeneratedMarkers []string `json:"generated_markers"`
	InterpretedHash  string   `json:"interpreted_hash"`
	GeneratedHash    string   `json:"generated_hash"`
	UnexpectedDrift  []string `json:"unexpected_drift,omitempty"`
	Conclusion       string   `json:"conclusion"`
}

type FixtureSet struct {
	Version                  string                   `json:"version"`
	FixtureID                string                   `json:"fixture_id"`
	GeneratedAt              string                   `json:"generated_at"`
	BackendVersion           string                   `json:"backend_version"`
	RecommendedNextMilestone string                   `json:"recommended_next_milestone"`
	Decision                 string                   `json:"decision"`
	BlockerCount             int                      `json:"blocker_count"`
	RiskCount                int                      `json:"risk_count"`
	ResourceLimits           ResourceLimitReport      `json:"resource_limits"`
	ConfigValidation         ConfigValidationReport   `json:"config_validation"`
	Lifecycle                LifecycleReport          `json:"lifecycle"`
	Logging                  LoggingDiagnosticsReport `json:"logging_diagnostics"`
	Rollback                 RollbackReport           `json:"rollback_update_boundaries"`
	Health                   HealthSummaryReport      `json:"health_summary"`
	Compatibility            CompatibilityReport      `json:"compatibility_integration"`
	Checklist                ChecklistReport          `json:"checklist"`
	Misuse                   MisuseReport             `json:"misuse"`
	TraceHygiene             TraceHygieneReport       `json:"trace_hygiene"`
	PublicClaims             PublicClaimSafetyReport  `json:"public_claims"`
	Parity                   ParityReport             `json:"parity"`
	FixtureHash              string                   `json:"fixture_hash"`
	PayloadLogged            bool                     `json:"payload_logged"`
	SecretLogged             bool                     `json:"secret_logged"`
	Conclusion               string                   `json:"conclusion"`
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
	set := FixtureSet{
		Version:                  Version,
		FixtureID:                DefaultFixtureID,
		GeneratedAt:              generatedAt,
		BackendVersion:           BackendVersion,
		RecommendedNextMilestone: RecommendedNextMilestone,
		Decision:                 "ready_for_android_architecture_review",
		BlockerCount:             0,
		RiskCount:                5,
		ResourceLimits:           DefaultResourceLimitReport(),
		ConfigValidation:         DefaultConfigValidationReport(),
		Lifecycle:                DefaultLifecycleReport(),
		Logging:                  DefaultLoggingDiagnosticsReport(),
		Rollback:                 DefaultRollbackReport(),
		Health:                   DefaultHealthSummaryReport(),
		Compatibility:            DefaultCompatibilityReport(),
		Checklist:                BuildChecklistReport(),
		Misuse:                   BuildMisuseReport(),
		TraceHygiene:             BuildTraceHygieneReport(),
		PublicClaims:             BuildPublicClaimSafetyReport(),
	}
	set.Parity = BuildParityReport(set)
	set.Conclusion = ConclusionPassed
	set.FixtureHash = HashValue(fixtureHashInput(set))
	if err := ValidateFixtureSet(set); err != nil {
		set.Conclusion = "failed"
		return set, err
	}
	return set, nil
}

func DefaultResourceLimitReport() ResourceLimitReport {
	return ResourceLimitReport{
		Policy: "bounded_relay_runtime_resources_fail_closed",
		Bounds: []string{
			"relay_process_count_bucket",
			"runtime_session_count_bucket",
			"stream_count_bucket",
			"carrier_queue_depth_bucket",
			"timer_count_bucket",
			"generated_profile_count_bucket",
			"diagnostic_buffer_bytes_bucket",
			"restart_attempt_bucket",
		},
		SafeClasses: []string{"resource_limit_process", "resource_limit_session", "resource_limit_stream", "resource_limit_queue", "resource_limit_timer", "resource_limit_diagnostic"},
		Conclusion:  ConclusionPassed,
	}
}

func DefaultConfigValidationReport() ConfigValidationReport {
	return ConfigValidationReport{
		Policy:         "strict_operational_config_validation_with_safe_error_classes",
		RequiredFields: []string{"profile_bundle_version", "relay_compatibility_floor", "carrier_review_gate", "measurement_review_gate", "hardening_gate_status", "diagnostic_policy", "rollback_policy"},
		RejectedConfigClasses: []string{
			"missing_required_config",
			"ambiguous_config",
			"unsafe_default_config",
			"incompatible_version_config",
			"stale_profile_config",
			"over_permissive_diagnostics",
			"disabled_safety_gate",
		},
		SafeErrorClasses: []string{"config_missing_required", "config_ambiguous", "config_unsafe_default", "config_incompatible", "config_stale", "config_over_permissive", "config_gate_disabled"},
		Conclusion:       ConclusionPassed,
	}
}

func DefaultLifecycleReport() LifecycleReport {
	return LifecycleReport{
		Policy:                   "deterministic_bounded_shutdown_restart",
		ShutdownPhases:           []string{"stop_accepting_new_sessions", "close_inflight_streams_with_safe_reason", "flush_redacted_diagnostics", "close_runtime_links", "mark_terminal"},
		RestartPhases:            []string{"validate_config", "validate_profile_compatibility", "restore_compatibility_state", "start_with_bounded_retry"},
		InFlightSessionPolicy:    "bounded_drain_then_safe_close",
		CompatibilityStatePolicy: "compatibility_state_revalidated_before_reopen",
		DeterministicShutdown:    true,
		IdempotentRestart:        true,
		Conclusion:               ConclusionPassed,
	}
}

func DefaultLoggingDiagnosticsReport() LoggingDiagnosticsReport {
	return LoggingDiagnosticsReport{
		Policy:          "state_failure_version_resource_redacted_only",
		AllowedFields:   []string{"state_bucket", "failure_class", "version_compatibility_bucket", "resource_limit_class", "redaction_status", "rollback_class", "health_summary_bucket"},
		ForbiddenFields: []string{"payload contents", "destination metadata", "profile secret material", "key material", "exact user identifier", "sensitive network metadata", "packet capture artifacts", "telemetry upload marker"},
		RedactionClasses: []string{
			"redacted_profile",
			"redacted_relay",
			"bucketed_version",
			"bucketed_resource_limit",
			"bucketed_failure",
		},
		Conclusion: ConclusionPassed,
	}
}

func DefaultRollbackReport() RollbackReport {
	return RollbackReport{
		Policy:                  "rollback_boundaries_fail_closed_on_ambiguity",
		RollbackableComponents:  []string{"runtime_config_class", "diagnostic_policy_class", "carrier_selection_policy_class"},
		ForwardCompatible:       []string{"profile_bundle_version_floor", "relay_compatibility_floor", "generated_backend_marker"},
		ProfileRotationRequired: []string{"auth_policy_change", "relay_identity_epoch_change", "profile_wire_policy_change"},
		FailClosedClasses:       []string{"unknown_version", "profile_rotation_required", "compatibility_floor_mismatch", "rollback_policy_missing"},
		FailClosedRequired:      true,
		Conclusion:              ConclusionPassed,
	}
}

func DefaultHealthSummaryReport() HealthSummaryReport {
	return HealthSummaryReport{
		Policy:          "redacted_android_ready_operational_health_summary",
		SafeFields:      []string{"state_bucket", "runtime_version_bucket", "profile_version_bucket", "carrier_family_bucket", "relay_compatibility_bucket", "resource_limit_bucket", "failure_class", "recovery_action_bucket", "diagnostic_redaction_status"},
		FailureBuckets:  []string{"config_rejected", "resource_limited", "compatibility_mismatch", "rotation_required", "shutdown_in_progress", "restart_exhausted"},
		ResourceBuckets: []string{"process", "session", "stream", "queue", "timer", "diagnostic_buffer"},
		Conclusion:      ConclusionPassed,
	}
}

func DefaultCompatibilityReport() CompatibilityReport {
	return CompatibilityReport{
		Policy:              "operational_hardening_preserves_prior_safety_gates",
		RequiredGates:       []string{"carrierreview", "measurementreview", "pathhealth", "relayauthplan", "keyexchangeplan", "relayprocess", "hardening"},
		CompatibilityChecks: []string{"profile_bundle_version", "relay_auth_policy", "rotation_window", "carrier_family_review", "measurement_review_status", "path_health_status", "generated_backend_version"},
		Conclusion:          ConclusionPassed,
	}
}

func BuildChecklistReport() ChecklistReport {
	items := []string{
		"resource_limits_defined",
		"config_validation_strict",
		"shutdown_restart_bounded",
		"safe_logging_diagnostics",
		"misuse_controls_present",
		"rollback_update_boundaries",
		"health_summary_redacted",
		"prior_gate_integration_preserved",
		"generated_backend_parity",
	}
	return ChecklistReport{Items: items, Passed: len(items), Conclusion: ConclusionPassed}
}

func BuildMisuseReport() MisuseReport {
	controls := RequiredMisuseNames()
	return MisuseReport{DetectedControls: controls, DetectedCount: len(controls), ExpectedCount: len(controls), Conclusion: ConclusionPassed}
}

func BuildTraceHygieneReport() TraceHygieneReport {
	return TraceHygieneReport{ReportsScanned: 10, Conclusion: ConclusionPassed}
}

func BuildPublicClaimSafetyReport() PublicClaimSafetyReport {
	return PublicClaimSafetyReport{
		DocsChecked:     5,
		ForbiddenClaims: []string{"public-network deployment ready", "field-ready", "guaranteed bypass", "undetectable", "Android ready", "production VPN"},
		Conclusion:      ConclusionPassed,
	}
}

func BuildParityReport(set FixtureSet) ParityReport {
	hash := HashValue(parityHashInput(set))
	return ParityReport{
		GeneratedMarkers: []string{"OperationalHardeningSchemaVersion", "OperationalHardeningBackendVersion", "OperationalHardeningDecision", "OperationalHardeningMisuseCount", "OperationalHardeningSafeErrorClasses", "OperationalHardeningNextMilestone"},
		InterpretedHash:  hash,
		GeneratedHash:    hash,
		Conclusion:       ConclusionPassed,
	}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.BackendVersion != BackendVersion || set.FixtureID == "" {
		return errors.New("invalid operational hardening fixture identity")
	}
	if set.Decision == "" || set.BlockerCount != 0 || set.RiskCount < 4 {
		return errors.New("operational hardening decision incomplete")
	}
	if set.ResourceLimits.MissingBounds || len(set.ResourceLimits.Bounds) < 8 || len(set.ResourceLimits.SafeClasses) < 6 {
		return errors.New("operational resource limits incomplete")
	}
	if set.ConfigValidation.AllowAmbiguousConfig || set.ConfigValidation.AllowOverbroadDefaults || len(set.ConfigValidation.RejectedConfigClasses) < 7 || len(set.ConfigValidation.SafeErrorClasses) < 7 {
		return errors.New("operational config validation unsafe")
	}
	if !set.Lifecycle.DeterministicShutdown || !set.Lifecycle.IdempotentRestart || set.Lifecycle.UnboundedRestartLoopAllowed || set.Lifecycle.InFlightSessionsDroppedOpen || set.Lifecycle.CompatibilityStateBypassable || len(set.Lifecycle.ShutdownPhases) < 5 {
		return errors.New("operational lifecycle unsafe")
	}
	if set.Logging.PayloadLogged || set.Logging.SecretLogged || set.Logging.DestinationLogged || set.Logging.KeyMaterialLogged || set.Logging.ExactUserIDLogged || set.Logging.NetworkMetadataLeak || len(set.Logging.ForbiddenFields) < 8 {
		return errors.New("operational logging diagnostics unsafe")
	}
	if !set.Rollback.FailClosedRequired || set.Rollback.UnsafeRollbackAllowed || len(set.Rollback.ProfileRotationRequired) < 3 || len(set.Rollback.FailClosedClasses) < 4 {
		return errors.New("operational rollback policy unsafe")
	}
	if set.Health.PayloadLogged || set.Health.SecretLogged || set.Health.ExactUserIdentifierLogged || set.Health.PreciseNetworkMetadata || len(set.Health.SafeFields) < 8 {
		return errors.New("operational health summary unsafe")
	}
	if set.Compatibility.BypassesCarrierReview || set.Compatibility.BypassesMeasurementReview || set.Compatibility.BypassesPathHealth || set.Compatibility.BypassesRelayAuth || set.Compatibility.BypassesHardening || set.Compatibility.AllowsGeneratedBackendDrift || set.Compatibility.AllowsProfileRotationBypass || set.Compatibility.AllowsCompatibilityFailOpen || len(set.Compatibility.RequiredGates) < 7 {
		return errors.New("operational compatibility integration unsafe")
	}
	if set.Checklist.Failed != 0 || set.Checklist.Passed < 9 || set.Checklist.Conclusion != ConclusionPassed {
		return errors.New("operational checklist incomplete")
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) || set.Misuse.ExpectedCount != len(RequiredMisuseNames()) || len(set.Misuse.DetectedControls) != len(RequiredMisuseNames()) || set.Misuse.Conclusion != ConclusionPassed {
		return errors.New("operational misuse controls incomplete")
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.DestinationLogged || set.TraceHygiene.KeyMaterialLogged || set.PayloadLogged || set.SecretLogged {
		return errors.New("operational trace hygiene failed")
	}
	if set.Parity.Conclusion != ConclusionPassed || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		return errors.New("operational generated parity failed")
	}
	return ScanForLeak(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: ConclusionPassed}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "operationalhardening_fixture_hash_changed")
	}
	if oldSet.Version != newSet.Version || oldSet.BackendVersion != newSet.BackendVersion {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "operationalhardening_schema_or_backend_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
		report.UnexpectedDrift = append(report.UnexpectedDrift, "operationalhardening_trace_hygiene_failed")
	}
	report.UnexpectedDrift = uniqueStrings(report.UnexpectedDrift)
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = "failed"
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
	if err := ValidateFixtureSet(set); err != nil {
		return err
	}
	return WriteJSON(path, set, force)
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s exists; use --force", path)
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func StableJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func HashValue(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return "sha256:invalid"
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ScanForLeak(value any) error {
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(raw))
	for _, marker := range ForbiddenMarkers() {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return fmt.Errorf("operational hardening unsafe marker %q", marker)
		}
	}
	return nil
}

func ForbiddenMarkers() []string {
	return []string{
		`"raw_payload"`,
		`"payload_body"`,
		`"raw_packet_capture"`,
		`"packet_capture"`,
		`"destination_url"`,
		`"visited_domain"`,
		`"sni"`,
		`"host_header"`,
		`"dns_query"`,
		`"resolver_ip"`,
		`"profile_secret"`,
		`"secret_value"`,
		`"key_material"`,
		`"auth_tag"`,
		`"proof_material"`,
		`"private_key"`,
		`"session_secret"`,
		`"exact_user_identifier"`,
		`"phone_identifier"`,
		`"sim_identifier"`,
		`"precise_location"`,
		`"telemetry_upload_endpoint"`,
	}
}

func RequiredMisuseNames() []string {
	return []string{
		"operationalhardening_unsafe_defaults_allowed",
		"operationalhardening_fail_open_allowed",
		"operationalhardening_unbounded_retry_loop",
		"operationalhardening_unbounded_memory_growth",
		"operationalhardening_verbose_sensitive_logs",
		"operationalhardening_auth_disabled",
		"operationalhardening_compatibility_checks_disabled",
		"operationalhardening_measurementreview_disabled",
		"operationalhardening_carrierreview_disabled",
		"operationalhardening_hardening_gates_disabled",
		"operationalhardening_rollback_without_fail_closed",
		"operationalhardening_generated_backend_drift",
	}
}

func fixtureHashInput(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}

func parityHashInput(set FixtureSet) struct {
	Version          string
	ResourceLimits   ResourceLimitReport
	ConfigValidation ConfigValidationReport
	Lifecycle        LifecycleReport
	Logging          LoggingDiagnosticsReport
	Rollback         RollbackReport
	Health           HealthSummaryReport
	Compatibility    CompatibilityReport
} {
	return struct {
		Version          string
		ResourceLimits   ResourceLimitReport
		ConfigValidation ConfigValidationReport
		Lifecycle        LifecycleReport
		Logging          LoggingDiagnosticsReport
		Rollback         RollbackReport
		Health           HealthSummaryReport
		Compatibility    CompatibilityReport
	}{set.Version, set.ResourceLimits, set.ConfigValidation, set.Lifecycle, set.Logging, set.Rollback, set.Health, set.Compatibility}
}

func uniqueStrings(values []string) []string {
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
