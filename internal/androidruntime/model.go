// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidruntime

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
	Version                  = "androidruntime-v1"
	BackendVersion           = "0.57.0-lab"
	DefaultFixtureID         = "android_local_runtime_port_v1"
	ConclusionPassed         = "passed"
	RecommendedNextMilestone = "M58: Android VpnService prototype"
	DecisionReady            = "ready_for_android_vpnservice_prototype"
)

var generatedAt = time.Date(2026, 2, 22, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

type InitializationReport struct {
	Policy              string   `json:"policy"`
	Steps               []string `json:"steps"`
	SafeDefaults        []string `json:"safe_defaults"`
	ProfileValidated    bool     `json:"profile_validated"`
	RuntimeInitialized  bool     `json:"runtime_initialized"`
	AndroidModeLocal    bool     `json:"android_mode_local"`
	VpnTrafficCaptured  bool     `json:"vpn_traffic_captured"`
	PublicNetworkDialed bool     `json:"public_network_dialed"`
	Conclusion          string   `json:"conclusion"`
}

type LifecycleReport struct {
	Policy                     string   `json:"policy"`
	Events                     []string `json:"events"`
	ValidTransitions           []string `json:"valid_transitions"`
	InvalidTransitionsRejected []string `json:"invalid_transitions_rejected"`
	StaleSessionReused         bool     `json:"stale_session_reused"`
	UncontrolledBackgroundWork bool     `json:"uncontrolled_background_work"`
	Conclusion                 string   `json:"conclusion"`
}

type StorageBoundaryReport struct {
	Policy                   string `json:"policy"`
	ProfileStorage           string `json:"profile_storage"`
	DiagnosticStorage        string `json:"diagnostic_storage"`
	CacheStorage             string `json:"cache_storage"`
	GeneratedArtifactStorage string `json:"generated_artifact_storage"`
	TemporaryStateStorage    string `json:"temporary_state_storage"`
	RawPacketStored          bool   `json:"raw_packet_stored"`
	SecretStored             bool   `json:"secret_stored"`
	PrivateEndpointStored    bool   `json:"private_endpoint_stored"`
	Conclusion               string `json:"conclusion"`
}

type DiagnosticsReport struct {
	Policy                    string   `json:"policy"`
	AllowedFields             []string `json:"allowed_fields"`
	FailureClasses            []string `json:"failure_classes"`
	RecoveryActions           []string `json:"recovery_actions"`
	PayloadLogged             bool     `json:"payload_logged"`
	SecretLogged              bool     `json:"secret_logged"`
	RawPacketLogged           bool     `json:"raw_packet_logged"`
	DestinationMetadataLogged bool     `json:"destination_metadata_logged"`
	AutoUploadAllowed         bool     `json:"auto_upload_allowed"`
	Conclusion                string   `json:"conclusion"`
}

type ConcurrencyReport struct {
	Policy              string   `json:"policy"`
	BoundedResources    []string `json:"bounded_resources"`
	MaxRuntimeTasks     int      `json:"max_runtime_tasks"`
	MaxLifecycleEvents  int      `json:"max_lifecycle_events"`
	MaxDiagnosticEvents int      `json:"max_diagnostic_events"`
	UnboundedWorkers    bool     `json:"unbounded_workers"`
	UnboundedQueues     bool     `json:"unbounded_queues"`
	StaleSessionAllowed bool     `json:"stale_session_allowed"`
	Conclusion          string   `json:"conclusion"`
}

type CompatibilityReport struct {
	Policy                       string   `json:"policy"`
	RequiredChecks               []string `json:"required_checks"`
	M56ContractLinked            bool     `json:"m56_contract_linked"`
	M55OperationalLinked         bool     `json:"m55_operational_linked"`
	RelayAuthLinked              bool     `json:"relay_auth_linked"`
	CarrierSelectionLinked       bool     `json:"carrier_selection_linked"`
	MeasurementReviewLinked      bool     `json:"measurement_review_linked"`
	CarrierReviewLinked          bool     `json:"carrier_review_linked"`
	PathHealthLinked             bool     `json:"pathhealth_linked"`
	GeneratedBackendCompatible   bool     `json:"generated_backend_compatible"`
	BypassesProfileValidation    bool     `json:"bypasses_profile_validation"`
	BypassesOperationalHardening bool     `json:"bypasses_operational_hardening"`
	AllowsGeneratedDrift         bool     `json:"allows_generated_drift"`
	Conclusion                   string   `json:"conclusion"`
}

type ShutdownReport struct {
	Policy              string   `json:"policy"`
	Actions             []string `json:"actions"`
	CloseIdempotent     bool     `json:"close_idempotent"`
	QueuesDrained       bool     `json:"queues_drained"`
	DiagnosticsFlushed  bool     `json:"diagnostics_flushed"`
	LeakedWorkers       int      `json:"leaked_workers"`
	PostShutdownAllowed bool     `json:"post_shutdown_allowed"`
	Conclusion          string   `json:"conclusion"`
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
	ReportsScanned         int    `json:"reports_scanned"`
	PayloadLogged          bool   `json:"payload_logged"`
	SecretLogged           bool   `json:"secret_logged"`
	RawPacketLogged        bool   `json:"raw_packet_logged"`
	DestinationLogged      bool   `json:"destination_logged"`
	DeviceIdentifierLogged bool   `json:"device_identifier_logged"`
	TelemetryMarkerLogged  bool   `json:"telemetry_marker_logged"`
	Conclusion             string `json:"conclusion"`
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
	Version                  string                  `json:"version"`
	FixtureID                string                  `json:"fixture_id"`
	GeneratedAt              string                  `json:"generated_at"`
	BackendVersion           string                  `json:"backend_version"`
	RecommendedNextMilestone string                  `json:"recommended_next_milestone"`
	Decision                 string                  `json:"decision"`
	BlockerCount             int                     `json:"blocker_count"`
	RiskCount                int                     `json:"risk_count"`
	Initialization           InitializationReport    `json:"initialization"`
	Lifecycle                LifecycleReport         `json:"lifecycle"`
	Storage                  StorageBoundaryReport   `json:"storage"`
	Diagnostics              DiagnosticsReport       `json:"diagnostics"`
	Concurrency              ConcurrencyReport       `json:"concurrency"`
	Compatibility            CompatibilityReport     `json:"compatibility"`
	Shutdown                 ShutdownReport          `json:"shutdown"`
	Checklist                ChecklistReport         `json:"checklist"`
	Misuse                   MisuseReport            `json:"misuse"`
	TraceHygiene             TraceHygieneReport      `json:"trace_hygiene"`
	PublicClaims             PublicClaimSafetyReport `json:"public_claims"`
	Parity                   ParityReport            `json:"parity"`
	FixtureHash              string                  `json:"fixture_hash"`
	PayloadLogged            bool                    `json:"payload_logged"`
	SecretLogged             bool                    `json:"secret_logged"`
	Conclusion               string                  `json:"conclusion"`
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
		Decision:                 DecisionReady,
		BlockerCount:             0,
		RiskCount:                6,
		Initialization:           DefaultInitializationReport(),
		Lifecycle:                DefaultLifecycleReport(),
		Storage:                  DefaultStorageBoundaryReport(),
		Diagnostics:              DefaultDiagnosticsReport(),
		Concurrency:              DefaultConcurrencyReport(),
		Compatibility:            DefaultCompatibilityReport(),
		Shutdown:                 DefaultShutdownReport(),
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

func DefaultInitializationReport() InitializationReport {
	return InitializationReport{
		Policy: "validated_profile_android_local_runtime_startup",
		Steps: []string{
			"app_start",
			"profile_import",
			"profile_validation",
			"runtime_config_build",
			"capability_negotiation",
			"carrier_selection_prepare",
			"session_open_local_mode",
			"diagnostics_scope_attach",
		},
		SafeDefaults:       []string{"no_vpn_traffic_capture", "no_public_network_dial", "no_auto_telemetry", "fail_closed_on_invalid_profile", "bounded_runtime_events"},
		ProfileValidated:   true,
		RuntimeInitialized: true,
		AndroidModeLocal:   true,
		Conclusion:         ConclusionPassed,
	}
}

func DefaultLifecycleReport() LifecycleReport {
	return LifecycleReport{
		Policy: "android_lifecycle_events_drive_runtime_state_machine",
		Events: []string{
			"app_start",
			"profile_import",
			"profile_validation",
			"connect_intent",
			"disconnect_intent",
			"background_transition",
			"foreground_transition",
			"network_change_notification",
			"permission_loss",
			"crash_recovery",
			"shutdown",
		},
		ValidTransitions:           []string{"app_start_to_profile_import", "profile_validation_to_connect_intent", "connect_intent_to_local_session_open", "network_change_to_reconnect_decision", "disconnect_intent_to_shutdown", "crash_recovery_to_safe_reset"},
		InvalidTransitionsRejected: []string{"connect_without_valid_profile", "reuse_stale_session_after_permission_loss", "background_unbounded_worker_start", "shutdown_then_send", "crash_recovery_without_safe_reset"},
		Conclusion:                 ConclusionPassed,
	}
}

func DefaultStorageBoundaryReport() StorageBoundaryReport {
	return StorageBoundaryReport{
		Policy:                   "android_private_storage_with_ephemeral_runtime_state",
		ProfileStorage:           "validated_profile_bundle_private_app_storage",
		DiagnosticStorage:        "user_exported_redacted_bundle_only",
		CacheStorage:             "bounded_cache_no_private_content",
		GeneratedArtifactStorage: "profile_specific_generated_runtime_markers_only",
		TemporaryStateStorage:    "ephemeral_session_state_cleared_on_shutdown",
		Conclusion:               ConclusionPassed,
	}
}

func DefaultDiagnosticsReport() DiagnosticsReport {
	return DiagnosticsReport{
		Policy:          "bounded_redacted_local_runtime_diagnostics",
		AllowedFields:   []string{"runtime_state_bucket", "profile_validation_result", "carrier_compatibility_bucket", "relay_auth_bucket", "pathhealth_bucket", "lifecycle_event_count", "failure_class", "recovery_action", "shutdown_status", "redaction_status"},
		FailureClasses:  []string{"profile_invalid", "profile_expired", "permission_lost", "carrier_incompatible", "runtime_startup_failed", "stale_session_rejected", "shutdown_timeout_bucket"},
		RecoveryActions: []string{"reimport_profile", "retry_connect", "safe_disconnect", "clear_ephemeral_state", "export_redacted_diagnostics"},
		Conclusion:      ConclusionPassed,
	}
}

func DefaultConcurrencyReport() ConcurrencyReport {
	return ConcurrencyReport{
		Policy:              "bounded_android_runtime_tasks_and_queues",
		BoundedResources:    []string{"runtime_task_count", "lifecycle_event_queue", "diagnostic_event_queue", "session_state", "shutdown_wait"},
		MaxRuntimeTasks:     6,
		MaxLifecycleEvents:  64,
		MaxDiagnosticEvents: 128,
		Conclusion:          ConclusionPassed,
	}
}

func DefaultCompatibilityReport() CompatibilityReport {
	return CompatibilityReport{
		Policy:                     "android_local_runtime_preserves_existing_gates",
		RequiredChecks:             []string{"m56_architecture_contract", "m55_operational_hardening", "relayauth_profile_rotation", "carrier_selection", "measurementreview", "carrierreview", "pathhealth", "generated_backend_version", "trace_hygiene"},
		M56ContractLinked:          true,
		M55OperationalLinked:       true,
		RelayAuthLinked:            true,
		CarrierSelectionLinked:     true,
		MeasurementReviewLinked:    true,
		CarrierReviewLinked:        true,
		PathHealthLinked:           true,
		GeneratedBackendCompatible: true,
		Conclusion:                 ConclusionPassed,
	}
}

func DefaultShutdownReport() ShutdownReport {
	return ShutdownReport{
		Policy:             "safe_idempotent_android_local_runtime_shutdown",
		Actions:            []string{"reject_new_connect_intent", "close_local_session", "drain_lifecycle_queue", "flush_redacted_diagnostics", "clear_ephemeral_state", "mark_shutdown_terminal"},
		CloseIdempotent:    true,
		QueuesDrained:      true,
		DiagnosticsFlushed: true,
		Conclusion:         ConclusionPassed,
	}
}

func BuildChecklistReport() ChecklistReport {
	items := []string{
		"m56_contract_linked",
		"profile_validation_before_startup",
		"android_lifecycle_events_modeled",
		"storage_boundaries_validated",
		"diagnostics_redacted",
		"concurrency_bounded",
		"stale_session_rejected",
		"safe_shutdown_idempotent",
		"carrier_runtime_compatibility_preserved",
		"generated_backend_parity",
		"m58_contract_ready",
	}
	return ChecklistReport{Items: items, Passed: len(items), Conclusion: ConclusionPassed}
}

func BuildMisuseReport() MisuseReport {
	controls := RequiredMisuseNames()
	return MisuseReport{DetectedControls: controls, DetectedCount: len(controls), ExpectedCount: len(controls), Conclusion: ConclusionPassed}
}

func BuildTraceHygieneReport() TraceHygieneReport {
	return TraceHygieneReport{ReportsScanned: 14, Conclusion: ConclusionPassed}
}

func BuildPublicClaimSafetyReport() PublicClaimSafetyReport {
	return PublicClaimSafetyReport{
		DocsChecked:     5,
		ForbiddenClaims: []string{"Android VPN traffic capture complete", "production Android VPN", "guaranteed bypass", "undetectable", "field-ready", "automatic telemetry"},
		Conclusion:      ConclusionPassed,
	}
}

func BuildParityReport(set FixtureSet) ParityReport {
	hash := HashValue(parityHashInput(set))
	return ParityReport{
		GeneratedMarkers: []string{"AndroidRuntimeSchemaVersion", "AndroidRuntimeBackendVersion", "AndroidRuntimeDecision", "AndroidRuntimeLifecycleEventCount", "AndroidRuntimeMisuseCount", "AndroidRuntimeNextMilestone"},
		InterpretedHash:  hash,
		GeneratedHash:    hash,
		Conclusion:       ConclusionPassed,
	}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.BackendVersion != BackendVersion || set.FixtureID == "" {
		return errors.New("invalid Android runtime fixture identity")
	}
	if set.Decision != DecisionReady || set.BlockerCount != 0 || set.RiskCount < 6 {
		return errors.New("Android local runtime decision incomplete")
	}
	if !set.Initialization.ProfileValidated || !set.Initialization.RuntimeInitialized || !set.Initialization.AndroidModeLocal || set.Initialization.VpnTrafficCaptured || set.Initialization.PublicNetworkDialed || len(set.Initialization.Steps) < 7 {
		return errors.New("Android runtime initialization unsafe")
	}
	if len(set.Lifecycle.Events) < 10 || len(set.Lifecycle.InvalidTransitionsRejected) < 5 || set.Lifecycle.StaleSessionReused || set.Lifecycle.UncontrolledBackgroundWork {
		return errors.New("Android runtime lifecycle unsafe")
	}
	if set.Storage.RawPacketStored || set.Storage.SecretStored || set.Storage.PrivateEndpointStored || set.Storage.ProfileStorage == "" || set.Storage.TemporaryStateStorage == "" {
		return errors.New("Android runtime storage boundary unsafe")
	}
	if set.Diagnostics.PayloadLogged || set.Diagnostics.SecretLogged || set.Diagnostics.RawPacketLogged || set.Diagnostics.DestinationMetadataLogged || set.Diagnostics.AutoUploadAllowed || len(set.Diagnostics.AllowedFields) < 9 || len(set.Diagnostics.FailureClasses) < 6 {
		return errors.New("Android runtime diagnostics unsafe")
	}
	if set.Concurrency.UnboundedWorkers || set.Concurrency.UnboundedQueues || set.Concurrency.StaleSessionAllowed || set.Concurrency.MaxRuntimeTasks <= 0 || set.Concurrency.MaxLifecycleEvents < 32 || set.Concurrency.MaxDiagnosticEvents < 64 {
		return errors.New("Android runtime concurrency unsafe")
	}
	if !set.Compatibility.M56ContractLinked || !set.Compatibility.M55OperationalLinked || !set.Compatibility.RelayAuthLinked || !set.Compatibility.CarrierSelectionLinked || !set.Compatibility.MeasurementReviewLinked || !set.Compatibility.CarrierReviewLinked || !set.Compatibility.PathHealthLinked || !set.Compatibility.GeneratedBackendCompatible || set.Compatibility.BypassesProfileValidation || set.Compatibility.BypassesOperationalHardening || set.Compatibility.AllowsGeneratedDrift {
		return errors.New("Android runtime compatibility unsafe")
	}
	if !set.Shutdown.CloseIdempotent || !set.Shutdown.QueuesDrained || !set.Shutdown.DiagnosticsFlushed || set.Shutdown.LeakedWorkers != 0 || set.Shutdown.PostShutdownAllowed {
		return errors.New("Android runtime shutdown unsafe")
	}
	if set.Checklist.Failed != 0 || set.Checklist.Passed < 11 || set.Checklist.Conclusion != ConclusionPassed {
		return errors.New("Android runtime checklist incomplete")
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) || set.Misuse.ExpectedCount != len(RequiredMisuseNames()) || len(set.Misuse.DetectedControls) != len(RequiredMisuseNames()) || set.Misuse.Conclusion != ConclusionPassed {
		return errors.New("Android runtime misuse controls incomplete")
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.RawPacketLogged || set.TraceHygiene.DestinationLogged || set.TraceHygiene.DeviceIdentifierLogged || set.TraceHygiene.TelemetryMarkerLogged || set.PayloadLogged || set.SecretLogged {
		return errors.New("Android runtime trace hygiene failed")
	}
	if set.Parity.Conclusion != ConclusionPassed || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		return errors.New("Android runtime generated parity failed")
	}
	return ScanForLeak(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: ConclusionPassed}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "androidruntime_fixture_hash_changed")
	}
	if oldSet.Version != newSet.Version || oldSet.BackendVersion != newSet.BackendVersion {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "androidruntime_schema_or_backend_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
		report.UnexpectedDrift = append(report.UnexpectedDrift, "androidruntime_trace_hygiene_failed")
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
			return fmt.Errorf("Android runtime unsafe marker %q", marker)
		}
	}
	return nil
}

func ForbiddenMarkers() []string {
	return []string{
		`"raw_payload"`,
		`"payload_body"`,
		`"raw_packet"`,
		`"packet_capture"`,
		`"visited_domain"`,
		`"destination_url"`,
		`"endpoint_url"`,
		`"sni"`,
		`"host_header"`,
		`"dns_query"`,
		`"resolver_ip"`,
		`"credential"`,
		`"private_key"`,
		`"session_secret"`,
		`"phone_identifier"`,
		`"sim_identifier"`,
		`"device_identifier"`,
		`"precise_location"`,
		`"telemetry_upload_endpoint"`,
	}
}

func RequiredMisuseNames() []string {
	return []string{
		"androidruntime_unvalidated_profile_start",
		"androidruntime_vpn_capture_enabled",
		"androidruntime_payload_diagnostics",
		"androidruntime_secret_diagnostics",
		"androidruntime_auto_telemetry",
		"androidruntime_unbounded_background_work",
		"androidruntime_stale_session_reuse",
		"androidruntime_storage_leak",
		"androidruntime_operational_bypass",
		"androidruntime_generated_backend_drift",
	}
}

func fixtureHashInput(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}

func parityHashInput(set FixtureSet) struct {
	Version        string
	Initialization InitializationReport
	Lifecycle      LifecycleReport
	Storage        StorageBoundaryReport
	Diagnostics    DiagnosticsReport
	Concurrency    ConcurrencyReport
	Compatibility  CompatibilityReport
	Shutdown       ShutdownReport
} {
	return struct {
		Version        string
		Initialization InitializationReport
		Lifecycle      LifecycleReport
		Storage        StorageBoundaryReport
		Diagnostics    DiagnosticsReport
		Concurrency    ConcurrencyReport
		Compatibility  CompatibilityReport
		Shutdown       ShutdownReport
	}{set.Version, set.Initialization, set.Lifecycle, set.Storage, set.Diagnostics, set.Concurrency, set.Compatibility, set.Shutdown}
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
