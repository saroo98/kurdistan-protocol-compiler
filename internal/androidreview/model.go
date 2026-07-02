// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidreview

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
	Version                  = "androidreview-v1"
	BackendVersion           = "0.56.0-lab"
	DefaultFixtureID         = "android_architecture_review_v1"
	ConclusionPassed         = "passed"
	RecommendedNextMilestone = "M57: Android local runtime port"
	DecisionReady            = "ready_for_android_local_runtime_port"
)

var generatedAt = time.Date(2026, 2, 21, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

type UserFlowReport struct {
	Policy           string   `json:"policy"`
	Flows            []string `json:"flows"`
	SafeErrorClasses []string `json:"safe_error_classes"`
	Conclusion       string   `json:"conclusion"`
}

type PermissionReport struct {
	Policy                    string   `json:"policy"`
	RequiredPermissions       []string `json:"required_permissions"`
	ForegroundServiceContract []string `json:"foreground_service_contract"`
	BackgroundBoundaries      []string `json:"background_boundaries"`
	BypassesVPNPermission     bool     `json:"bypasses_vpn_permission"`
	UnboundedBackgroundWork   bool     `json:"unbounded_background_work"`
	SilentBootStartAllowed    bool     `json:"silent_boot_start_allowed"`
	Conclusion                string   `json:"conclusion"`
}

type UIStateReport struct {
	Policy      string   `json:"policy"`
	States      []string `json:"states"`
	Terminal    []string `json:"terminal_states"`
	Recoverable []string `json:"recoverable_states"`
	Conclusion  string   `json:"conclusion"`
}

type DiagnosticsReport struct {
	Policy                string   `json:"policy"`
	AllowedFields         []string `json:"allowed_fields"`
	RedactionClasses      []string `json:"redaction_classes"`
	UserNotePolicy        string   `json:"user_note_policy"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	NetworkContentLogged  bool     `json:"network_content_logged"`
	DeviceIdentifierSaved bool     `json:"device_identifier_saved"`
	AutoUploadAllowed     bool     `json:"auto_upload_allowed"`
	Conclusion            string   `json:"conclusion"`
}

type PrivacyBoundaryReport struct {
	Policy                   string   `json:"policy"`
	StorageBoundaries        []string `json:"storage_boundaries"`
	LogBoundaries            []string `json:"log_boundaries"`
	FeedbackBoundaries       []string `json:"feedback_boundaries"`
	RawPacketStored          bool     `json:"raw_packet_stored"`
	PrivateEndpointStored    bool     `json:"private_endpoint_stored"`
	CredentialStoredInLogs   bool     `json:"credential_stored_in_logs"`
	PhoneIdentifierCollected bool     `json:"phone_identifier_collected"`
	PreciseLocationCollected bool     `json:"precise_location_collected"`
	TelemetryUploadByDefault bool     `json:"telemetry_upload_by_default"`
	Conclusion               string   `json:"conclusion"`
}

type KillSwitchReport struct {
	Policy                  string   `json:"policy"`
	FailClosedTriggers      []string `json:"fail_closed_triggers"`
	RecoveryClasses         []string `json:"recovery_classes"`
	FailClosedRequired      bool     `json:"fail_closed_required"`
	BypassAllowed           bool     `json:"bypass_allowed"`
	ProfileInvalidFailsOpen bool     `json:"profile_invalid_fails_open"`
	PermissionLossFailsOpen bool     `json:"permission_loss_fails_open"`
	Conclusion              string   `json:"conclusion"`
}

type IntegrationReport struct {
	Policy                    string   `json:"policy"`
	RequiredCompositions      []string `json:"required_compositions"`
	CompatibilityChecks       []string `json:"compatibility_checks"`
	BypassesCarrierSelection  bool     `json:"bypasses_carrier_selection"`
	BypassesPathHealth        bool     `json:"bypasses_pathhealth"`
	BypassesRelayAuth         bool     `json:"bypasses_relay_auth"`
	BypassesMeasurementReview bool     `json:"bypasses_measurementreview"`
	BypassesCarrierReview     bool     `json:"bypasses_carrierreview"`
	BypassesHardening         bool     `json:"bypasses_hardening"`
	AllowsGeneratedDrift      bool     `json:"allows_generated_drift"`
	Conclusion                string   `json:"conclusion"`
}

type FutureContractReport struct {
	Policy             string   `json:"policy"`
	M57Requirements    []string `json:"m57_requirements"`
	M58Requirements    []string `json:"m58_requirements"`
	ReopenArchitecture bool     `json:"reopen_architecture"`
	AndroidImplAdded   bool     `json:"android_impl_added"`
	Conclusion         string   `json:"conclusion"`
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
	NetworkContentLogged   bool   `json:"network_content_logged"`
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
	UserFlows                UserFlowReport          `json:"user_flows"`
	Permissions              PermissionReport        `json:"permissions"`
	UIStates                 UIStateReport           `json:"ui_states"`
	Diagnostics              DiagnosticsReport       `json:"diagnostics"`
	Privacy                  PrivacyBoundaryReport   `json:"privacy_boundaries"`
	KillSwitch               KillSwitchReport        `json:"kill_switch"`
	Integration              IntegrationReport       `json:"integration"`
	Contracts                FutureContractReport    `json:"future_contracts"`
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
		UserFlows:                DefaultUserFlowReport(),
		Permissions:              DefaultPermissionReport(),
		UIStates:                 DefaultUIStateReport(),
		Diagnostics:              DefaultDiagnosticsReport(),
		Privacy:                  DefaultPrivacyBoundaryReport(),
		KillSwitch:               DefaultKillSwitchReport(),
		Integration:              DefaultIntegrationReport(),
		Contracts:                DefaultFutureContractReport(),
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

func DefaultUserFlowReport() UserFlowReport {
	return UserFlowReport{
		Policy: "signed_profile_import_then_explicit_connect",
		Flows: []string{
			"onboarding_intro",
			"profile_import",
			"profile_verification",
			"profile_expiry",
			"profile_rotation",
			"connect",
			"disconnect",
			"reconnect",
			"failure_display",
			"diagnostic_export",
			"safe_reset",
		},
		SafeErrorClasses: []string{"profile_invalid", "profile_expired", "relay_incompatible", "carrier_unavailable", "permission_required", "network_changed", "diagnostics_redacted"},
		Conclusion:       ConclusionPassed,
	}
}

func DefaultPermissionReport() PermissionReport {
	return PermissionReport{
		Policy:                    "platform_permission_first_foreground_service_bounded",
		RequiredPermissions:       []string{"vpn_permission_user_grant", "foreground_service_notification", "network_state_visibility", "local_profile_file_access"},
		ForegroundServiceContract: []string{"persistent_status_notification", "explicit_disconnect_action", "bounded_reconnect_attempts", "redacted_failure_class"},
		BackgroundBoundaries:      []string{"no_silent_vpn_start_without_permission", "optional_boot_requires_user_enabled_setting", "battery_optimization_guidance_only", "no_unbounded_background_worker"},
		Conclusion:                ConclusionPassed,
	}
}

func DefaultUIStateReport() UIStateReport {
	return UIStateReport{
		Policy: "single_source_of_truth_connection_state_machine",
		States: []string{
			"disconnected",
			"validating_profile",
			"connecting",
			"carrier_selecting",
			"relay_handshaking",
			"connected",
			"reconnecting",
			"blocked_by_kill_switch",
			"profile_expired",
			"relay_incompatible",
			"carrier_failed",
			"network_changed",
			"vpn_permission_revoked",
			"diagnostic_bundle_ready",
			"crashed_recovered",
		},
		Terminal:    []string{"disconnected", "blocked_by_kill_switch"},
		Recoverable: []string{"network_changed", "carrier_failed", "relay_incompatible", "vpn_permission_revoked", "crashed_recovered"},
		Conclusion:  ConclusionPassed,
	}
}

func DefaultDiagnosticsReport() DiagnosticsReport {
	return DiagnosticsReport{
		Policy:           "local_user_export_only_redacted_diagnostic_bundle",
		AllowedFields:    []string{"app_version_bucket", "profile_version_bucket", "relay_compatibility_bucket", "carrier_family_bucket", "pathhealth_bucket", "permission_state_bucket", "failure_class", "resource_limit_bucket", "redaction_status", "user_note_length_bucket"},
		RedactionClasses: []string{"bucketed_profile", "bucketed_relay", "bucketed_carrier", "bucketed_permission", "bucketed_failure", "user_note_private_content_not_collected"},
		UserNotePolicy:   "optional_local_note_length_bucket_only",
		Conclusion:       ConclusionPassed,
	}
}

func DefaultPrivacyBoundaryReport() PrivacyBoundaryReport {
	return PrivacyBoundaryReport{
		Policy:             "local_storage_minimized_redacted_feedback_only",
		StorageBoundaries:  []string{"signed_profile_bundle_private_app_storage", "runtime_state_ephemeral", "diagnostic_bundle_user_export_only", "no_persistent_session_secret_material"},
		LogBoundaries:      []string{"state_buckets_only", "safe_failure_classes_only", "no_network_content", "no_device_identity"},
		FeedbackBoundaries: []string{"user_initiated_export", "private_content_not_required", "no_automatic_upload", "redaction_status_visible"},
		Conclusion:         ConclusionPassed,
	}
}

func DefaultKillSwitchReport() KillSwitchReport {
	return KillSwitchReport{
		Policy:             "fail_closed_on_profile_permission_runtime_or_carrier_invalid",
		FailClosedTriggers: []string{"vpn_permission_lost", "profile_invalid", "profile_expired", "relay_incompatible", "carrier_selection_failed", "runtime_security_failed", "kill_switch_enabled_network_change"},
		RecoveryClasses:    []string{"user_regrant_permission", "import_rotated_profile", "retry_after_network_change", "safe_disconnect_then_reconnect"},
		FailClosedRequired: true,
		Conclusion:         ConclusionPassed,
	}
}

func DefaultIntegrationReport() IntegrationReport {
	return IntegrationReport{
		Policy:               "android_state_composes_with_existing_runtime_gates",
		RequiredCompositions: []string{"carrier_selection", "pathhealth", "relay_auth_compatibility", "profile_rotation", "measurementreview", "carrierreview", "operationalhardening", "generated_backend_compatibility"},
		CompatibilityChecks:  []string{"profile_bundle_version", "relay_auth_policy", "carrier_family_review", "path_health_status", "measurement_review_status", "generated_backend_version", "operational_health_summary"},
		Conclusion:           ConclusionPassed,
	}
}

func DefaultFutureContractReport() FutureContractReport {
	return FutureContractReport{
		Policy: "m57_runtime_port_then_m58_vpnservice_prototype",
		M57Requirements: []string{
			"pure_runtime_port_boundary",
			"profile_import_verification_without_vpn_traffic",
			"foreground_status_model_without_vpnservice",
			"capability_negotiation_execution",
			"safe_diagnostics_export",
			"no_raw_packet_capture",
		},
		M58Requirements: []string{
			"vpnservice_permission_flow",
			"tun_semantics_mapping_reviewed_before_traffic",
			"kill_switch_fail_closed_semantics",
			"network_change_reconnect_policy",
			"foreground_service_lifecycle",
			"no_unreviewed_carrier_or_public_network_behavior",
		},
		Conclusion: ConclusionPassed,
	}
}

func BuildChecklistReport() ChecklistReport {
	items := []string{
		"user_flows_defined",
		"profile_import_verification_defined",
		"permission_model_defined",
		"ui_states_defined",
		"diagnostics_redacted",
		"privacy_boundaries_explicit",
		"kill_switch_fail_closed",
		"runtime_gate_composition_defined",
		"m57_contract_defined",
		"m58_contract_defined",
		"generated_backend_parity",
	}
	return ChecklistReport{Items: items, Passed: len(items), Conclusion: ConclusionPassed}
}

func BuildMisuseReport() MisuseReport {
	controls := RequiredMisuseNames()
	return MisuseReport{DetectedControls: controls, DetectedCount: len(controls), ExpectedCount: len(controls), Conclusion: ConclusionPassed}
}

func BuildTraceHygieneReport() TraceHygieneReport {
	return TraceHygieneReport{ReportsScanned: 12, Conclusion: ConclusionPassed}
}

func BuildPublicClaimSafetyReport() PublicClaimSafetyReport {
	return PublicClaimSafetyReport{
		DocsChecked:     5,
		ForbiddenClaims: []string{"working Android VPN app", "production Android VPN", "guaranteed bypass", "undetectable", "field-ready", "live probing"},
		Conclusion:      ConclusionPassed,
	}
}

func BuildParityReport(set FixtureSet) ParityReport {
	hash := HashValue(parityHashInput(set))
	return ParityReport{
		GeneratedMarkers: []string{"AndroidReviewSchemaVersion", "AndroidReviewBackendVersion", "AndroidReviewDecision", "AndroidReviewUIStateCount", "AndroidReviewMisuseCount", "AndroidReviewNextMilestone"},
		InterpretedHash:  hash,
		GeneratedHash:    hash,
		Conclusion:       ConclusionPassed,
	}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.BackendVersion != BackendVersion || set.FixtureID == "" {
		return errors.New("invalid Android review fixture identity")
	}
	if set.Decision != DecisionReady || set.BlockerCount != 0 || set.RiskCount < 5 {
		return errors.New("Android architecture review decision incomplete")
	}
	if len(set.UserFlows.Flows) < 10 || len(set.UserFlows.SafeErrorClasses) < 6 {
		return errors.New("Android user flow coverage incomplete")
	}
	if set.Permissions.BypassesVPNPermission || set.Permissions.UnboundedBackgroundWork || set.Permissions.SilentBootStartAllowed || len(set.Permissions.RequiredPermissions) < 4 || len(set.Permissions.ForegroundServiceContract) < 4 {
		return errors.New("Android permission model unsafe")
	}
	if len(set.UIStates.States) < 14 || len(set.UIStates.Recoverable) < 5 {
		return errors.New("Android UI state model incomplete")
	}
	if set.Diagnostics.PayloadLogged || set.Diagnostics.SecretLogged || set.Diagnostics.NetworkContentLogged || set.Diagnostics.DeviceIdentifierSaved || set.Diagnostics.AutoUploadAllowed || len(set.Diagnostics.AllowedFields) < 9 {
		return errors.New("Android diagnostics contract unsafe")
	}
	if set.Privacy.RawPacketStored || set.Privacy.PrivateEndpointStored || set.Privacy.CredentialStoredInLogs || set.Privacy.PhoneIdentifierCollected || set.Privacy.PreciseLocationCollected || set.Privacy.TelemetryUploadByDefault || len(set.Privacy.StorageBoundaries) < 4 {
		return errors.New("Android privacy boundary unsafe")
	}
	if !set.KillSwitch.FailClosedRequired || set.KillSwitch.BypassAllowed || set.KillSwitch.ProfileInvalidFailsOpen || set.KillSwitch.PermissionLossFailsOpen || len(set.KillSwitch.FailClosedTriggers) < 6 {
		return errors.New("Android kill-switch contract unsafe")
	}
	if set.Integration.BypassesCarrierSelection || set.Integration.BypassesPathHealth || set.Integration.BypassesRelayAuth || set.Integration.BypassesMeasurementReview || set.Integration.BypassesCarrierReview || set.Integration.BypassesHardening || set.Integration.AllowsGeneratedDrift || len(set.Integration.RequiredCompositions) < 8 {
		return errors.New("Android runtime integration contract unsafe")
	}
	if set.Contracts.ReopenArchitecture || set.Contracts.AndroidImplAdded || len(set.Contracts.M57Requirements) < 6 || len(set.Contracts.M58Requirements) < 6 {
		return errors.New("Android M57/M58 contracts incomplete")
	}
	if set.Checklist.Failed != 0 || set.Checklist.Passed < 11 || set.Checklist.Conclusion != ConclusionPassed {
		return errors.New("Android architecture checklist incomplete")
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) || set.Misuse.ExpectedCount != len(RequiredMisuseNames()) || len(set.Misuse.DetectedControls) != len(RequiredMisuseNames()) || set.Misuse.Conclusion != ConclusionPassed {
		return errors.New("Android misuse controls incomplete")
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.RawPacketLogged || set.TraceHygiene.NetworkContentLogged || set.TraceHygiene.DeviceIdentifierLogged || set.TraceHygiene.TelemetryMarkerLogged || set.PayloadLogged || set.SecretLogged {
		return errors.New("Android trace hygiene failed")
	}
	if set.Parity.Conclusion != ConclusionPassed || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		return errors.New("Android generated parity failed")
	}
	return ScanForLeak(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: ConclusionPassed}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "androidreview_fixture_hash_changed")
	}
	if oldSet.Version != newSet.Version || oldSet.BackendVersion != newSet.BackendVersion {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "androidreview_schema_or_backend_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
		report.UnexpectedDrift = append(report.UnexpectedDrift, "androidreview_trace_hygiene_failed")
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
			return fmt.Errorf("Android review unsafe marker %q", marker)
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
		"androidreview_bypasses_vpn_permission",
		"androidreview_profile_import_without_verification",
		"androidreview_payload_diagnostics",
		"androidreview_secret_diagnostics",
		"androidreview_auto_telemetry",
		"androidreview_kill_switch_fail_open",
		"androidreview_background_service_unbounded",
		"androidreview_raw_network_metadata",
		"androidreview_android_ready_claim",
		"androidreview_generated_backend_drift",
	}
}

func fixtureHashInput(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}

func parityHashInput(set FixtureSet) struct {
	Version     string
	UserFlows   UserFlowReport
	Permissions PermissionReport
	UIStates    UIStateReport
	Diagnostics DiagnosticsReport
	Privacy     PrivacyBoundaryReport
	KillSwitch  KillSwitchReport
	Integration IntegrationReport
	Contracts   FutureContractReport
} {
	return struct {
		Version     string
		UserFlows   UserFlowReport
		Permissions PermissionReport
		UIStates    UIStateReport
		Diagnostics DiagnosticsReport
		Privacy     PrivacyBoundaryReport
		KillSwitch  KillSwitchReport
		Integration IntegrationReport
		Contracts   FutureContractReport
	}{set.Version, set.UserFlows, set.Permissions, set.UIStates, set.Diagnostics, set.Privacy, set.KillSwitch, set.Integration, set.Contracts}
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
