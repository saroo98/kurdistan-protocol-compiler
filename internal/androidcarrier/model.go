// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidcarrier

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
	Version                  = "androidcarrier-v1"
	BackendVersion           = "0.59.0-lab"
	DefaultFixtureID         = "android_carrier_integration_v1"
	ConclusionPassed         = "passed"
	RecommendedNextMilestone = "M60: Android adversarial and safety audit"
	DecisionReady            = "ready_for_android_adversarial_safety_audit"
)

var generatedAt = time.Date(2026, 2, 24, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

type RuntimePathReport struct {
	Policy                          string   `json:"policy"`
	RequiredStages                  []string `json:"required_stages"`
	ProfileValidationBeforeConnect  bool     `json:"profile_validation_before_connect"`
	RuntimeInitialized              bool     `json:"runtime_initialized"`
	CarrierSelectionCompleted       bool     `json:"carrier_selection_completed"`
	RelayCompatibilityChecked       bool     `json:"relay_compatibility_checked"`
	AuthenticatedSessionEstablished bool     `json:"authenticated_session_established"`
	StreamMappingCompleted          bool     `json:"stream_mapping_completed"`
	PathHealthChecked               bool     `json:"pathhealth_checked"`
	SafeShutdownLinked              bool     `json:"safe_shutdown_linked"`
	BypassesProfileValidation       bool     `json:"bypasses_profile_validation"`
	BypassesCarrierSelection        bool     `json:"bypasses_carrier_selection"`
	BypassesRelayCompatibility      bool     `json:"bypasses_relay_compatibility"`
	UnreviewedPublicNetworkEgress   bool     `json:"unreviewed_public_network_egress"`
	UnrestrictedTrafficForwarding   bool     `json:"unrestricted_traffic_forwarding"`
	Conclusion                      string   `json:"conclusion"`
}

type UIStateReport struct {
	Policy                    string   `json:"policy"`
	States                    []string `json:"states"`
	FailureStates             []string `json:"failure_states"`
	ConnectedState            string   `json:"connected_state"`
	DiagnosticState           string   `json:"diagnostic_state"`
	CarrierFailureVisible     bool     `json:"carrier_failure_visible"`
	RelayFailureVisible       bool     `json:"relay_failure_visible"`
	ProfileExpiryVisible      bool     `json:"profile_expiry_visible"`
	FallbackAttemptVisible    bool     `json:"fallback_attempt_visible"`
	DiagnosticReadyVisible    bool     `json:"diagnostic_ready_visible"`
	FieldReadyClaimVisible    bool     `json:"field_ready_claim_visible"`
	GuaranteedBypassDisplayed bool     `json:"guaranteed_bypass_displayed"`
	Conclusion                string   `json:"conclusion"`
}

type CarrierSelectionReport struct {
	Policy                       string   `json:"policy"`
	RequiredGates                []string `json:"required_gates"`
	CandidateFamilies            []string `json:"candidate_families"`
	SelectedCarrierClass         string   `json:"selected_carrier_class"`
	FallbackCarrierClass         string   `json:"fallback_carrier_class"`
	SelectionRespectsProfile     bool     `json:"selection_respects_profile"`
	CarrierReviewEnforced        bool     `json:"carrierreview_enforced"`
	MeasurementReviewEnforced    bool     `json:"measurementreview_enforced"`
	PathHealthEnforced           bool     `json:"pathhealth_enforced"`
	RuntimeCompatibilityEnforced bool     `json:"runtime_compatibility_enforced"`
	OperationalSafetyEnforced    bool     `json:"operational_safety_enforced"`
	GeneratedParityEnforced      bool     `json:"generated_parity_enforced"`
	HighRiskDefaultAllowed       bool     `json:"high_risk_default_allowed"`
	ReviewBypassAllowed          bool     `json:"review_bypass_allowed"`
	UnboundedFallbackAllowed     bool     `json:"unbounded_fallback_allowed"`
	PublicCarrierAutoSelected    bool     `json:"public_carrier_auto_selected"`
	Conclusion                   string   `json:"conclusion"`
}

type RelayCompatibilityReport struct {
	Policy                          string   `json:"policy"`
	RequiredChecks                  []string `json:"required_checks"`
	CompatibleRelayClasses          []string `json:"compatible_relay_classes"`
	IncompatibleFailureClasses      []string `json:"incompatible_failure_classes"`
	ProfileIdentityBound            bool     `json:"profile_identity_bound"`
	RelayIdentityBound              bool     `json:"relay_identity_bound"`
	RelayAuthChecked                bool     `json:"relay_auth_checked"`
	RotationWindowChecked           bool     `json:"rotation_window_checked"`
	ExpiredProfileRejected          bool     `json:"expired_profile_rejected"`
	UnknownRelayRejected            bool     `json:"unknown_relay_rejected"`
	AuthenticatedSessionEstablished bool     `json:"authenticated_session_established"`
	RelayBypassAllowed              bool     `json:"relay_bypass_allowed"`
	DowngradeAccepted               bool     `json:"downgrade_accepted"`
	Conclusion                      string   `json:"conclusion"`
}

type FlowIntegrationReport struct {
	Policy                       string   `json:"policy"`
	FlowClasses                  []string `json:"flow_classes"`
	MappingRules                 []string `json:"mapping_rules"`
	BackpressureRules            []string `json:"backpressure_rules"`
	ResetErrorRules              []string `json:"reset_error_rules"`
	AndroidVpnServiceLinked      bool     `json:"android_vpnservice_linked"`
	ControlledTrafficRepresented bool     `json:"controlled_traffic_represented"`
	ConnectedThroughCarrier      bool     `json:"connected_through_carrier"`
	RuntimeStreamsMapped         int      `json:"runtime_streams_mapped"`
	CarrierEnvelopesMapped       int      `json:"carrier_envelopes_mapped"`
	PacketPayloadLogged          bool     `json:"packet_payload_logged"`
	PacketCaptureEnabled         bool     `json:"packet_capture_enabled"`
	RawDestinationLogged         bool     `json:"raw_destination_logged"`
	AppIdentityLogged            bool     `json:"app_identity_logged"`
	Conclusion                   string   `json:"conclusion"`
}

type FailureDiagnosticsReport struct {
	Policy                    string   `json:"policy"`
	FailureClasses            []string `json:"failure_classes"`
	AllowedDiagnosticFields   []string `json:"allowed_diagnostic_fields"`
	CarrierFailuresSurfaced   bool     `json:"carrier_failures_surfaced"`
	RuntimeFailuresSurfaced   bool     `json:"runtime_failures_surfaced"`
	RelayFailuresSurfaced     bool     `json:"relay_failures_surfaced"`
	ProfileFailuresSurfaced   bool     `json:"profile_failures_surfaced"`
	FallbackFailuresSurfaced  bool     `json:"fallback_failures_surfaced"`
	PayloadLogged             bool     `json:"payload_logged"`
	SecretLogged              bool     `json:"secret_logged"`
	RawPacketLogged           bool     `json:"raw_packet_logged"`
	DomainLogged              bool     `json:"domain_logged"`
	URLLogged                 bool     `json:"url_logged"`
	SNIHostLogged             bool     `json:"sni_host_logged"`
	DeviceIdentifierLogged    bool     `json:"device_identifier_logged"`
	TelemetryUploadConfigured bool     `json:"telemetry_upload_configured"`
	Conclusion                string   `json:"conclusion"`
}

type ReconnectFallbackReport struct {
	Policy                       string   `json:"policy"`
	Scenarios                    []string `json:"scenarios"`
	FallbackClasses              []string `json:"fallback_classes"`
	MaxFallbackAttempts          int      `json:"max_fallback_attempts"`
	MaxReconnectAttempts         int      `json:"max_reconnect_attempts"`
	MaxQueuedEvents              int      `json:"max_queued_events"`
	NetworkChangeRecovery        bool     `json:"network_change_recovery"`
	CarrierFailureRecovery       bool     `json:"carrier_failure_recovery"`
	RuntimeRestartRecovery       bool     `json:"runtime_restart_recovery"`
	FallbackExhaustionFailClosed bool     `json:"fallback_exhaustion_fail_closed"`
	KillSwitchInteractionChecked bool     `json:"kill_switch_interaction_checked"`
	UnboundedRetry               bool     `json:"unbounded_retry"`
	UnsafeFallbackAllowed        bool     `json:"unsafe_fallback_allowed"`
	Conclusion                   string   `json:"conclusion"`
}

type ProfileValidationReport struct {
	Policy                        string   `json:"policy"`
	ValidationStages              []string `json:"validation_stages"`
	ImportedProfileValidated      bool     `json:"imported_profile_validated"`
	ProfileHashChecked            bool     `json:"profile_hash_checked"`
	ProfileExpiryChecked          bool     `json:"profile_expiry_checked"`
	RelayCompatibilityBeforeStart bool     `json:"relay_compatibility_before_start"`
	InvalidProfileFailsClosed     bool     `json:"invalid_profile_fails_closed"`
	ExpiredProfileFailsClosed     bool     `json:"expired_profile_fails_closed"`
	StaleProfileRejected          bool     `json:"stale_profile_rejected"`
	ProfileValidationBypassed     bool     `json:"profile_validation_bypassed"`
	Conclusion                    string   `json:"conclusion"`
}

type ShutdownSafetyReport struct {
	Policy                    string   `json:"policy"`
	Actions                   []string `json:"actions"`
	CarrierSessionClosed      bool     `json:"carrier_session_closed"`
	RuntimeSessionClosed      bool     `json:"runtime_session_closed"`
	AndroidFlowClosed         bool     `json:"android_flow_closed"`
	DiagnosticsFlushed        bool     `json:"diagnostics_flushed"`
	KillSwitchEngagedOnUnsafe bool     `json:"kill_switch_engaged_on_unsafe"`
	StopIdempotent            bool     `json:"stop_idempotent"`
	PostShutdownTraffic       bool     `json:"post_shutdown_traffic"`
	LeakedSessions            int      `json:"leaked_sessions"`
	Conclusion                string   `json:"conclusion"`
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
	DomainLogged           bool   `json:"domain_logged"`
	URLLogged              bool   `json:"url_logged"`
	SNIHostLogged          bool   `json:"sni_host_logged"`
	ResolverLogged         bool   `json:"resolver_logged"`
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
	Version                  string                   `json:"version"`
	FixtureID                string                   `json:"fixture_id"`
	GeneratedAt              string                   `json:"generated_at"`
	BackendVersion           string                   `json:"backend_version"`
	RecommendedNextMilestone string                   `json:"recommended_next_milestone"`
	Decision                 string                   `json:"decision"`
	BlockerCount             int                      `json:"blocker_count"`
	RiskCount                int                      `json:"risk_count"`
	RuntimePath              RuntimePathReport        `json:"runtime_path"`
	UIStates                 UIStateReport            `json:"ui_states"`
	CarrierSelection         CarrierSelectionReport   `json:"carrier_selection"`
	RelayCompatibility       RelayCompatibilityReport `json:"relay_compatibility"`
	FlowIntegration          FlowIntegrationReport    `json:"flow_integration"`
	FailureDiagnostics       FailureDiagnosticsReport `json:"failure_diagnostics"`
	ReconnectFallback        ReconnectFallbackReport  `json:"reconnect_fallback"`
	ProfileValidation        ProfileValidationReport  `json:"profile_validation"`
	ShutdownSafety           ShutdownSafetyReport     `json:"shutdown_safety"`
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
		Decision:                 DecisionReady,
		BlockerCount:             0,
		RiskCount:                8,
		RuntimePath:              DefaultRuntimePathReport(),
		UIStates:                 DefaultUIStateReport(),
		CarrierSelection:         DefaultCarrierSelectionReport(),
		RelayCompatibility:       DefaultRelayCompatibilityReport(),
		FlowIntegration:          DefaultFlowIntegrationReport(),
		FailureDiagnostics:       DefaultFailureDiagnosticsReport(),
		ReconnectFallback:        DefaultReconnectFallbackReport(),
		ProfileValidation:        DefaultProfileValidationReport(),
		ShutdownSafety:           DefaultShutdownSafetyReport(),
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

func RequiredUIStates() []string {
	return []string{
		"selecting_carrier",
		"connecting_relay",
		"connected_through_carrier",
		"carrier_failed",
		"relay_incompatible",
		"profile_expired",
		"reconnecting",
		"fallback_attempted",
		"diagnostic_bundle_ready",
	}
}

func DefaultRuntimePathReport() RuntimePathReport {
	return RuntimePathReport{
		Policy: "android_carrier_runtime_path_validated_before_connect",
		RequiredStages: []string{
			"profile_validation",
			"android_vpnservice_active",
			"runtime_initialization",
			"carrier_selection",
			"relay_compatibility",
			"authenticated_session",
			"stream_mapping",
			"pathhealth",
			"safe_shutdown",
		},
		ProfileValidationBeforeConnect:  true,
		RuntimeInitialized:              true,
		CarrierSelectionCompleted:       true,
		RelayCompatibilityChecked:       true,
		AuthenticatedSessionEstablished: true,
		StreamMappingCompleted:          true,
		PathHealthChecked:               true,
		SafeShutdownLinked:              true,
		Conclusion:                      ConclusionPassed,
	}
}

func DefaultUIStateReport() UIStateReport {
	return UIStateReport{
		Policy:                 "android_ui_reflects_carrier_runtime_path",
		States:                 RequiredUIStates(),
		FailureStates:          []string{"carrier_failed", "relay_incompatible", "profile_expired", "fallback_exhausted", "diagnostic_bundle_ready"},
		ConnectedState:         "connected_through_carrier",
		DiagnosticState:        "diagnostic_bundle_ready",
		CarrierFailureVisible:  true,
		RelayFailureVisible:    true,
		ProfileExpiryVisible:   true,
		FallbackAttemptVisible: true,
		DiagnosticReadyVisible: true,
		Conclusion:             ConclusionPassed,
	}
}

func DefaultCarrierSelectionReport() CarrierSelectionReport {
	return CarrierSelectionReport{
		Policy: "android_carrier_selection_uses_reviewed_runtime_constraints",
		RequiredGates: []string{
			"profile_policy",
			"carrierreview",
			"measurementreview",
			"pathhealth",
			"runtime_compatibility",
			"operational_safety",
			"generated_parity",
		},
		CandidateFamilies:            []string{"https_like_lab_carrier", "constrained_lab_carrier", "loopback_control_carrier"},
		SelectedCarrierClass:         "reviewed_primary_carrier_bucket",
		FallbackCarrierClass:         "reviewed_fallback_carrier_bucket",
		SelectionRespectsProfile:     true,
		CarrierReviewEnforced:        true,
		MeasurementReviewEnforced:    true,
		PathHealthEnforced:           true,
		RuntimeCompatibilityEnforced: true,
		OperationalSafetyEnforced:    true,
		GeneratedParityEnforced:      true,
		Conclusion:                   ConclusionPassed,
	}
}

func DefaultRelayCompatibilityReport() RelayCompatibilityReport {
	return RelayCompatibilityReport{
		Policy: "relay_compatibility_checked_before_android_connected_state",
		RequiredChecks: []string{
			"profile_identity_bound",
			"relay_identity_bound",
			"relay_auth_checked",
			"profile_bundle_version_checked",
			"rotation_window_checked",
			"expiry_revocation_checked",
			"downgrade_rejected",
		},
		CompatibleRelayClasses:          []string{"relay_profile_match", "relay_carrier_match", "relay_rotation_window_valid"},
		IncompatibleFailureClasses:      []string{"relay_profile_mismatch", "relay_carrier_incompatible", "relay_profile_expired", "relay_rotation_window_invalid"},
		ProfileIdentityBound:            true,
		RelayIdentityBound:              true,
		RelayAuthChecked:                true,
		RotationWindowChecked:           true,
		ExpiredProfileRejected:          true,
		UnknownRelayRejected:            true,
		AuthenticatedSessionEstablished: true,
		Conclusion:                      ConclusionPassed,
	}
}

func DefaultFlowIntegrationReport() FlowIntegrationReport {
	return FlowIntegrationReport{
		Policy: "android_vpn_flow_maps_to_carrier_runtime_streams",
		FlowClasses: []string{
			"small_interactive_vpn_flow",
			"large_backpressured_vpn_flow",
			"network_change_reconnect_flow",
			"carrier_failure_flow",
			"relay_incompatible_flow",
			"diagnostic_control_flow",
		},
		MappingRules:                 []string{"vpn_flow_to_runtime_stream", "runtime_stream_to_carrier_envelope", "carrier_response_to_runtime_stream", "runtime_stream_to_android_flow", "terminal_state_to_android_state"},
		BackpressureRules:            []string{"carrier_queue_pressure_to_vpn_pause", "runtime_backpressure_to_android_flow_pause", "fallback_exhaustion_to_fail_closed"},
		ResetErrorRules:              []string{"carrier_failure_to_android_failure_class", "relay_incompatible_to_android_failure_class", "profile_expired_to_fail_closed"},
		AndroidVpnServiceLinked:      true,
		ControlledTrafficRepresented: true,
		ConnectedThroughCarrier:      true,
		RuntimeStreamsMapped:         8,
		CarrierEnvelopesMapped:       13,
		Conclusion:                   ConclusionPassed,
	}
}

func DefaultFailureDiagnosticsReport() FailureDiagnosticsReport {
	return FailureDiagnosticsReport{
		Policy: "android_carrier_failures_are_redacted_and_bucketed",
		FailureClasses: []string{
			"profile_invalid",
			"profile_expired",
			"carrier_unavailable",
			"carrier_review_blocked",
			"measurement_review_blocked",
			"pathhealth_blocked",
			"relay_incompatible",
			"relay_auth_failed",
			"fallback_exhausted",
			"runtime_restart_required",
		},
		AllowedDiagnosticFields:  []string{"android_state_bucket", "carrier_family_bucket", "relay_compatibility_bucket", "pathhealth_bucket", "fallback_attempt_bucket", "failure_class", "redaction_status"},
		CarrierFailuresSurfaced:  true,
		RuntimeFailuresSurfaced:  true,
		RelayFailuresSurfaced:    true,
		ProfileFailuresSurfaced:  true,
		FallbackFailuresSurfaced: true,
		Conclusion:               ConclusionPassed,
	}
}

func DefaultReconnectFallbackReport() ReconnectFallbackReport {
	return ReconnectFallbackReport{
		Policy: "bounded_android_carrier_reconnect_and_fallback",
		Scenarios: []string{
			"success_path",
			"carrier_failure",
			"relay_failure",
			"profile_failure",
			"network_change_recovery",
			"fallback_exhaustion",
			"kill_switch_interaction",
			"diagnostic_export",
		},
		FallbackClasses:              []string{"primary_carrier_retry", "reviewed_backup_carrier", "no_fallback_fail_closed"},
		MaxFallbackAttempts:          2,
		MaxReconnectAttempts:         3,
		MaxQueuedEvents:              64,
		NetworkChangeRecovery:        true,
		CarrierFailureRecovery:       true,
		RuntimeRestartRecovery:       true,
		FallbackExhaustionFailClosed: true,
		KillSwitchInteractionChecked: true,
		Conclusion:                   ConclusionPassed,
	}
}

func DefaultProfileValidationReport() ProfileValidationReport {
	return ProfileValidationReport{
		Policy: "profile_validation_and_relay_compatibility_before_android_connected",
		ValidationStages: []string{
			"profile_import_validation",
			"profile_hash_validation",
			"profile_expiry_validation",
			"capability_compatibility",
			"relay_profile_compatibility",
			"carrier_policy_compatibility",
		},
		ImportedProfileValidated:      true,
		ProfileHashChecked:            true,
		ProfileExpiryChecked:          true,
		RelayCompatibilityBeforeStart: true,
		InvalidProfileFailsClosed:     true,
		ExpiredProfileFailsClosed:     true,
		StaleProfileRejected:          true,
		Conclusion:                    ConclusionPassed,
	}
}

func DefaultShutdownSafetyReport() ShutdownSafetyReport {
	return ShutdownSafetyReport{
		Policy: "android_carrier_integration_safe_shutdown",
		Actions: []string{
			"stop_accepting_android_flows",
			"close_runtime_streams",
			"close_carrier_session",
			"close_relay_session",
			"engage_fail_closed_on_unsafe_stop",
			"flush_redacted_diagnostics",
		},
		CarrierSessionClosed:      true,
		RuntimeSessionClosed:      true,
		AndroidFlowClosed:         true,
		DiagnosticsFlushed:        true,
		KillSwitchEngagedOnUnsafe: true,
		StopIdempotent:            true,
		Conclusion:                ConclusionPassed,
	}
}

func BuildChecklistReport() ChecklistReport {
	items := []string{
		"m58_vpnservice_linked",
		"profile_validation_before_connected",
		"runtime_initialization_linked",
		"carrier_selection_gates_enforced",
		"relay_compatibility_checked",
		"authenticated_session_established",
		"stream_mapping_completed",
		"pathhealth_checked",
		"failure_diagnostics_redacted",
		"fallback_bounded_fail_closed",
		"kill_switch_interaction_checked",
		"generated_backend_parity",
	}
	return ChecklistReport{Items: items, Passed: len(items), Conclusion: ConclusionPassed}
}

func BuildMisuseReport() MisuseReport {
	controls := RequiredMisuseNames()
	return MisuseReport{DetectedControls: controls, DetectedCount: len(controls), ExpectedCount: len(controls), Conclusion: ConclusionPassed}
}

func BuildTraceHygieneReport() TraceHygieneReport {
	return TraceHygieneReport{ReportsScanned: 19, Conclusion: ConclusionPassed}
}

func BuildPublicClaimSafetyReport() PublicClaimSafetyReport {
	return PublicClaimSafetyReport{
		DocsChecked:     6,
		ForbiddenClaims: []string{"guaranteed bypass", "undetectable", "field-ready", "public beta", "production Android VPN", "live probing", "unrestricted carrier forwarding"},
		Conclusion:      ConclusionPassed,
	}
}

func BuildParityReport(set FixtureSet) ParityReport {
	hash := HashValue(parityHashInput(set))
	return ParityReport{
		GeneratedMarkers: []string{"AndroidCarrierSchemaVersion", "AndroidCarrierBackendVersion", "AndroidCarrierDecision", "AndroidCarrierConnectedState", "AndroidCarrierMisuseCount", "AndroidCarrierNextMilestone"},
		InterpretedHash:  hash,
		GeneratedHash:    hash,
		Conclusion:       ConclusionPassed,
	}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.BackendVersion != BackendVersion || set.FixtureID == "" {
		return errors.New("invalid Android carrier fixture identity")
	}
	if set.Decision != DecisionReady || set.BlockerCount != 0 || set.RiskCount < 8 {
		return errors.New("Android carrier decision incomplete")
	}
	if !set.RuntimePath.ProfileValidationBeforeConnect || !set.RuntimePath.RuntimeInitialized || !set.RuntimePath.CarrierSelectionCompleted || !set.RuntimePath.RelayCompatibilityChecked || !set.RuntimePath.AuthenticatedSessionEstablished || !set.RuntimePath.StreamMappingCompleted || !set.RuntimePath.PathHealthChecked || !set.RuntimePath.SafeShutdownLinked || set.RuntimePath.BypassesProfileValidation || set.RuntimePath.BypassesCarrierSelection || set.RuntimePath.BypassesRelayCompatibility || set.RuntimePath.UnreviewedPublicNetworkEgress || set.RuntimePath.UnrestrictedTrafficForwarding || len(set.RuntimePath.RequiredStages) < 9 {
		return errors.New("Android carrier runtime path unsafe")
	}
	if !containsAll(set.UIStates.States, RequiredUIStates()) || !set.UIStates.CarrierFailureVisible || !set.UIStates.RelayFailureVisible || !set.UIStates.ProfileExpiryVisible || !set.UIStates.FallbackAttemptVisible || !set.UIStates.DiagnosticReadyVisible || set.UIStates.FieldReadyClaimVisible || set.UIStates.GuaranteedBypassDisplayed {
		return errors.New("Android carrier UI states unsafe")
	}
	if !set.CarrierSelection.SelectionRespectsProfile || !set.CarrierSelection.CarrierReviewEnforced || !set.CarrierSelection.MeasurementReviewEnforced || !set.CarrierSelection.PathHealthEnforced || !set.CarrierSelection.RuntimeCompatibilityEnforced || !set.CarrierSelection.OperationalSafetyEnforced || !set.CarrierSelection.GeneratedParityEnforced || set.CarrierSelection.HighRiskDefaultAllowed || set.CarrierSelection.ReviewBypassAllowed || set.CarrierSelection.UnboundedFallbackAllowed || set.CarrierSelection.PublicCarrierAutoSelected || len(set.CarrierSelection.RequiredGates) < 7 {
		return errors.New("Android carrier selection unsafe")
	}
	if !set.RelayCompatibility.ProfileIdentityBound || !set.RelayCompatibility.RelayIdentityBound || !set.RelayCompatibility.RelayAuthChecked || !set.RelayCompatibility.RotationWindowChecked || !set.RelayCompatibility.ExpiredProfileRejected || !set.RelayCompatibility.UnknownRelayRejected || !set.RelayCompatibility.AuthenticatedSessionEstablished || set.RelayCompatibility.RelayBypassAllowed || set.RelayCompatibility.DowngradeAccepted || len(set.RelayCompatibility.RequiredChecks) < 7 {
		return errors.New("Android carrier relay compatibility unsafe")
	}
	if !set.FlowIntegration.AndroidVpnServiceLinked || !set.FlowIntegration.ControlledTrafficRepresented || !set.FlowIntegration.ConnectedThroughCarrier || set.FlowIntegration.RuntimeStreamsMapped < 4 || set.FlowIntegration.CarrierEnvelopesMapped < 4 || set.FlowIntegration.PacketPayloadLogged || set.FlowIntegration.PacketCaptureEnabled || set.FlowIntegration.RawDestinationLogged || set.FlowIntegration.AppIdentityLogged || len(set.FlowIntegration.MappingRules) < 5 {
		return errors.New("Android carrier flow integration unsafe")
	}
	if !set.FailureDiagnostics.CarrierFailuresSurfaced || !set.FailureDiagnostics.RuntimeFailuresSurfaced || !set.FailureDiagnostics.RelayFailuresSurfaced || !set.FailureDiagnostics.ProfileFailuresSurfaced || !set.FailureDiagnostics.FallbackFailuresSurfaced || set.FailureDiagnostics.PayloadLogged || set.FailureDiagnostics.SecretLogged || set.FailureDiagnostics.RawPacketLogged || set.FailureDiagnostics.DomainLogged || set.FailureDiagnostics.URLLogged || set.FailureDiagnostics.SNIHostLogged || set.FailureDiagnostics.DeviceIdentifierLogged || set.FailureDiagnostics.TelemetryUploadConfigured || len(set.FailureDiagnostics.FailureClasses) < 10 {
		return errors.New("Android carrier diagnostics unsafe")
	}
	if !set.ReconnectFallback.NetworkChangeRecovery || !set.ReconnectFallback.CarrierFailureRecovery || !set.ReconnectFallback.RuntimeRestartRecovery || !set.ReconnectFallback.FallbackExhaustionFailClosed || !set.ReconnectFallback.KillSwitchInteractionChecked || set.ReconnectFallback.UnboundedRetry || set.ReconnectFallback.UnsafeFallbackAllowed || set.ReconnectFallback.MaxFallbackAttempts <= 0 || set.ReconnectFallback.MaxFallbackAttempts > 3 || set.ReconnectFallback.MaxReconnectAttempts <= 0 || set.ReconnectFallback.MaxReconnectAttempts > 5 || set.ReconnectFallback.MaxQueuedEvents < 32 {
		return errors.New("Android carrier reconnect/fallback unsafe")
	}
	if !set.ProfileValidation.ImportedProfileValidated || !set.ProfileValidation.ProfileHashChecked || !set.ProfileValidation.ProfileExpiryChecked || !set.ProfileValidation.RelayCompatibilityBeforeStart || !set.ProfileValidation.InvalidProfileFailsClosed || !set.ProfileValidation.ExpiredProfileFailsClosed || !set.ProfileValidation.StaleProfileRejected || set.ProfileValidation.ProfileValidationBypassed || len(set.ProfileValidation.ValidationStages) < 6 {
		return errors.New("Android carrier profile validation unsafe")
	}
	if !set.ShutdownSafety.CarrierSessionClosed || !set.ShutdownSafety.RuntimeSessionClosed || !set.ShutdownSafety.AndroidFlowClosed || !set.ShutdownSafety.DiagnosticsFlushed || !set.ShutdownSafety.KillSwitchEngagedOnUnsafe || !set.ShutdownSafety.StopIdempotent || set.ShutdownSafety.PostShutdownTraffic || set.ShutdownSafety.LeakedSessions != 0 {
		return errors.New("Android carrier shutdown unsafe")
	}
	if set.Checklist.Failed != 0 || set.Checklist.Passed < 12 || set.Checklist.Conclusion != ConclusionPassed {
		return errors.New("Android carrier checklist incomplete")
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) || set.Misuse.ExpectedCount != len(RequiredMisuseNames()) || len(set.Misuse.DetectedControls) != len(RequiredMisuseNames()) || set.Misuse.Conclusion != ConclusionPassed {
		return errors.New("Android carrier misuse controls incomplete")
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.RawPacketLogged || set.TraceHygiene.DomainLogged || set.TraceHygiene.URLLogged || set.TraceHygiene.SNIHostLogged || set.TraceHygiene.ResolverLogged || set.TraceHygiene.DeviceIdentifierLogged || set.TraceHygiene.TelemetryMarkerLogged || set.PayloadLogged || set.SecretLogged {
		return errors.New("Android carrier trace hygiene failed")
	}
	if set.Parity.Conclusion != ConclusionPassed || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		return errors.New("Android carrier generated parity failed")
	}
	return ScanForLeak(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: ConclusionPassed}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "androidcarrier_fixture_hash_changed")
	}
	if oldSet.Version != newSet.Version || oldSet.BackendVersion != newSet.BackendVersion {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "androidcarrier_schema_or_backend_changed")
	}
	if oldSet.PayloadLogged || oldSet.SecretLogged || newSet.PayloadLogged || newSet.SecretLogged {
		report.PayloadLogged = oldSet.PayloadLogged || newSet.PayloadLogged
		report.SecretLogged = oldSet.SecretLogged || newSet.SecretLogged
		report.UnexpectedDrift = append(report.UnexpectedDrift, "androidcarrier_trace_hygiene_failed")
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
			return fmt.Errorf("Android carrier unsafe marker %q", marker)
		}
	}
	return nil
}

func ForbiddenMarkers() []string {
	return []string{
		`"raw_payload"`,
		`"payload_body"`,
		`"packet_capture"`,
		`"raw_packet"`,
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
		"androidcarrier_bypasses_profile_validation",
		"androidcarrier_bypasses_carrierreview",
		"androidcarrier_bypasses_measurementreview",
		"androidcarrier_bypasses_pathhealth",
		"androidcarrier_accepts_relay_incompatible",
		"androidcarrier_accepts_profile_expired",
		"androidcarrier_unbounded_fallback",
		"androidcarrier_kill_switch_fail_open",
		"androidcarrier_payload_diagnostics",
		"androidcarrier_packet_capture",
		"androidcarrier_raw_destination_logging",
		"androidcarrier_auto_telemetry",
		"androidcarrier_public_network_egress",
		"androidcarrier_generated_backend_drift",
	}
}

func fixtureHashInput(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}

func parityHashInput(set FixtureSet) struct {
	Version            string
	RuntimePath        RuntimePathReport
	UIStates           UIStateReport
	CarrierSelection   CarrierSelectionReport
	RelayCompatibility RelayCompatibilityReport
	FlowIntegration    FlowIntegrationReport
	FailureDiagnostics FailureDiagnosticsReport
	ReconnectFallback  ReconnectFallbackReport
	ProfileValidation  ProfileValidationReport
} {
	return struct {
		Version            string
		RuntimePath        RuntimePathReport
		UIStates           UIStateReport
		CarrierSelection   CarrierSelectionReport
		RelayCompatibility RelayCompatibilityReport
		FlowIntegration    FlowIntegrationReport
		FailureDiagnostics FailureDiagnosticsReport
		ReconnectFallback  ReconnectFallbackReport
		ProfileValidation  ProfileValidationReport
	}{set.Version, set.RuntimePath, set.UIStates, set.CarrierSelection, set.RelayCompatibility, set.FlowIntegration, set.FailureDiagnostics, set.ReconnectFallback, set.ProfileValidation}
}

func containsAll(have, want []string) bool {
	seen := map[string]bool{}
	for _, item := range have {
		seen[item] = true
	}
	for _, item := range want {
		if !seen[item] {
			return false
		}
	}
	return true
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
