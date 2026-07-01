// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

import "kurdistan/internal/proxyegress"

const (
	Version                  = "relaybridge-v1"
	RecommendedNextMilestone = "M34: end-to-end local proxy pipeline"
)

type RelayBridgeVersion string
type RelayBridgeID string
type RelayBridgeSessionID string
type RelayBridgeState string

const (
	BridgeStateCreated       RelayBridgeState = "created"
	BridgeStateBound         RelayBridgeState = "bound"
	BridgeStateOpen          RelayBridgeState = "open"
	BridgeStateDraining      RelayBridgeState = "draining"
	BridgeStateBackpressured RelayBridgeState = "backpressured"
	BridgeStateFailed        RelayBridgeState = "failed"
	BridgeStateReset         RelayBridgeState = "reset"
	BridgeStateClosed        RelayBridgeState = "closed"
)

type RelayBridgeSession struct {
	BridgeID          string           `json:"bridge_id"`
	SessionID         string           `json:"session_id"`
	BundleID          string           `json:"bundle_id"`
	CandidateID       string           `json:"candidate_id"`
	ActivePathID      string           `json:"active_path_id"`
	RelayID           string           `json:"relay_id"`
	SyntheticHostID   string           `json:"synthetic_host_id"`
	StreamPolicyClass string           `json:"stream_policy_class"`
	BackpressureClass string           `json:"backpressure_class"`
	IsolationClass    string           `json:"isolation_class"`
	CurrentState      RelayBridgeState `json:"current_state"`
	PayloadLogged     bool             `json:"payload_logged"`
	SecretLogged      bool             `json:"secret_logged"`
	SessionHash       string           `json:"session_hash"`
}

type RelayBridgeStream struct {
	StreamID         string `json:"stream_id"`
	BridgeID         string `json:"bridge_id"`
	IngressRequestID string `json:"ingress_request_id"`
	EgressRequestID  string `json:"egress_request_id"`
	TargetID         string `json:"target_id"`
	StreamClass      string `json:"stream_class"`
	WindowClass      string `json:"window_class"`
	SchedulerClass   string `json:"scheduler_class"`
	ResetPolicyClass string `json:"reset_policy_class"`
	ErrorPolicyClass string `json:"error_policy_class"`
	PayloadLogged    bool   `json:"payload_logged"`
	SecretLogged     bool   `json:"secret_logged"`
	StreamHash       string `json:"stream_hash"`
}

type RelayBridgeScenario struct {
	ScenarioID               string                        `json:"scenario_id"`
	IngressRequestClass      string                        `json:"ingress_request_class"`
	EgressTargetClass        proxyegress.EgressTargetClass `json:"egress_target_class"`
	BridgeSessionClass       string                        `json:"bridge_session_class"`
	AdaptiveBindingClass     string                        `json:"adaptive_binding_class"`
	ExpectedFinalBridgeState RelayBridgeState              `json:"expected_final_bridge_state"`
	ExpectedCompleted        int                           `json:"expected_completed"`
	ExpectedReset            int                           `json:"expected_reset"`
	ExpectedFailed           int                           `json:"expected_failed"`
	ExpectedBackpressure     int                           `json:"expected_backpressure"`
	ExpectedTraceHygiene     string                        `json:"expected_trace_hygiene"`
	Control                  bool                          `json:"control"`
	PayloadLogged            bool                          `json:"payload_logged"`
	SecretLogged             bool                          `json:"secret_logged"`
}

type RelayBridgeReport struct {
	Version             string   `json:"version"`
	BridgeID            string   `json:"bridge_id"`
	SessionCount        int      `json:"session_count"`
	StreamCount         int      `json:"stream_count"`
	MappedRequests      int      `json:"mapped_requests"`
	CompletedRequests   int      `json:"completed_requests"`
	ResetRequests       int      `json:"reset_requests"`
	FailedRequests      int      `json:"failed_requests"`
	BackpressureEvents  int      `json:"backpressure_events"`
	IsolationViolations int      `json:"isolation_violations"`
	SafeErrorClasses    []string `json:"safe_error_classes,omitempty"`
	PayloadLogged       bool     `json:"payload_logged"`
	SecretLogged        bool     `json:"secret_logged"`
	ReportHash          string   `json:"report_hash"`
	Conclusion          string   `json:"conclusion"`
}

type RelayBridgeAdaptiveBindingReport struct {
	Version                string `json:"version"`
	BindingsChecked        int    `json:"bindings_checked"`
	BundleBound            bool   `json:"bundle_bound"`
	RaceBound              bool   `json:"race_bound"`
	HealthBound            bool   `json:"health_bound"`
	CarrierReviewBound     bool   `json:"carrier_review_bound"`
	MeasurementReviewBound bool   `json:"measurement_review_bound"`
	HighRiskBlocked        int    `json:"high_risk_blocked"`
	ExperimentalBlocked    int    `json:"experimental_blocked"`
	FailedHealthBlocked    int    `json:"failed_health_blocked"`
	Conclusion             string `json:"conclusion"`
}

type RelayBridgeMisuseReport struct {
	Version           string   `json:"version"`
	ObjectsScanned    int      `json:"objects_scanned"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	PayloadLogged     bool     `json:"payload_logged"`
	SecretLogged      bool     `json:"secret_logged"`
	Conclusion        string   `json:"conclusion"`
}

type RelayBridgeParityReport struct {
	Version               string   `json:"version"`
	ComparedScenarios     int      `json:"compared_scenarios"`
	MatchingSessions      int      `json:"matching_sessions"`
	MatchingStreams       int      `json:"matching_streams"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type RelayBridgeFixtureSet struct {
	Version       string                           `json:"version"`
	GeneratedAt   string                           `json:"generated_at"`
	Scenarios     []RelayBridgeScenario            `json:"scenarios"`
	Sessions      []RelayBridgeSession             `json:"sessions"`
	Streams       []RelayBridgeStream              `json:"streams"`
	Reports       []RelayBridgeReport              `json:"reports"`
	Adaptive      RelayBridgeAdaptiveBindingReport `json:"adaptive_binding"`
	Misuse        RelayBridgeMisuseReport          `json:"misuse"`
	Parity        RelayBridgeParityReport          `json:"parity"`
	PayloadLogged bool                             `json:"payload_logged"`
	SecretLogged  bool                             `json:"secret_logged"`
	FixtureHash   string                           `json:"fixture_hash"`
	Conclusion    string                           `json:"conclusion"`
}

type RelayBridgeComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}
