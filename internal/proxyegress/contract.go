// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyegress

const (
	Version                  = "proxyegress-v1"
	RecommendedNextMilestone = "M34: end-to-end local proxy pipeline"
)

type ProxyEgressVersion string
type EgressRequestID string
type EgressTargetID string
type EgressMappingID string
type EgressTargetClass string
type EgressLifecycleState string

const (
	EgressTargetEchoSynthetic      EgressTargetClass = "echo_synthetic"
	EgressTargetFixedResponse      EgressTargetClass = "fixed_response"
	EgressTargetChunkedResponse    EgressTargetClass = "chunked_response"
	EgressTargetSlowResponse       EgressTargetClass = "slow_response"
	EgressTargetLargeObject        EgressTargetClass = "large_object"
	EgressTargetResetMidstream     EgressTargetClass = "reset_midstream"
	EgressTargetErrorResponse      EgressTargetClass = "error_response"
	EgressTargetDripResponse       EgressTargetClass = "drip_response"
	EgressTargetBlackholeSynthetic EgressTargetClass = "blackhole_synthetic"
	EgressTargetControlCollapsed   EgressTargetClass = "control_collapsed"
)

const (
	EgressStateCreated       EgressLifecycleState = "created"
	EgressStateMapped        EgressLifecycleState = "mapped"
	EgressStateTargetBound   EgressLifecycleState = "target_bound"
	EgressStateStreaming     EgressLifecycleState = "streaming"
	EgressStateBackpressured EgressLifecycleState = "backpressured"
	EgressStateCompleted     EgressLifecycleState = "completed"
	EgressStateReset         EgressLifecycleState = "reset"
	EgressStateFailed        EgressLifecycleState = "failed"
	EgressStateQuarantined   EgressLifecycleState = "quarantined"
)

type EgressRequestDescriptor struct {
	RequestID         string            `json:"request_id"`
	IngressRequestID  string            `json:"ingress_request_id"`
	StreamID          string            `json:"stream_id"`
	CandidateID       string            `json:"candidate_id"`
	BundleID          string            `json:"bundle_id"`
	ActivePathID      string            `json:"active_path_id"`
	TargetClass       EgressTargetClass `json:"target_class"`
	RequestClass      string            `json:"request_class"`
	ResponseClass     string            `json:"response_class"`
	BackpressureClass string            `json:"backpressure_class"`
	ErrorPolicyClass  string            `json:"error_policy_class"`
	ResetPolicyClass  string            `json:"reset_policy_class"`
	PayloadLogged     bool              `json:"payload_logged"`
	SecretLogged      bool              `json:"secret_logged"`
	DescriptorHash    string            `json:"descriptor_hash"`
}

type EgressTargetDescriptor struct {
	TargetID           string            `json:"target_id"`
	TargetClass        EgressTargetClass `json:"target_class"`
	ResponsePlanClass  string            `json:"response_plan_class"`
	ChunkPlanClass     string            `json:"chunk_plan_class"`
	LatencyBucket      string            `json:"latency_bucket"`
	FailureBucket      string            `json:"failure_bucket"`
	ResetBucket        string            `json:"reset_bucket"`
	BackpressureBucket string            `json:"backpressure_bucket"`
	PayloadLogged      bool              `json:"payload_logged"`
	SecretLogged       bool              `json:"secret_logged"`
	TargetHash         string            `json:"target_hash"`
}

type EgressMappingPlan struct {
	MappingID      string `json:"mapping_id"`
	RequestID      string `json:"request_id"`
	TargetID       string `json:"target_id"`
	RelayBridgeID  string `json:"relay_bridge_id"`
	StreamID       string `json:"stream_id"`
	CandidateID    string `json:"candidate_id"`
	BundleID       string `json:"bundle_id"`
	ActivePathID   string `json:"active_path_id"`
	MappingClass   string `json:"mapping_class"`
	IsolationClass string `json:"isolation_class"`
	MappingHash    string `json:"mapping_hash"`
	PayloadLogged  bool   `json:"payload_logged"`
	SecretLogged   bool   `json:"secret_logged"`
}

type EgressAdaptiveBindingReport struct {
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
	SafeBindings           int    `json:"safe_bindings"`
	PayloadLogged          bool   `json:"payload_logged"`
	SecretLogged           bool   `json:"secret_logged"`
	Conclusion             string `json:"conclusion"`
}

type IngressEgressMappingReport struct {
	Version                 string `json:"version"`
	IngressRequestsChecked  int    `json:"ingress_requests_checked"`
	EgressRequestsCreated   int    `json:"egress_requests_created"`
	StreamsMapped           int    `json:"streams_mapped"`
	DescriptorAbuseRejected int    `json:"descriptor_abuse_rejected"`
	BackpressurePreserved   bool   `json:"backpressure_preserved"`
	ResetMappingPreserved   bool   `json:"reset_mapping_preserved"`
	ErrorMappingPreserved   bool   `json:"error_mapping_preserved"`
	IsolationPreserved      bool   `json:"isolation_preserved"`
	PayloadLogged           bool   `json:"payload_logged"`
	SecretLogged            bool   `json:"secret_logged"`
	Conclusion              string `json:"conclusion"`
}

type EgressLifecycleScenario struct {
	ScenarioID           string               `json:"scenario_id"`
	TargetClass          EgressTargetClass    `json:"target_class"`
	ExpectedFinalState   EgressLifecycleState `json:"expected_final_state"`
	ExpectedResponse     string               `json:"expected_response"`
	ExpectedBackpressure int                  `json:"expected_backpressure"`
	ExpectedReset        int                  `json:"expected_reset"`
	ExpectedError        int                  `json:"expected_error"`
	Control              bool                 `json:"control"`
	PayloadLogged        bool                 `json:"payload_logged"`
	SecretLogged         bool                 `json:"secret_logged"`
}

type EgressLifecycleReport struct {
	Version            string               `json:"version"`
	ScenarioID         string               `json:"scenario_id"`
	RequestID          string               `json:"request_id"`
	TargetID           string               `json:"target_id"`
	MappingID          string               `json:"mapping_id"`
	FinalState         EgressLifecycleState `json:"final_state"`
	CompletedRequests  int                  `json:"completed_requests"`
	ResetRequests      int                  `json:"reset_requests"`
	FailedRequests     int                  `json:"failed_requests"`
	BackpressureEvents int                  `json:"backpressure_events"`
	LogicalTicks       int                  `json:"logical_ticks"`
	PayloadLogged      bool                 `json:"payload_logged"`
	SecretLogged       bool                 `json:"secret_logged"`
	ReportHash         string               `json:"report_hash"`
	Conclusion         string               `json:"conclusion"`
}

type EgressBackpressureReport struct {
	Version            string `json:"version"`
	ScenarioID         string `json:"scenario_id"`
	StreamsChecked     int    `json:"streams_checked"`
	PressureEvents     int    `json:"pressure_events"`
	PauseEvents        int    `json:"pause_events"`
	ResumeEvents       int    `json:"resume_events"`
	WindowBucket       string `json:"window_bucket"`
	PressureBucket     string `json:"pressure_bucket"`
	IsolationPreserved bool   `json:"isolation_preserved"`
	PayloadLogged      bool   `json:"payload_logged"`
	SecretLogged       bool   `json:"secret_logged"`
	Conclusion         string `json:"conclusion"`
}

type EgressResetErrorReport struct {
	Version          string   `json:"version"`
	ScenarioID       string   `json:"scenario_id"`
	StreamsChecked   int      `json:"streams_checked"`
	ResetEvents      int      `json:"reset_events"`
	ErrorEvents      int      `json:"error_events"`
	IsolatedResets   int      `json:"isolated_resets"`
	CrossStreamLeaks int      `json:"cross_stream_leaks"`
	SafeErrorClasses []string `json:"safe_error_classes"`
	PayloadLogged    bool     `json:"payload_logged"`
	SecretLogged     bool     `json:"secret_logged"`
	Conclusion       string   `json:"conclusion"`
}

type EgressMisuseReport struct {
	Version           string   `json:"version"`
	ObjectsScanned    int      `json:"objects_scanned"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	PayloadLogged     bool     `json:"payload_logged"`
	SecretLogged      bool     `json:"secret_logged"`
	Conclusion        string   `json:"conclusion"`
}

type EgressFixtureSet struct {
	Version        string                      `json:"version"`
	GeneratedAt    string                      `json:"generated_at"`
	Scenarios      []EgressLifecycleScenario   `json:"scenarios"`
	Requests       []EgressRequestDescriptor   `json:"requests"`
	Targets        []EgressTargetDescriptor    `json:"targets"`
	Mappings       []EgressMappingPlan         `json:"mappings"`
	Lifecycle      []EgressLifecycleReport     `json:"lifecycle"`
	Backpressure   EgressBackpressureReport    `json:"backpressure"`
	ResetError     EgressResetErrorReport      `json:"reset_error"`
	Adaptive       EgressAdaptiveBindingReport `json:"adaptive_binding"`
	IngressMapping IngressEgressMappingReport  `json:"ingress_mapping"`
	Misuse         EgressMisuseReport          `json:"misuse"`
	Parity         EgressParityReport          `json:"parity"`
	PayloadLogged  bool                        `json:"payload_logged"`
	SecretLogged   bool                        `json:"secret_logged"`
	FixtureHash    string                      `json:"fixture_hash"`
	Conclusion     string                      `json:"conclusion"`
}

type EgressParityReport struct {
	Version               string   `json:"version"`
	ComparedScenarios     int      `json:"compared_scenarios"`
	MatchingLifecycle     int      `json:"matching_lifecycle"`
	MatchingMappings      int      `json:"matching_mappings"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type EgressComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}
