// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localpipeline

const (
	Version                   = "localpipeline-v1"
	RecommendedNextMilestone  = "M35: production integration readiness review"
	DefaultPipelineSchemaName = "local-proxy-pipeline"
)

type ScenarioKind string
type PipelineState string

const (
	ScenarioSingleFlowEcho        ScenarioKind = "pipeline_single_flow_echo"
	ScenarioManySmallRequests     ScenarioKind = "pipeline_many_small_requests"
	ScenarioLargeBackpressure     ScenarioKind = "pipeline_large_backpressure"
	ScenarioSlowChunkedResponse   ScenarioKind = "pipeline_slow_chunked_response"
	ScenarioResetIsolation        ScenarioKind = "pipeline_reset_isolation"
	ScenarioTargetErrorIsolation  ScenarioKind = "pipeline_target_error_isolation"
	ScenarioBridgeBackpressure    ScenarioKind = "pipeline_bridge_backpressure"
	ScenarioPathFailover          ScenarioKind = "pipeline_path_failover"
	ScenarioDescriptorRejection   ScenarioKind = "pipeline_descriptor_rejection"
	ScenarioMixedSyntheticTargets ScenarioKind = "pipeline_mixed_synthetic_targets"
	ScenarioCollapsedControl      ScenarioKind = "pipeline_collapsed_control"
	ScenarioLeakControl           ScenarioKind = "pipeline_leak_control"
)

const (
	StateCreated      PipelineState = "created"
	StateIngressBound PipelineState = "ingress_bound"
	StateEgressBound  PipelineState = "egress_bound"
	StateBridgeOpen   PipelineState = "bridge_open"
	StateRunning      PipelineState = "running"
	StateDraining     PipelineState = "draining"
	StateCompleted    PipelineState = "completed"
	StateReset        PipelineState = "reset"
	StateFailed       PipelineState = "failed"
	StateRejected     PipelineState = "rejected"
)

type PipelineScenario struct {
	ScenarioID             string        `json:"scenario_id"`
	Kind                   ScenarioKind  `json:"kind"`
	IngressClass           string        `json:"ingress_class"`
	EgressClass            string        `json:"egress_class"`
	BridgeClass            string        `json:"bridge_class"`
	RuntimeClass           string        `json:"runtime_class"`
	CarrierClass           string        `json:"carrier_class"`
	ExpectedFinalState     PipelineState `json:"expected_final_state"`
	ExpectedFlows          int           `json:"expected_flows"`
	ExpectedRuntimeStreams int           `json:"expected_runtime_streams"`
	ExpectedBackpressure   int           `json:"expected_backpressure"`
	ExpectedErrors         int           `json:"expected_errors"`
	ExpectedResets         int           `json:"expected_resets"`
	Control                bool          `json:"control"`
	PayloadLogged          bool          `json:"payload_logged"`
	SecretLogged           bool          `json:"secret_logged"`
}

type PipelineRunSummary struct {
	Version              string        `json:"version"`
	ScenarioID           string        `json:"scenario_id"`
	Kind                 ScenarioKind  `json:"kind"`
	FinalState           PipelineState `json:"final_state"`
	IngressRequests      int           `json:"ingress_requests"`
	EgressRequests       int           `json:"egress_requests"`
	BridgeSessions       int           `json:"bridge_sessions"`
	BridgeStreams        int           `json:"bridge_streams"`
	RuntimeStreams       int           `json:"runtime_streams"`
	CarrierEnvelopes     int           `json:"carrier_envelopes"`
	ByteFrames           int           `json:"byte_frames"`
	SinkCompletions      int           `json:"sink_completions"`
	BackpressureEvents   int           `json:"backpressure_events"`
	TargetErrors         int           `json:"target_errors"`
	TargetResets         int           `json:"target_resets"`
	DescriptorRejections int           `json:"descriptor_rejections"`
	FailoverDecisions    int           `json:"failover_decisions"`
	PayloadLogged        bool          `json:"payload_logged"`
	SecretLogged         bool          `json:"secret_logged"`
	RunHash              string        `json:"run_hash"`
	Conclusion           string        `json:"conclusion"`
}

type PipelineBoundaryReport struct {
	Version            string `json:"version"`
	ScenariosChecked   int    `json:"scenarios_checked"`
	IngressBound       bool   `json:"ingress_bound"`
	EgressBound        bool   `json:"egress_bound"`
	BridgeBound        bool   `json:"bridge_bound"`
	RuntimeBound       bool   `json:"runtime_bound"`
	CarrierBound       bool   `json:"carrier_bound"`
	ByteTransportBound bool   `json:"byte_transport_bound"`
	AdaptiveBound      bool   `json:"adaptive_bound"`
	PayloadLogged      bool   `json:"payload_logged"`
	SecretLogged       bool   `json:"secret_logged"`
	Conclusion         string `json:"conclusion"`
}

type PipelineMisuseReport struct {
	Version           string   `json:"version"`
	ObjectsScanned    int      `json:"objects_scanned"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	PayloadLogged     bool     `json:"payload_logged"`
	SecretLogged      bool     `json:"secret_logged"`
	Conclusion        string   `json:"conclusion"`
}

type PipelineParityReport struct {
	Version               string   `json:"version"`
	ComparedScenarios     int      `json:"compared_scenarios"`
	MatchingSummaries     int      `json:"matching_summaries"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type PipelineCollapseReport struct {
	Version           string   `json:"version"`
	ScenarioCount     int      `json:"scenario_count"`
	UniqueRunHashes   int      `json:"unique_run_hashes"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	DiversityScore    float64  `json:"diversity_score"`
	Conclusion        string   `json:"conclusion"`
}

type PipelineFixtureSet struct {
	Version       string                 `json:"version"`
	GeneratedAt   string                 `json:"generated_at"`
	SchemaName    string                 `json:"schema_name"`
	Scenarios     []PipelineScenario     `json:"scenarios"`
	Runs          []PipelineRunSummary   `json:"runs"`
	Boundary      PipelineBoundaryReport `json:"boundary"`
	Collapse      PipelineCollapseReport `json:"collapse"`
	Misuse        PipelineMisuseReport   `json:"misuse"`
	Parity        PipelineParityReport   `json:"parity"`
	PayloadLogged bool                   `json:"payload_logged"`
	SecretLogged  bool                   `json:"secret_logged"`
	FixtureHash   string                 `json:"fixture_hash"`
	Conclusion    string                 `json:"conclusion"`
}

type PipelineComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}
