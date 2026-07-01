// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package concretelocaladapter

import "time"

const (
	Version                  = "concretelocaladapter-v1"
	DefaultFixtureID         = "concrete_local_socket_adapter_fixture_v1"
	RecommendedNextMilestone = "M37: concrete local socket adversarial hardening"

	ScenarioSingleFlowEcho       = "socket_single_flow_echo"
	ScenarioManySmallFlows       = "socket_many_small_flows"
	ScenarioLargeBackpressure    = "socket_large_backpressure"
	ScenarioResetIsolation       = "socket_reset_isolation"
	ScenarioTargetErrorMapping   = "socket_target_error_mapping"
	ScenarioTargetResetMapping   = "socket_target_reset_mapping"
	ScenarioLoopbackBindPolicy   = "socket_loopback_bind_policy"
	ScenarioMalformedLocalEvent  = "socket_malformed_local_event"
	ScenarioNoExternalBind       = "socket_no_external_bind_control"
	ScenarioPayloadLeakControl   = "socket_payload_leak_control"

	BindClassLoopbackOnly = "loopback_only"
)

type BindConfig struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	MaxConnections    int    `json:"max_connections"`
	MaxBufferedBytes  int    `json:"max_buffered_bytes"`
	MaxEvents         int    `json:"max_events"`
	TraceEnabled      bool   `json:"trace_enabled"`
	DeterministicSeed uint64 `json:"deterministic_seed"`
}

type SocketScenario struct {
	Name             string   `json:"name"`
	SourceModel      string   `json:"source_model"`
	SinkModel        string   `json:"sink_model"`
	TargetClass      string   `json:"target_class"`
	FlowCount        int      `json:"flow_count"`
	ChunkCount       int      `json:"chunk_count"`
	ByteBudget       int      `json:"byte_budget"`
	ExpectedEvents   []string `json:"expected_events"`
	RequiresLoopback bool     `json:"requires_loopback"`
}

type SocketRunSummary struct {
	Scenario              string `json:"scenario"`
	BindClass             string `json:"bind_class"`
	HostClass             string `json:"host_class"`
	PortClass             string `json:"port_class"`
	FlowsOpened           int    `json:"flows_opened"`
	FlowsClosed           int    `json:"flows_closed"`
	FlowsReset            int    `json:"flows_reset"`
	ConnectionsAccepted   int    `json:"connections_accepted"`
	RuntimeStreamsMapped  int    `json:"runtime_streams_mapped"`
	SourceChunks          int    `json:"source_chunks"`
	SinkChunks            int    `json:"sink_chunks"`
	BytesInBucket         string `json:"bytes_in_bucket"`
	BytesOutBucket        string `json:"bytes_out_bucket"`
	BackpressureEvents    int    `json:"backpressure_events"`
	TargetErrors          int    `json:"target_errors"`
	TargetResets          int    `json:"target_resets"`
	MalformedRejected     int    `json:"malformed_rejected"`
	ExternalBindRejected  int    `json:"external_bind_rejected"`
	TraceEvents           int    `json:"trace_events"`
	PayloadLogged         bool   `json:"payload_logged"`
	SecretLogged          bool   `json:"secret_logged"`
	Completed             bool   `json:"completed"`
	SummaryHash           string `json:"summary_hash"`
}

type SocketFixtureSet struct {
	Version                  string             `json:"version"`
	FixtureID                string             `json:"fixture_id"`
	GeneratedAt              string             `json:"generated_at"`
	GeneratedAtUnix          int64              `json:"generated_at_unix"`
	BackendVersion           string             `json:"backend_version"`
	RecommendedNextMilestone string             `json:"recommended_next_milestone"`
	BindConfig               BindConfig         `json:"bind_config"`
	Scenarios                []SocketScenario   `json:"scenarios"`
	Summaries                []SocketRunSummary `json:"summaries"`
	Comparison               SocketComparison   `json:"comparison"`
	Misuse                   SocketMisuseReport `json:"misuse"`
	Parity                   SocketParityReport `json:"parity"`
	Collapse                 SocketCollapseReport `json:"collapse"`
	FixtureHash              string             `json:"fixture_hash"`
	PayloadLogged            bool               `json:"payload_logged"`
	SecretLogged             bool               `json:"secret_logged"`
	Conclusion               string             `json:"conclusion"`
}

type SocketComparison struct {
	ScenarioCount int    `json:"scenario_count"`
	SummaryCount  int    `json:"summary_count"`
	Conclusion    string `json:"conclusion"`
}

type SocketMisuseReport struct {
	ObjectsChecked    int      `json:"objects_checked"`
	ExternalRejected  int      `json:"external_rejected"`
	WildcardRejected  int      `json:"wildcard_rejected"`
	MalformedRejected int      `json:"malformed_rejected"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	PayloadLogged     bool     `json:"payload_logged"`
	SecretLogged      bool     `json:"secret_logged"`
	Conclusion        string   `json:"conclusion"`
}

type SocketParityReport struct {
	ComparedSummaries     int      `json:"compared_summaries"`
	SemanticMatches       int      `json:"semantic_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type SocketCollapseReport struct {
	Scenario          string   `json:"scenario"`
	ProfileCount      int      `json:"profile_count"`
	AdapterKinds      []string `json:"adapter_kinds"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	DiversityScore    float64  `json:"diversity_score"`
	Conclusion        string   `json:"conclusion"`
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

func DefaultConfig() BindConfig {
	return BindConfig{
		Host:              "127.0.0.1",
		Port:              0,
		MaxConnections:    16,
		MaxBufferedBytes:  64 * 1024,
		MaxEvents:         512,
		TraceEnabled:      true,
		DeterministicSeed: 36,
	}
}

func fixedGeneratedAt() (string, int64) {
	t := time.Unix(36, 0).UTC()
	return t.Format(time.RFC3339), t.Unix()
}
