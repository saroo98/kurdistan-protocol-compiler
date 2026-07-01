// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localprotocoladapter

import "time"

const (
	Version                  = "localprotocoladapter-v1"
	DefaultFixtureID         = "local_protocol_adapter_fixture_v1"
	RecommendedNextMilestone = "M38: local loopback relay transport"

	ProtocolFamilyConnectLikeMetadata = "connect_like_metadata"
	ProtocolFamilySocks5LikeMetadata  = "socks5_like_metadata"
	ProtocolFamilyAutoDetectMetadata  = "auto_detect_metadata"
	ProtocolFamilyRejectedUnsafe      = "rejected_unsafe"
	ProtocolFamilyControlUnsafe       = "control_unsafe"

	ParserStateCreated        = "created"
	ParserStateAwaitingInput  = "awaiting_input"
	ParserStateHeaderParsed   = "header_parsed"
	ParserStateMethodSelected = "method_selected"
	ParserStateRequestParsed  = "request_parsed"
	ParserStateTargetRedacted = "target_redacted"
	ParserStateMapped         = "mapped"
	ParserStateRejected       = "rejected"
	ParserStateFailed         = "failed"
	ParserStateClosed         = "closed"

	RequestCommandConnectMetadata = "connect_metadata"
	RequestCommandUnsupported     = "unsupported"
	RequestCommandRejectedUnsafe  = "rejected_unsafe"

	TargetClassSyntheticName    = "synthetic_name"
	TargetClassRedactedNameLike = "redacted_name_like"
	TargetClassRedactedIPv4Like = "redacted_ipv4_like"
	TargetClassRedactedIPv6Like = "redacted_ipv6_like"
	TargetClassLoopbackLocal    = "loopback_local"
	TargetClassRejectedUnsafe   = "rejected_unsafe"
	TargetClassUnknownRejected  = "unknown_rejected"

	TargetPortBucketLow        = "low_port_bucket"
	TargetPortBucketCommon     = "common_service_bucket"
	TargetPortBucketRegistered = "registered_port_bucket"
	TargetPortBucketEphemeral  = "ephemeral_port_bucket"
	TargetPortBucketRejected   = "rejected"

	ScenarioConnectSynthetic       = "connect_like_synthetic_metadata"
	ScenarioConnectUnsupported     = "connect_like_unsupported_method"
	ScenarioConnectOversized       = "connect_like_oversized_control"
	ScenarioConnectSmuggling       = "connect_like_header_smuggling_control"
	ScenarioSocks5Synthetic        = "socks5_like_synthetic_metadata"
	ScenarioSocks5AuthRejected     = "socks5_like_auth_rejected"
	ScenarioSocks5CommandRejected  = "socks5_like_command_rejected"
	ScenarioTargetRedaction        = "target_redaction_matrix"
	ScenarioConcreteAdapterMapping = "concrete_adapter_mapping"
	ScenarioPipelineMapping        = "localpipeline_mapping"
	ScenarioResourceLimit          = "parser_resource_limits"
	ScenarioMisuseControls         = "local_protocol_misuse_controls"
)

type LocalProtocolAdapterConfig struct {
	ConfigID                  string   `json:"config_id"`
	EnabledFamilies           []string `json:"enabled_families"`
	MaxHeaderBytes            int      `json:"max_header_bytes"`
	MaxHandshakeBytes         int      `json:"max_handshake_bytes"`
	MaxRequestLineBytes       int      `json:"max_request_line_bytes"`
	MaxBufferedBytes          int      `json:"max_buffered_bytes"`
	MaxParserTransitions      int      `json:"max_parser_transitions"`
	AllowConnectLike          bool     `json:"allow_connect_like"`
	AllowSocks5Like           bool     `json:"allow_socks5_like"`
	AllowCredentials          bool     `json:"allow_credentials"`
	AllowPayloadForwarding    bool     `json:"allow_payload_forwarding"`
	AllowOutboundDial         bool     `json:"allow_outbound_dial"`
	AllowDNSResolution        bool     `json:"allow_dns_resolution"`
	AllowTargetPersistence    bool     `json:"allow_target_persistence"`
	AllowExactPortPersistence bool     `json:"allow_exact_port_persistence"`
	PayloadLoggingAllowed     bool     `json:"payload_logging_allowed"`
	ConfigHash                string   `json:"config_hash"`
	PayloadLogged             bool     `json:"payload_logged"`
	SecretLogged              bool     `json:"secret_logged"`
}

type ParsedLocalProxyRequest struct {
	RequestID             string   `json:"request_id"`
	ConnectionID          string   `json:"connection_id"`
	ProtocolFamily        string   `json:"protocol_family"`
	ParserState           string   `json:"parser_state"`
	CommandClass          string   `json:"command_class"`
	TargetClass           string   `json:"target_class"`
	TargetPortBucket      string   `json:"target_port_bucket"`
	RequestClass          string   `json:"request_class"`
	PipelineMappingClass  string   `json:"pipeline_mapping_class"`
	UnsupportedFeatures   []string `json:"unsupported_features,omitempty"`
	RejectedReasonClass   string   `json:"rejected_reason_class,omitempty"`
	ExactTargetPersisted  bool     `json:"exact_target_persisted"`
	ExactPortPersisted    bool     `json:"exact_port_persisted"`
	CredentialsSeen       bool     `json:"credentials_seen"`
	PayloadForwardingUsed bool     `json:"payload_forwarding_used"`
	OutboundDialUsed      bool     `json:"outbound_dial_used"`
	DNSResolutionUsed     bool     `json:"dns_resolution_used"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	RequestHash           string   `json:"request_hash"`
}

type ParserStateReport struct {
	Version       string   `json:"version"`
	Transitions   []string `json:"transitions"`
	Rejected      int      `json:"rejected"`
	Failed        int      `json:"failed"`
	Closed        int      `json:"closed"`
	ReportHash    string   `json:"report_hash"`
	Conclusion    string   `json:"conclusion"`
	PayloadLogged bool     `json:"payload_logged"`
	SecretLogged  bool     `json:"secret_logged"`
}

type LocalProtocolAdapterReport struct {
	Version                 string `json:"version"`
	RunID                   string `json:"run_id"`
	ConfigsChecked          int    `json:"configs_checked"`
	ConnectionsChecked      int    `json:"connections_checked"`
	ParserRuns              int    `json:"parser_runs"`
	RequestsParsed          int    `json:"requests_parsed"`
	RequestsRejected        int    `json:"requests_rejected"`
	ConnectLikeRuns         int    `json:"connect_like_runs"`
	Socks5LikeRuns          int    `json:"socks5_like_runs"`
	PipelineMappings        int    `json:"pipeline_mappings"`
	UnsupportedFeaturesSeen int    `json:"unsupported_features_seen"`
	ResourceLimitEvents     int    `json:"resource_limit_events"`
	PayloadForwardingEvents int    `json:"payload_forwarding_events"`
	OutboundDialEvents      int    `json:"outbound_dial_events"`
	DNSResolutionEvents     int    `json:"dns_resolution_events"`
	PayloadLogged           bool   `json:"payload_logged"`
	SecretLogged            bool   `json:"secret_logged"`
	ReportHash              string `json:"report_hash"`
	Conclusion              string `json:"conclusion"`
}

type ConfigValidationReport struct {
	Version                   string `json:"version"`
	ConfigsChecked            int    `json:"configs_checked"`
	ValidConfigs              int    `json:"valid_configs"`
	RejectedConfigs           int    `json:"rejected_configs"`
	OutboundDialRejected      int    `json:"outbound_dial_rejected"`
	DNSResolutionRejected     int    `json:"dns_resolution_rejected"`
	PayloadForwardingRejected int    `json:"payload_forwarding_rejected"`
	TargetPersistenceRejected int    `json:"target_persistence_rejected"`
	CredentialSupportRejected int    `json:"credential_support_rejected"`
	PayloadLoggingRejected    int    `json:"payload_logging_rejected"`
	ResourceLimitRejected     int    `json:"resource_limit_rejected"`
	PayloadLogged             bool   `json:"payload_logged"`
	SecretLogged              bool   `json:"secret_logged"`
	Conclusion                string `json:"conclusion"`
}

type ConnectLikeParseReport struct {
	Version                 string `json:"version"`
	ParserRuns              int    `json:"parser_runs"`
	RequestsParsed          int    `json:"requests_parsed"`
	RequestsRejected        int    `json:"requests_rejected"`
	UnsupportedMethods      int    `json:"unsupported_methods"`
	OversizedRejected       int    `json:"oversized_rejected"`
	MalformedRejected       int    `json:"malformed_rejected"`
	AbsoluteURLRejected     int    `json:"absolute_url_rejected"`
	HeaderSmugglingRejected int    `json:"header_smuggling_rejected"`
	TargetRedacted          int    `json:"target_redacted"`
	PortsBucketed           int    `json:"ports_bucketed"`
	PayloadLogged           bool   `json:"payload_logged"`
	SecretLogged            bool   `json:"secret_logged"`
	Conclusion              string `json:"conclusion"`
}

type Socks5LikeParseReport struct {
	Version                    string `json:"version"`
	ParserRuns                 int    `json:"parser_runs"`
	HandshakesParsed           int    `json:"handshakes_parsed"`
	RequestsParsed             int    `json:"requests_parsed"`
	RequestsRejected           int    `json:"requests_rejected"`
	UnsupportedAuthRejected    int    `json:"unsupported_auth_rejected"`
	UnsupportedCommandRejected int    `json:"unsupported_command_rejected"`
	OversizedRejected          int    `json:"oversized_rejected"`
	MalformedRejected          int    `json:"malformed_rejected"`
	TargetRedacted             int    `json:"target_redacted"`
	PortsBucketed              int    `json:"ports_bucketed"`
	PayloadLogged              bool   `json:"payload_logged"`
	SecretLogged               bool   `json:"secret_logged"`
	Conclusion                 string `json:"conclusion"`
}

type TargetRedactionReport struct {
	Version              string `json:"version"`
	TargetsChecked       int    `json:"targets_checked"`
	TargetsRedacted      int    `json:"targets_redacted"`
	TargetsRejected      int    `json:"targets_rejected"`
	PortsBucketed        int    `json:"ports_bucketed"`
	ExactTargetLeaks     int    `json:"exact_target_leaks"`
	ExactPortLeaks       int    `json:"exact_port_leaks"`
	UnsafeTargetFindings int    `json:"unsafe_target_findings"`
	PayloadLogged        bool   `json:"payload_logged"`
	SecretLogged         bool   `json:"secret_logged"`
	Conclusion           string `json:"conclusion"`
}

type LocalProtocolFixtureSet struct {
	Version                  string                     `json:"version"`
	FixtureID                string                     `json:"fixture_id"`
	GeneratedAt              string                     `json:"generated_at"`
	GeneratedAtUnix          int64                      `json:"generated_at_unix"`
	BackendVersion           string                     `json:"backend_version"`
	RecommendedNextMilestone string                     `json:"recommended_next_milestone"`
	Config                   LocalProtocolAdapterConfig `json:"config"`
	Scenarios                []string                   `json:"scenarios"`
	Requests                 []ParsedLocalProxyRequest  `json:"requests"`
	ConfigReport             ConfigValidationReport     `json:"config_report"`
	ConnectReport            ConnectLikeParseReport     `json:"connect_report"`
	Socks5Report             Socks5LikeParseReport      `json:"socks5_report"`
	RedactionReport          TargetRedactionReport      `json:"redaction_report"`
	StateReport              ParserStateReport          `json:"state_report"`
	Report                   LocalProtocolAdapterReport `json:"report"`
	Misuse                   LocalProtocolMisuseReport  `json:"misuse"`
	Parity                   LocalProtocolParityReport  `json:"parity"`
	FixtureHash              string                     `json:"fixture_hash"`
	PayloadLogged            bool                       `json:"payload_logged"`
	SecretLogged             bool                       `json:"secret_logged"`
	Conclusion               string                     `json:"conclusion"`
}

type LocalProtocolMisuseReport struct {
	ObjectsChecked         int      `json:"objects_checked"`
	UnsafeDetected         int      `json:"unsafe_detected"`
	LeakControlsDetected   int      `json:"leak_controls_detected"`
	PipelineBypassDetected int      `json:"pipeline_bypass_detected"`
	Findings               []string `json:"findings,omitempty"`
	PayloadLogged          bool     `json:"payload_logged"`
	SecretLogged           bool     `json:"secret_logged"`
	Conclusion             string   `json:"conclusion"`
}

type LocalProtocolParityReport struct {
	ComparedRequests      int      `json:"compared_requests"`
	SemanticMatches       int      `json:"semantic_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
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

func DefaultConfig() LocalProtocolAdapterConfig {
	return LocalProtocolAdapterConfig{
		ConfigID:                  "localprotocoladapter-default",
		EnabledFamilies:           []string{ProtocolFamilyConnectLikeMetadata, ProtocolFamilySocks5LikeMetadata},
		MaxHeaderBytes:            512,
		MaxHandshakeBytes:         64,
		MaxRequestLineBytes:       256,
		MaxBufferedBytes:          2048,
		MaxParserTransitions:      16,
		AllowConnectLike:          true,
		AllowSocks5Like:           true,
		AllowCredentials:          false,
		AllowPayloadForwarding:    false,
		AllowOutboundDial:         false,
		AllowDNSResolution:        false,
		AllowTargetPersistence:    false,
		AllowExactPortPersistence: false,
		PayloadLoggingAllowed:     false,
	}
}

func fixedGeneratedAt() (string, int64) {
	t := time.Unix(37, 0).UTC()
	return t.Format(time.RFC3339), t.Unix()
}
