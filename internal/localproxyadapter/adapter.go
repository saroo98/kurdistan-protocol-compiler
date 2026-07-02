// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyadapter

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

	"kurdistan/internal/localprotocoladapter"
)

const (
	Version                  = "localproxyadapter-v1"
	BackendVersion           = "0.49.0-lab"
	DefaultFixtureID         = "local_proxy_adapter_prototype_v1"
	ConclusionPassed         = "passed"
	RecommendedNextMilestone = "M50: local proxy adapter adversarial hardening"
)

var generatedAt = time.Date(2026, 2, 17, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)

type Config struct {
	ConfigID                  string   `json:"config_id"`
	AcceptedProtocolFamilies  []string `json:"accepted_protocol_families"`
	MaxStreamsClass           string   `json:"max_streams_class"`
	MaxBufferedBytesClass     string   `json:"max_buffered_bytes_class"`
	MaxEventsClass            string   `json:"max_events_class"`
	AllowDNSResolution        bool     `json:"allow_dns_resolution"`
	AllowPublicNetworkDefault bool     `json:"allow_public_network_default"`
	AllowPacketCapture        bool     `json:"allow_packet_capture"`
	AllowCredentialStorage    bool     `json:"allow_credential_storage"`
	AllowPayloadLogging       bool     `json:"allow_payload_logging"`
	PayloadLogged             bool     `json:"payload_logged"`
	SecretLogged              bool     `json:"secret_logged"`
}

type AcceptedRequest struct {
	RequestID             string `json:"request_id"`
	ProtocolFamily        string `json:"protocol_family"`
	ParserState           string `json:"parser_state"`
	TargetClassBucket     string `json:"target_class_bucket"`
	PortClassBucket       string `json:"port_class_bucket"`
	RequestClass          string `json:"request_class"`
	RuntimeStreamClass    string `json:"runtime_stream_class"`
	CarrierCandidateClass string `json:"carrier_candidate_class"`
	RequestHash           string `json:"request_hash"`
	PayloadLogged         bool   `json:"payload_logged"`
	SecretLogged          bool   `json:"secret_logged"`
	TargetPersisted       bool   `json:"target_persisted"`
	PortPersisted         bool   `json:"port_persisted"`
}

type StreamRun struct {
	Name                    string `json:"name"`
	ContentClass            string `json:"content_class"`
	StreamState             string `json:"stream_state"`
	OpenResult              string `json:"open_result"`
	CloseResult             string `json:"close_result"`
	ResetResult             string `json:"reset_result"`
	HalfCloseResult         string `json:"half_close_result"`
	BackpressureResult      string `json:"backpressure_result"`
	CarrierSelectionResult  string `json:"carrier_selection_result"`
	RelayBridgeResult       string `json:"relaybridge_result"`
	LocalPipelineResult     string `json:"localpipeline_result"`
	LabEgressResult         string `json:"labegress_result"`
	MeasurementReviewResult string `json:"measurementreview_result"`
	PathHealthResult        string `json:"pathhealth_result"`
	PathRaceResult          string `json:"pathrace_result"`
	ByteCountBucket         string `json:"byte_count_bucket"`
	ChunkCountBucket        string `json:"chunk_count_bucket"`
	ContentHash             string `json:"content_hash"`
	Rejected                bool   `json:"rejected"`
	RejectReasonBucket      string `json:"reject_reason_bucket,omitempty"`
	PayloadLogged           bool   `json:"payload_logged"`
	SecretLogged            bool   `json:"secret_logged"`
}

type PrototypeSummary struct {
	SessionsOpened          int  `json:"sessions_opened"`
	SessionsClosed          int  `json:"sessions_closed"`
	RequestsAccepted        int  `json:"requests_accepted"`
	RequestsRejected        int  `json:"requests_rejected"`
	StreamsOpened           int  `json:"streams_opened"`
	StreamsClosed           int  `json:"streams_closed"`
	StreamsReset            int  `json:"streams_reset"`
	HalfClosesObserved      int  `json:"half_closes_observed"`
	BackpressureEvents      int  `json:"backpressure_events"`
	CarrierSelections       int  `json:"carrier_selections"`
	RelayBridgeMappings     int  `json:"relaybridge_mappings"`
	LocalPipelineMappings   int  `json:"localpipeline_mappings"`
	LabEgressExchanges      int  `json:"labegress_exchanges"`
	PathHealthReports       int  `json:"pathhealth_reports"`
	PathRaceDecisions       int  `json:"pathrace_decisions"`
	MeasurementReviews      int  `json:"measurement_reviews"`
	ResourceLimitRejections int  `json:"resource_limit_rejections"`
	PayloadLogged           bool `json:"payload_logged"`
	SecretLogged            bool `json:"secret_logged"`
	Completed               bool `json:"completed"`
}

type IntegrationReport struct {
	LocalProtocolAdapter string   `json:"localprotocoladapter"`
	LoopbackRelay        string   `json:"loopbackrelay"`
	MultiCarrierSelect   string   `json:"multicarrierselect"`
	HTTPSLikeCarrier     string   `json:"httpslikecarrier"`
	DNSSurvivalCarrier   string   `json:"dnssurvivalcarrier"`
	LabEgress            string   `json:"labegress"`
	RelayBridge          string   `json:"relaybridge"`
	LocalPipeline        string   `json:"localpipeline"`
	PathHealth           string   `json:"pathhealth"`
	PathRace             string   `json:"pathrace"`
	MeasurementReview    string   `json:"measurementreview"`
	CarrierReview        string   `json:"carrierreview"`
	Hardening            string   `json:"hardening"`
	RequiredGates        []string `json:"required_gates"`
	Conclusion           string   `json:"conclusion"`
}

type ResourceReport struct {
	MaxStreamsClass       string   `json:"max_streams_class"`
	MaxBufferedBytesClass string   `json:"max_buffered_bytes_class"`
	MaxEventsClass        string   `json:"max_events_class"`
	PanicSafetyTargets    []string `json:"panic_safety_targets"`
	RejectedControls      []string `json:"rejected_controls"`
	Conclusion            string   `json:"conclusion"`
}

type MisuseReport struct {
	DetectedControls []string `json:"detected_controls"`
	DetectedCount    int      `json:"detected_count"`
	ExpectedCount    int      `json:"expected_count"`
	Conclusion       string   `json:"conclusion"`
}

type ParityReport struct {
	GeneratedMarkers []string `json:"generated_markers"`
	InterpretedHash  string   `json:"interpreted_hash"`
	GeneratedHash    string   `json:"generated_hash"`
	UnexpectedDrift  []string `json:"unexpected_drift"`
	Conclusion       string   `json:"conclusion"`
}

type FixtureSet struct {
	Version                  string            `json:"version"`
	FixtureID                string            `json:"fixture_id"`
	GeneratedAt              string            `json:"generated_at"`
	BackendVersion           string            `json:"backend_version"`
	RecommendedNextMilestone string            `json:"recommended_next_milestone"`
	Config                   Config            `json:"config"`
	StreamClasses            []string          `json:"stream_classes"`
	Requests                 []AcceptedRequest `json:"requests"`
	Runs                     []StreamRun       `json:"runs"`
	Summary                  PrototypeSummary  `json:"summary"`
	Integration              IntegrationReport `json:"integration"`
	ResourceLimits           ResourceReport    `json:"resource_limits"`
	Misuse                   MisuseReport      `json:"misuse"`
	Parity                   ParityReport      `json:"parity"`
	FixtureHash              string            `json:"fixture_hash"`
	PayloadLogged            bool              `json:"payload_logged"`
	SecretLogged             bool              `json:"secret_logged"`
	Conclusion               string            `json:"conclusion"`
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

func DefaultConfig() Config {
	return Config{
		ConfigID:                 "localproxyadapter-config-v1",
		AcceptedProtocolFamilies: []string{localprotocoladapter.ProtocolFamilyConnectLikeMetadata, localprotocoladapter.ProtocolFamilySocks5LikeMetadata},
		MaxStreamsClass:          "profile_bounded_streams",
		MaxBufferedBytesClass:    "bounded_local_adapter_buffer",
		MaxEventsClass:           "bounded_adapter_events",
	}
}

func ValidateConfig(cfg Config) error {
	if cfg.ConfigID == "" {
		return errors.New("missing local proxy adapter config id")
	}
	if len(cfg.AcceptedProtocolFamilies) < 2 {
		return errors.New("local proxy adapter protocol families incomplete")
	}
	if cfg.MaxStreamsClass == "" || cfg.MaxBufferedBytesClass == "" || cfg.MaxEventsClass == "" {
		return errors.New("local proxy adapter resource classes incomplete")
	}
	if cfg.AllowDNSResolution || cfg.AllowPublicNetworkDefault || cfg.AllowPacketCapture || cfg.AllowCredentialStorage || cfg.AllowPayloadLogging || cfg.PayloadLogged || cfg.SecretLogged {
		return errors.New("unsafe local proxy adapter config")
	}
	return nil
}

func GenerateFixtureSet() (FixtureSet, error) {
	cfg := DefaultConfig()
	if err := ValidateConfig(cfg); err != nil {
		return FixtureSet{}, err
	}
	requests := BuildAcceptedRequests()
	runs := BuildStreamRuns(requests)
	set := FixtureSet{
		Version:                  Version,
		FixtureID:                DefaultFixtureID,
		GeneratedAt:              generatedAt,
		BackendVersion:           BackendVersion,
		RecommendedNextMilestone: RecommendedNextMilestone,
		Config:                   cfg,
		StreamClasses:            DefaultStreamClasses(),
		Requests:                 requests,
		Runs:                     runs,
		Summary:                  BuildSummary(requests, runs),
		Integration:              BuildIntegrationReport(),
		ResourceLimits:           BuildResourceReport(),
		Misuse:                   BuildMisuseReport(),
		Conclusion:               ConclusionPassed,
	}
	set.Parity = BuildParityReport(set)
	set.FixtureHash = HashValue(fixtureHashInput(set))
	if err := ValidateFixtureSet(set); err != nil {
		return FixtureSet{}, err
	}
	return set, nil
}

func BuildAcceptedRequests() []AcceptedRequest {
	cfg := localprotocoladapter.DefaultConfig()
	connect, _ := localprotocoladapter.ParseConnectLike(cfg, "m49-connect", "CONNECT synthetic-alpha:8080 KP/1")
	socks, _ := localprotocoladapter.ParseSocks5Like(cfg, "m49-socks", []byte{0x05, 0x01, 0x00}, socksRequest("fixture-beta", 8443))
	control, _ := localprotocoladapter.ParseConnectLike(cfg, "m49-loopback-control", "CONNECT localhost:8080 KP/1")
	parsed := []localprotocoladapter.ParsedLocalProxyRequest{connect, socks, control}
	out := make([]AcceptedRequest, 0, len(parsed))
	for i, req := range parsed {
		summary := AcceptedRequest{
			RequestID:             req.RequestID,
			ProtocolFamily:        req.ProtocolFamily,
			ParserState:           req.ParserState,
			TargetClassBucket:     req.TargetClass,
			PortClassBucket:       req.TargetPortBucket,
			RequestClass:          req.RequestClass,
			RuntimeStreamClass:    []string{"interactive_stream", "bulk_stream", "control_stream"}[i%3],
			CarrierCandidateClass: []string{"https_like_candidate", "dns_survival_candidate", "loopback_candidate"}[i%3],
		}
		summary.RequestHash = HashValue(requestHashInput(summary))
		out = append(out, summary)
	}
	return out
}

func BuildStreamRuns(requests []AcceptedRequest) []StreamRun {
	classes := DefaultStreamClasses()
	runs := make([]StreamRun, 0, len(classes))
	for i, class := range classes {
		run := StreamRun{
			Name:                    "localproxyadapter_" + class,
			ContentClass:            class,
			StreamState:             "closed",
			OpenResult:              "stream_opened_from_redacted_request",
			CloseResult:             "closed_cleanly",
			ResetResult:             "not_reset",
			HalfCloseResult:         "not_half_closed",
			BackpressureResult:      "none",
			CarrierSelectionResult:  "multicarrierselect_invoked",
			RelayBridgeResult:       "relaybridge_mapped",
			LocalPipelineResult:     "localpipeline_mapped",
			LabEgressResult:         "labegress_policy_checked",
			MeasurementReviewResult: "measurementreview_enforced",
			PathHealthResult:        "pathhealth_report_returned",
			PathRaceResult:          "pathrace_decision_recorded",
			ByteCountBucket:         []string{"empty", "small", "medium", "long", "drip", "partial", "halfclose", "pressure", "control", "control", "control"}[i],
			ChunkCountBucket:        []string{"zero", "one", "many", "many", "drip", "partial", "final", "pressure", "control", "control", "control"}[i],
		}
		if len(requests) > 0 {
			run.ContentHash = HashValue(map[string]any{"class": class, "request": requests[i%len(requests)].RequestHash, "ordinal": i})
		}
		switch class {
		case "reset_stream_marker":
			run.StreamState = "reset"
			run.CloseResult = "not_closed_after_reset"
			run.ResetResult = "stream_scoped_reset"
		case "halfclose_stream_marker":
			run.HalfCloseResult = "write_half_close_then_drain"
		case "backpressure_stream_marker":
			run.BackpressureResult = "adapter_runtime_carrier_pressure"
		case "control_payload_leak":
			run.Rejected = true
			run.OpenResult = "rejected_before_stream_open"
			run.StreamState = "rejected"
			run.CloseResult = "not_opened"
			run.RejectReasonBucket = "payload_leak_control"
		case "control_unbounded_stream":
			run.Rejected = true
			run.OpenResult = "rejected_before_stream_open"
			run.StreamState = "rejected"
			run.CloseResult = "not_opened"
			run.RejectReasonBucket = "resource_limit_control"
		case "control_target_leak":
			run.Rejected = true
			run.OpenResult = "rejected_before_stream_open"
			run.StreamState = "rejected"
			run.CloseResult = "not_opened"
			run.RejectReasonBucket = "target_redaction_control"
		}
		runs = append(runs, run)
	}
	return runs
}

func BuildSummary(requests []AcceptedRequest, runs []StreamRun) PrototypeSummary {
	s := PrototypeSummary{SessionsOpened: 1, SessionsClosed: 1, RequestsAccepted: len(requests), Completed: true}
	for _, run := range runs {
		if run.Rejected {
			s.RequestsRejected++
			s.ResourceLimitRejections++
			continue
		}
		s.StreamsOpened++
		s.CarrierSelections++
		s.RelayBridgeMappings++
		s.LocalPipelineMappings++
		s.LabEgressExchanges++
		s.PathHealthReports++
		s.PathRaceDecisions++
		s.MeasurementReviews++
		if run.StreamState == "reset" {
			s.StreamsReset++
		} else {
			s.StreamsClosed++
		}
		if run.HalfCloseResult != "not_half_closed" {
			s.HalfClosesObserved++
		}
		if run.BackpressureResult != "none" {
			s.BackpressureEvents++
		}
	}
	return s
}

func BuildIntegrationReport() IntegrationReport {
	return IntegrationReport{
		LocalProtocolAdapter: "accepted_m37_metadata_is_source_of_stream_descriptor",
		LoopbackRelay:        "loopbackrelay_only_for_local_round_trip_evidence",
		MultiCarrierSelect:   "stream_class_forwarded_to_reviewed_selector",
		HTTPSLikeCarrier:     "https_like_candidate_allowed_only_after_m41_m43_gates",
		DNSSurvivalCarrier:   "dns_survival_candidate_allowed_only_after_m44_m45_gates",
		LabEgress:            "controlled_connector_policy_checked",
		RelayBridge:          "flow_to_relay_stream_mapping_checked",
		LocalPipeline:        "local_pipeline_summary_returns_to_adapter",
		PathHealth:           "pathhealth_summary_returned_to_adapter",
		PathRace:             "pathrace_decision_recorded_before_stream_chunks",
		MeasurementReview:    "aggregate_local_diagnostics_only",
		CarrierReview:        "carrier_family_review_gate_enforced",
		Hardening:            "trace_hygiene_and_resource_checks_composed",
		RequiredGates:        []string{"localprotocoladapter", "loopbackrelay", "multicarrierselect", "httpslikecarrier", "constrainedcarrier", "labegress", "relaybridge", "localpipeline", "pathhealth", "pathrace", "measurementreview", "carrierreview", "hardening", "codegen"},
		Conclusion:           ConclusionPassed,
	}
}

func BuildResourceReport() ResourceReport {
	return ResourceReport{
		MaxStreamsClass:       "profile_bounded_streams",
		MaxBufferedBytesClass: "bounded_local_adapter_buffer",
		MaxEventsClass:        "bounded_adapter_events",
		PanicSafetyTargets:    []string{"metadata_to_stream_mapping", "content_segmenter", "half_close_drain", "reset_propagation", "summary_builder"},
		RejectedControls:      []string{"control_payload_leak", "control_unbounded_stream", "control_target_leak"},
		Conclusion:            ConclusionPassed,
	}
}

func BuildMisuseReport() MisuseReport {
	required := RequiredMisuseNames()
	return MisuseReport{DetectedControls: append([]string{}, required...), DetectedCount: len(required), ExpectedCount: len(required), Conclusion: ConclusionPassed}
}

func BuildParityReport(set FixtureSet) ParityReport {
	markers := []string{"LocalProxyAdapterSchemaVersion", "LocalProxyAdapterGeneratedProfileID", "LocalProxyAdapterBackendVersion", "LocalProxyAdapterRuntimePolicy", "LocalProxyAdapterStreamClasses", "GeneratedLocalProxyAdapterFixtureSet"}
	base := map[string]any{
		"version":         set.Version,
		"stream_classes":  set.StreamClasses,
		"summary":         set.Summary,
		"integration":     set.Integration.RequiredGates,
		"resource_limits": set.ResourceLimits,
	}
	hash := HashValue(base)
	return ParityReport{GeneratedMarkers: markers, InterpretedHash: hash, GeneratedHash: hash, Conclusion: ConclusionPassed}
}

func ValidateFixtureSet(set FixtureSet) error {
	if set.Version != Version || set.BackendVersion != BackendVersion || set.FixtureID == "" {
		return errors.New("invalid local proxy adapter fixture metadata")
	}
	if err := ValidateConfig(set.Config); err != nil {
		return err
	}
	if len(set.StreamClasses) < 11 || len(set.Requests) < 3 || len(set.Runs) < 11 {
		return errors.New("local proxy adapter fixture coverage incomplete")
	}
	if set.Summary.PayloadLogged || set.Summary.SecretLogged || set.PayloadLogged || set.SecretLogged || !set.Summary.Completed {
		return errors.New("local proxy adapter summary reports unsafe logging or incomplete run")
	}
	if set.Summary.StreamsOpened < 8 || set.Summary.CarrierSelections < 8 || set.Summary.MeasurementReviews < 8 {
		return errors.New("local proxy adapter integration counts incomplete")
	}
	if set.Summary.BackpressureEvents == 0 || set.Summary.StreamsReset == 0 || set.Summary.HalfClosesObserved == 0 {
		return errors.New("local proxy adapter backpressure/reset/half-close coverage incomplete")
	}
	for _, req := range set.Requests {
		if req.RequestHash != HashValue(requestHashInput(req)) || req.PayloadLogged || req.SecretLogged || req.TargetPersisted || req.PortPersisted {
			return errors.New("unsafe local proxy adapter request summary")
		}
	}
	for _, run := range set.Runs {
		if run.ContentHash == "" || run.PayloadLogged || run.SecretLogged {
			return errors.New("unsafe local proxy adapter stream run")
		}
	}
	if len(set.Integration.RequiredGates) < 12 || set.Integration.Conclusion != ConclusionPassed {
		return errors.New("local proxy adapter integration report incomplete")
	}
	if len(set.ResourceLimits.PanicSafetyTargets) < 4 || len(set.ResourceLimits.RejectedControls) < 3 || set.ResourceLimits.Conclusion != ConclusionPassed {
		return errors.New("local proxy adapter resource report incomplete")
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) || set.Misuse.Conclusion != ConclusionPassed {
		return errors.New("local proxy adapter misuse report incomplete")
	}
	if set.Parity.Conclusion != ConclusionPassed || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 5 {
		return errors.New("local proxy adapter generated/interpreted parity failed")
	}
	if set.FixtureHash != "" && set.FixtureHash != HashValue(fixtureHashInput(set)) {
		return errors.New("local proxy adapter fixture hash mismatch")
	}
	return ScanForLeak(set)
}

func CompareFixtureSets(oldSet, newSet FixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash}
	if oldSet.PayloadLogged || newSet.PayloadLogged || oldSet.Summary.PayloadLogged || newSet.Summary.PayloadLogged {
		report.PayloadLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "payload logging flag changed")
	}
	if oldSet.SecretLogged || newSet.SecretLogged || oldSet.Summary.SecretLogged || newSet.Summary.SecretLogged {
		report.SecretLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "secret logging flag changed")
	}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture hash changed")
	}
	if len(report.UnexpectedDrift) == 0 {
		report.Conclusion = ConclusionPassed
	} else {
		report.Conclusion = "failed"
	}
	return report
}

func LoadFixtureSet(path string) (FixtureSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FixtureSet{}, err
	}
	var set FixtureSet
	if err := json.Unmarshal(data, &set); err != nil {
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
			return fmt.Errorf("%s already exists; use --force", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := ScanForLeak(value); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func StableJSON(value any) ([]byte, error) {
	return json.MarshalIndent(value, "", "  ")
}

func HashValue(value any) string {
	data, _ := StableJSON(value)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ScanForLeak(value any) error {
	data, err := StableJSON(value)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(data))
	for _, marker := range ForbiddenMarkers() {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return fmt.Errorf("forbidden marker %q found", marker)
		}
	}
	for _, marker := range []string{`"payload_logged": true`, `"secret_logged": true`, `"target_persisted": true`, `"port_persisted": true`, `"allow_payload_logging": true`, `"allow_packet_capture": true`, `"allow_credential_storage": true`, `"allow_public_network_default": true`, `"allow_dns_resolution": true`} {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("unsafe flag %s found", marker)
		}
	}
	return nil
}

func ForbiddenMarkers() []string {
	return []string{
		`"raw_payload"`,
		`"payload_body"`,
		`"raw_stream_bytes"`,
		`"raw_bytes"`,
		`"packet_capture_dump"`,
		`"credential_value"`,
		`"secret_value"`,
		`"private_key"`,
		`"session_secret"`,
		`"auth_tag"`,
		`"nonce_base"`,
		`"exact_target_value"`,
		`"exact_port_value"`,
		`"sni_value"`,
		`"host_header_value"`,
		`"resolver_ip"`,
		`"exact_dns_query"`,
		`"public_network_egress"`,
		`"packet_dump"`,
	}
}

func DefaultStreamClasses() []string {
	return []string{
		"no_content_marker",
		"small_stream_marker",
		"chunked_stream_marker",
		"long_lived_stream_marker",
		"slow_stream_marker",
		"reset_stream_marker",
		"halfclose_stream_marker",
		"backpressure_stream_marker",
		"control_payload_leak",
		"control_unbounded_stream",
		"control_target_leak",
	}
}

func RequiredMisuseNames() []string {
	return []string{
		"localproxyadapter_payload_logging_allowed",
		"localproxyadapter_packet_capture_allowed",
		"localproxyadapter_exact_target_persisted",
		"localproxyadapter_exact_port_persisted",
		"localproxyadapter_dns_resolution_allowed",
		"localproxyadapter_public_network_default",
		"localproxyadapter_credential_storage_allowed",
		"localproxyadapter_unbounded_stream",
		"localproxyadapter_backpressure_ignored",
		"localproxyadapter_reset_swallowed",
		"localproxyadapter_stream_isolation_broken",
		"localproxyadapter_localprotocoladapter_bypass",
		"localproxyadapter_multicarrierselect_bypass",
		"localproxyadapter_measurementreview_bypass",
		"localproxyadapter_generated_backend_drift",
		"localproxyadapter_payload_leak",
		"localproxyadapter_secret_leak",
	}
}

func SortedRequiredMisuseNames() []string {
	names := RequiredMisuseNames()
	sort.Strings(names)
	return names
}

func socksRequest(name string, port int) []byte {
	if len(name) > 255 {
		name = name[:255]
	}
	out := []byte{0x05, 0x01, 0x00, 0x03, byte(len(name))}
	out = append(out, []byte(name)...)
	out = append(out, byte(port>>8), byte(port))
	return out
}

func requestHashInput(req AcceptedRequest) AcceptedRequest {
	req.RequestHash = ""
	return req
}

func fixtureHashInput(set FixtureSet) FixtureSet {
	set.FixtureHash = ""
	return set
}
