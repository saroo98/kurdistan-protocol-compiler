// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package trace

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

const DiagnosticSchemaV1 = "diagnostic_v1"

var ErrDiagnosticEventInvalidV1 = errors.New("diagnostic_event_invalid")
var ErrDiagnosticRecorderLimitV1 = errors.New("diagnostic_recorder_limit")

// DiagnosticEventV1 is the strict operational diagnostic schema. It has no
// timestamp, profile, peer, stream, relay, destination, hash, or free-text
// field. Coarse combinations may still correlate activity, so this schema is
// data-minimized but does not claim anonymity.
type DiagnosticEventV1 struct {
	SchemaVersion   string `json:"schema_version"`
	EventClass      string `json:"event_class"`
	RoleBucket      string `json:"role_bucket,omitempty"`
	StateBucket     string `json:"state_bucket,omitempty"`
	OutcomeBucket   string `json:"outcome_bucket,omitempty"`
	DirectionBucket string `json:"direction_bucket,omitempty"`
	SizeBucket      string `json:"size_bucket,omitempty"`
	CountBucket     string `json:"count_bucket,omitempty"`
	ReasonBucket    string `json:"reason_bucket,omitempty"`
	HygieneResult   string `json:"hygiene_result,omitempty"`
}

var diagnosticAllowedV1 = map[string]map[string]bool{
	"event_class":      {"runtime": true, "channel": true, "replay": true, "rekey": true, "failure": true, "close": true, "security_envelope": true},
	"role_bucket":      {"client": true, "relay": true},
	"state_bucket":     {"starting": true, "active": true, "terminal": true},
	"outcome_bucket":   {"accepted": true, "rejected": true, "completed": true},
	"direction_bucket": {"client_to_relay": true, "relay_to_client": true},
	"size_bucket":      {"none": true, "small": true, "medium": true, "large": true},
	"count_bucket":     {"none": true, "one": true, "few": true, "many": true},
	"reason_bucket":    {"replay": true, "policy": true, "profile": true, "capability": true, "config": true, "resource": true, "timeout": true, "closed": true, "other": true},
	"hygiene_result":   {"redacted": true},
}

func ValidateDiagnosticEventV1(event DiagnosticEventV1) error {
	if event.SchemaVersion != DiagnosticSchemaV1 || !diagnosticAllowedV1["event_class"][event.EventClass] {
		return ErrDiagnosticEventInvalidV1
	}
	values := map[string]string{"role_bucket": event.RoleBucket, "state_bucket": event.StateBucket, "outcome_bucket": event.OutcomeBucket, "direction_bucket": event.DirectionBucket, "size_bucket": event.SizeBucket, "count_bucket": event.CountBucket, "reason_bucket": event.ReasonBucket, "hygiene_result": event.HygieneResult}
	for field, value := range values {
		if value != "" && !diagnosticAllowedV1[field][value] {
			return ErrDiagnosticEventInvalidV1
		}
	}
	return nil
}

func ValidateDiagnosticSequenceV1(events []DiagnosticEventV1) error {
	for _, event := range events {
		if err := ValidateDiagnosticEventV1(event); err != nil {
			return err
		}
	}
	return nil
}

type DiagnosticRecorderV1 struct {
	mu              sync.Mutex
	events          []DiagnosticEventV1
	encodedBytes    int
	maxEvents       int
	maxEncodedBytes int
}

func NewDiagnosticRecorderV1(maxEvents, maxEncodedBytes int) (*DiagnosticRecorderV1, error) {
	if maxEvents <= 0 || maxEvents > 4096 || maxEncodedBytes <= 0 || maxEncodedBytes > 4<<20 {
		return nil, ErrDiagnosticRecorderLimitV1
	}
	return &DiagnosticRecorderV1{events: make([]DiagnosticEventV1, 0, minIntV1(maxEvents, 64)), maxEvents: maxEvents, maxEncodedBytes: maxEncodedBytes}, nil
}

func (recorder *DiagnosticRecorderV1) Record(event DiagnosticEventV1) error {
	if recorder == nil {
		return ErrDiagnosticRecorderLimitV1
	}
	if err := ValidateDiagnosticEventV1(event); err != nil {
		return err
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.events) >= recorder.maxEvents || recorder.encodedBytes+len(raw) > recorder.maxEncodedBytes {
		return ErrDiagnosticRecorderLimitV1
	}
	recorder.events = append(recorder.events, event)
	recorder.encodedBytes += len(raw)
	return nil
}

func (recorder *DiagnosticRecorderV1) Snapshot() []DiagnosticEventV1 {
	if recorder == nil {
		return nil
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]DiagnosticEventV1(nil), recorder.events...)
}

func minIntV1(left, right int) int {
	if left < right {
		return left
	}
	return right
}

// Event is the legacy research-only trace schema. Strict operational paths
// must use DiagnosticEventV1 and DiagnosticRecorderV1.
type Event struct {
	TimeUnixNano                       int64  `json:"time_unix_nano"`
	Role                               string `json:"role"`
	ProfileID                          string `json:"profile_id,omitempty"`
	EventType                          string `json:"event_type"`
	State                              string `json:"state,omitempty"`
	Semantic                           string `json:"semantic,omitempty"`
	WireSymbol                         string `json:"wire_symbol,omitempty"`
	Direction                          string `json:"direction,omitempty"`
	FrameBytes                         int    `json:"frame_bytes,omitempty"`
	PayloadBytes                       int    `json:"payload_bytes,omitempty"`
	PaddingBytes                       int    `json:"padding_bytes,omitempty"`
	SchedulerMode                      string `json:"scheduler_mode,omitempty"`
	StreamLabel                        string `json:"stream_label,omitempty"`
	StreamEvent                        string `json:"stream_event,omitempty"`
	StreamState                        string `json:"stream_state,omitempty"`
	StreamWindowBucket                 string `json:"stream_window_bucket,omitempty"`
	SessionWindowBucket                string `json:"session_window_bucket,omitempty"`
	PriorityClass                      string `json:"priority_class,omitempty"`
	CloseResetEvent                    string `json:"close_reset_event,omitempty"`
	Backpressure                       bool   `json:"backpressure,omitempty"`
	TargetClassBucket                  string `json:"target_class_bucket,omitempty"`
	RequestClassBucket                 string `json:"request_class_bucket,omitempty"`
	ResponseModeBucket                 string `json:"response_mode_bucket,omitempty"`
	TargetEventType                    string `json:"target_event_type,omitempty"`
	TargetErrorBucket                  string `json:"target_error_bucket,omitempty"`
	TargetReset                        bool   `json:"target_reset,omitempty"`
	TargetClose                        bool   `json:"target_close,omitempty"`
	ResponseChunkBucket                string `json:"response_chunk_bucket,omitempty"`
	TargetBackpressure                 bool   `json:"target_backpressure,omitempty"`
	ProxyScenario                      string `json:"proxy_scenario,omitempty"`
	CarrierFamilyBucket                string `json:"carrier_family_bucket,omitempty"`
	CarrierEnvelopeKind                string `json:"carrier_envelope_kind,omitempty"`
	CarrierEnvelopeCount               string `json:"carrier_envelope_count,omitempty"`
	CarrierSemanticCount               string `json:"carrier_semantic_count,omitempty"`
	CarrierChunkCount                  string `json:"carrier_chunk_count,omitempty"`
	CarrierBatchCount                  string `json:"carrier_batch_count,omitempty"`
	CarrierFlushClass                  string `json:"carrier_flush_class,omitempty"`
	CarrierRetryCount                  string `json:"carrier_retry_count,omitempty"`
	CarrierReordered                   bool   `json:"carrier_reordered,omitempty"`
	CarrierDropped                     bool   `json:"carrier_dropped,omitempty"`
	CarrierBackpressure                bool   `json:"carrier_backpressure,omitempty"`
	CarrierQueueDepth                  string `json:"carrier_queue_depth,omitempty"`
	CarrierReconstruction              string `json:"carrier_reconstruction,omitempty"`
	CarrierScenario                    string `json:"carrier_scenario,omitempty"`
	SecuritySuiteBucket                string `json:"security_suite_bucket,omitempty"`
	TranscriptModeBucket               string `json:"transcript_mode_bucket,omitempty"`
	NonceModeBucket                    string `json:"nonce_mode_bucket,omitempty"`
	ReplayPolicyBucket                 string `json:"replay_policy_bucket,omitempty"`
	CapabilityPolicyBucket             string `json:"capability_policy_bucket,omitempty"`
	CompatibilityPolicyBucket          string `json:"compatibility_policy_bucket,omitempty"`
	SecureEnvelopeModeBucket           string `json:"secure_envelope_mode_bucket,omitempty"`
	ReplayRejectionCount               int    `json:"replay_rejection_count,omitempty"`
	DowngradeRejectionCount            int    `json:"downgrade_rejection_count,omitempty"`
	ConfigHygieneResult                string `json:"config_hygiene_result,omitempty"`
	SecretHygieneResult                string `json:"secret_hygiene_result,omitempty"`
	GeneratedParityResult              string `json:"generated_parity_result,omitempty"`
	RuntimeRole                        string `json:"runtime_role,omitempty"`
	RuntimeState                       string `json:"runtime_state,omitempty"`
	SessionState                       string `json:"session_state,omitempty"`
	LifecycleTransition                string `json:"lifecycle_transition,omitempty"`
	NegotiationResultBucket            string `json:"negotiation_result_bucket,omitempty"`
	CompatibilityResult                string `json:"compatibility_result,omitempty"`
	SecurityContextResult              string `json:"security_context_result,omitempty"`
	TranscriptMatch                    bool   `json:"transcript_match,omitempty"`
	CapabilityMatch                    bool   `json:"capability_match,omitempty"`
	FrameDirectionBucket               string `json:"frame_direction_bucket,omitempty"`
	RuntimeFrameBucket                 string `json:"runtime_frame_bucket,omitempty"`
	RuntimeFrameCount                  string `json:"runtime_frame_count,omitempty"`
	StreamEventBucket                  string `json:"stream_event_bucket,omitempty"`
	RuntimeReplayRejections            int    `json:"runtime_replay_rejections,omitempty"`
	RuntimeBackpressureCount           int    `json:"runtime_backpressure_count,omitempty"`
	RuntimeTargetErrorCount            int    `json:"runtime_target_error_count,omitempty"`
	RuntimeTargetResetCount            int    `json:"runtime_target_reset_count,omitempty"`
	CloseReasonBucket                  string `json:"close_reason_bucket,omitempty"`
	FailureReasonBucket                string `json:"failure_reason_bucket,omitempty"`
	PayloadHygiene                     bool   `json:"payload_hygiene,omitempty"`
	SecretHygiene                      bool   `json:"secret_hygiene,omitempty"`
	RuntimeScenario                    string `json:"runtime_scenario,omitempty"`
	AdapterNameBucket                  string `json:"adapter_name_bucket,omitempty"`
	AdapterKind                        string `json:"adapter_kind,omitempty"`
	FlowState                          string `json:"flow_state,omitempty"`
	FlowEvent                          string `json:"flow_event,omitempty"`
	FlowCountBucket                    string `json:"flow_count_bucket,omitempty"`
	AdapterChunkCountBucket            string `json:"adapter_chunk_count_bucket,omitempty"`
	AdapterByteCountBucket             string `json:"adapter_byte_count_bucket,omitempty"`
	AdapterBackpressureCount           int    `json:"adapter_backpressure_count,omitempty"`
	AdapterResetCount                  int    `json:"adapter_reset_count,omitempty"`
	AdapterCloseCount                  int    `json:"adapter_close_count,omitempty"`
	RuntimeStreamMappingResult         string `json:"runtime_stream_mapping_result,omitempty"`
	AdapterScenario                    string `json:"adapter_scenario,omitempty"`
	LocalAdapterSourceModel            string `json:"local_adapter_source_model,omitempty"`
	LocalAdapterSinkModel              string `json:"local_adapter_sink_model,omitempty"`
	LocalFlowState                     string `json:"local_flow_state,omitempty"`
	LocalSourceChunkCountBucket        string `json:"local_source_chunk_count_bucket,omitempty"`
	LocalSinkChunkCountBucket          string `json:"local_sink_chunk_count_bucket,omitempty"`
	LocalSourceByteBucket              string `json:"local_source_byte_bucket,omitempty"`
	LocalSinkByteBucket                string `json:"local_sink_byte_bucket,omitempty"`
	LocalSequenceIntegrityResult       string `json:"local_sequence_integrity_result,omitempty"`
	LocalPostCloseRejections           int    `json:"local_post_close_rejections,omitempty"`
	LocalBackpressureCount             int    `json:"local_backpressure_count,omitempty"`
	LocalQueuePressureCount            int    `json:"local_queue_pressure_count,omitempty"`
	LocalAdapterScenario               string `json:"local_adapter_scenario,omitempty"`
	ByteTransportScenario              string `json:"byte_transport_scenario,omitempty"`
	ByteFrameKindBucket                string `json:"byte_frame_kind_bucket,omitempty"`
	ByteFrameCountBucket               string `json:"byte_frame_count_bucket,omitempty"`
	ByteFragmentCountBucket            string `json:"byte_fragment_count_bucket,omitempty"`
	ByteCountBucket                    string `json:"byte_count_bucket,omitempty"`
	BytePipeQueuePressureBucket        string `json:"byte_pipe_queue_pressure_bucket,omitempty"`
	ByteReassemblyResult               string `json:"byte_reassembly_result,omitempty"`
	ByteSequenceRejectionCount         int    `json:"byte_sequence_rejection_count,omitempty"`
	ByteCorruptionRejectionCount       int    `json:"byte_corruption_rejection_count,omitempty"`
	ByteMalformedRejectionCount        int    `json:"byte_malformed_rejection_count,omitempty"`
	ByteCloseResetEventBucket          string `json:"byte_close_reset_event_bucket,omitempty"`
	ProxyIngressVersion                string `json:"proxy_ingress_version,omitempty"`
	ProxyIngressRequestState           string `json:"proxy_ingress_request_state,omitempty"`
	ProxyIngressScenario               string `json:"proxy_ingress_scenario,omitempty"`
	ProxyIngressTargetClass            string `json:"proxy_ingress_target_class,omitempty"`
	ProxyIngressMappingResult          string `json:"proxy_ingress_mapping_result,omitempty"`
	LocalProxyIngressVersion           string `json:"local_proxy_ingress_version,omitempty"`
	LocalProxyIngressScenario          string `json:"local_proxy_ingress_scenario,omitempty"`
	LocalProxyIngressEventBucket       string `json:"local_proxy_ingress_event_bucket,omitempty"`
	LocalProxyIngressRequestBucket     string `json:"local_proxy_ingress_request_bucket,omitempty"`
	LocalProxyIngressBackpressureCount int    `json:"local_proxy_ingress_backpressure_count,omitempty"`
	LocalProxyIngressResetCount        int    `json:"local_proxy_ingress_reset_count,omitempty"`
	LocalProxyIngressErrorCount        int    `json:"local_proxy_ingress_error_count,omitempty"`
	LocalProxyIngressHygiene           string `json:"local_proxy_ingress_hygiene,omitempty"`
	RelayFleetID                       string `json:"relay_fleet_id,omitempty"`
	RelayIDBucket                      string `json:"relay_id_bucket,omitempty"`
	RelayLifecycleState                string `json:"relay_lifecycle_state,omitempty"`
	RelayLifecycleEvent                string `json:"relay_lifecycle_event,omitempty"`
	RelayClassBucket                   string `json:"relay_class_bucket,omitempty"`
	RelayChurnReasonBucket             string `json:"relay_churn_reason_bucket,omitempty"`
	RelayMigrationResultBucket         string `json:"relay_migration_result_bucket,omitempty"`
	RelayBurnRiskBucket                string `json:"relay_burn_risk_bucket,omitempty"`
	RelayProfileAssignmentBucket       string `json:"relay_profile_assignment_bucket,omitempty"`
	RelayPolicyBucket                  string `json:"relay_policy_bucket,omitempty"`
	RelayCollapseResult                string `json:"relay_collapse_result,omitempty"`
	Note                               string `json:"note,omitempty"`
}

// Recorder is a legacy research-only arbitrary-writer recorder.
type Recorder struct {
	mu sync.Mutex
	w  io.Writer
	c  io.Closer
}

const diagnosticTimeQuantum = time.Minute

// MinimizeDiagnosticEvent removes values that can act as stable cross-session
// identifiers and reduces wall-clock precision. It does not claim that the
// remaining coarse operational data is anonymous.
func MinimizeDiagnosticEvent(ev Event) Event {
	ev.ProfileID = ""
	ev.StreamLabel = ""
	ev.RelayFleetID = ""
	ev.RelayIDBucket = ""
	ev.Note = ""
	if ev.TimeUnixNano != 0 {
		ev.TimeUnixNano = time.Unix(0, ev.TimeUnixNano).UTC().Truncate(diagnosticTimeQuantum).UnixNano()
	}
	return ev
}

func NewRecorder(w io.Writer) *Recorder {
	if w == nil {
		return nil
	}
	return &Recorder{w: w}
}

func OpenRecorder(path string) (*Recorder, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &Recorder{w: f, c: f}, nil
}

func (r *Recorder) Close() error {
	if r == nil || r.c == nil {
		return nil
	}
	return r.c.Close()
}

func (r *Recorder) Record(ev Event) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ev.TimeUnixNano == 0 {
		ev.TimeUnixNano = time.Now().UTC().Truncate(diagnosticTimeQuantum).UnixNano()
	}
	ev = MinimizeDiagnosticEvent(ev)
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = r.w.Write(append(raw, '\n'))
	return err
}

func ReadJSONL(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return DecodeJSONL(f)
}

func DecodeJSONL(r io.Reader) ([]Event, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	var events []Event
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, err
		}
		events = append(events, ev)
	}
	return events, scanner.Err()
}
