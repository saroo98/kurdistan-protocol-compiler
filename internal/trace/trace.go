// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package trace

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

type Event struct {
	TimeUnixNano              int64  `json:"time_unix_nano"`
	Role                      string `json:"role"`
	ProfileID                 string `json:"profile_id"`
	EventType                 string `json:"event_type"`
	State                     string `json:"state,omitempty"`
	Semantic                  string `json:"semantic,omitempty"`
	WireSymbol                string `json:"wire_symbol,omitempty"`
	Direction                 string `json:"direction,omitempty"`
	FrameBytes                int    `json:"frame_bytes,omitempty"`
	PayloadBytes              int    `json:"payload_bytes,omitempty"`
	PaddingBytes              int    `json:"padding_bytes,omitempty"`
	SchedulerMode             string `json:"scheduler_mode,omitempty"`
	StreamLabel               string `json:"stream_label,omitempty"`
	StreamEvent               string `json:"stream_event,omitempty"`
	StreamState               string `json:"stream_state,omitempty"`
	StreamWindowBucket        string `json:"stream_window_bucket,omitempty"`
	SessionWindowBucket       string `json:"session_window_bucket,omitempty"`
	PriorityClass             string `json:"priority_class,omitempty"`
	CloseResetEvent           string `json:"close_reset_event,omitempty"`
	Backpressure              bool   `json:"backpressure,omitempty"`
	TargetClassBucket         string `json:"target_class_bucket,omitempty"`
	RequestClassBucket        string `json:"request_class_bucket,omitempty"`
	ResponseModeBucket        string `json:"response_mode_bucket,omitempty"`
	TargetEventType           string `json:"target_event_type,omitempty"`
	TargetErrorBucket         string `json:"target_error_bucket,omitempty"`
	TargetReset               bool   `json:"target_reset,omitempty"`
	TargetClose               bool   `json:"target_close,omitempty"`
	ResponseChunkBucket       string `json:"response_chunk_bucket,omitempty"`
	TargetBackpressure        bool   `json:"target_backpressure,omitempty"`
	ProxyScenario             string `json:"proxy_scenario,omitempty"`
	CarrierFamilyBucket       string `json:"carrier_family_bucket,omitempty"`
	CarrierEnvelopeKind       string `json:"carrier_envelope_kind,omitempty"`
	CarrierEnvelopeCount      string `json:"carrier_envelope_count,omitempty"`
	CarrierSemanticCount      string `json:"carrier_semantic_count,omitempty"`
	CarrierChunkCount         string `json:"carrier_chunk_count,omitempty"`
	CarrierBatchCount         string `json:"carrier_batch_count,omitempty"`
	CarrierFlushClass         string `json:"carrier_flush_class,omitempty"`
	CarrierRetryCount         string `json:"carrier_retry_count,omitempty"`
	CarrierReordered          bool   `json:"carrier_reordered,omitempty"`
	CarrierDropped            bool   `json:"carrier_dropped,omitempty"`
	CarrierBackpressure       bool   `json:"carrier_backpressure,omitempty"`
	CarrierQueueDepth         string `json:"carrier_queue_depth,omitempty"`
	CarrierReconstruction     string `json:"carrier_reconstruction,omitempty"`
	CarrierScenario           string `json:"carrier_scenario,omitempty"`
	SecuritySuiteBucket       string `json:"security_suite_bucket,omitempty"`
	TranscriptModeBucket      string `json:"transcript_mode_bucket,omitempty"`
	NonceModeBucket           string `json:"nonce_mode_bucket,omitempty"`
	ReplayPolicyBucket        string `json:"replay_policy_bucket,omitempty"`
	CapabilityPolicyBucket    string `json:"capability_policy_bucket,omitempty"`
	CompatibilityPolicyBucket string `json:"compatibility_policy_bucket,omitempty"`
	SecureEnvelopeModeBucket  string `json:"secure_envelope_mode_bucket,omitempty"`
	ReplayRejectionCount      int    `json:"replay_rejection_count,omitempty"`
	DowngradeRejectionCount   int    `json:"downgrade_rejection_count,omitempty"`
	ConfigHygieneResult       string `json:"config_hygiene_result,omitempty"`
	SecretHygieneResult       string `json:"secret_hygiene_result,omitempty"`
	GeneratedParityResult     string `json:"generated_parity_result,omitempty"`
	Note                      string `json:"note,omitempty"`
}

type Recorder struct {
	mu sync.Mutex
	w  io.Writer
	c  io.Closer
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
		ev.TimeUnixNano = time.Now().UnixNano()
	}
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
