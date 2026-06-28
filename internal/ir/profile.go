// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package ir

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

const (
	SupportedVersion = "0.1.0-lab"

	RoleClient = "client"
	RoleServer = "server"
	RoleShared = "shared"

	SemanticOpenStream   = "open_stream"
	SemanticData         = "data"
	SemanticClose        = "close_stream"
	SemanticAck          = "ack"
	SemanticResetStream  = "reset_stream"
	SemanticWindowUpdate = "window_update"
	SemanticSessionClose = "session_close"
	SemanticPadding      = "padding"
	SemanticError        = "error"

	SemanticOpenRelay        = "open_relay"
	SemanticTargetDescriptor = "target_descriptor"
	SemanticTargetData       = "target_data"
	SemanticTargetResponse   = "target_response"
	SemanticTargetError      = "target_error"
	SemanticTargetClose      = "target_close"
	SemanticTargetReset      = "target_reset"
	SemanticTargetMetadata   = "target_metadata"
)

type Profile struct {
	Version        string               `json:"version"`
	ID             string               `json:"id"`
	Seed           int64                `json:"seed"`
	GenerationHash string               `json:"generation_hash,omitempty"`
	RolePolicy     RolePolicy           `json:"role_policy"`
	Carrier        CarrierSpec          `json:"carrier"`
	States         []State              `json:"states"`
	Transitions    []Transition         `json:"transitions"`
	FirstContact   FirstContactSpec     `json:"first_contact"`
	Messages       []MessageSymbol      `json:"messages"`
	FrameGrammar   FrameGrammar         `json:"frame_grammar"`
	Auth           AuthSpec             `json:"auth"`
	Scheduler      SchedulerPolicy      `json:"scheduler"`
	Stream         StreamPolicy         `json:"stream"`
	ProxySemantics ProxySemanticsPolicy `json:"proxy_semantics"`
	CarrierPolicy  CarrierPolicy        `json:"carrier_policy"`
	Padding        PaddingPolicy        `json:"padding"`
	InvalidInput   InvalidInputPolicy   `json:"invalid_input"`
	Limits         SafetyLimits         `json:"limits"`
}

type RolePolicy struct {
	ClientRole string `json:"client_role"`
	ServerRole string `json:"server_role"`
}

type CarrierSpec struct {
	Type string `json:"type"`
}

type State struct {
	ID       string `json:"id"`
	Role     string `json:"role"`
	Terminal bool   `json:"terminal"`
}

type Transition struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Role         string `json:"role"`
	OnMessage    string `json:"on_message"`
	EmitsMessage string `json:"emits_message,omitempty"`
	RequiresAuth bool   `json:"requires_auth"`
	Description  string `json:"description"`
}

type FirstContactSpec struct {
	PatternID       string             `json:"pattern_id"`
	StartState      string             `json:"start_state"`
	RelayReadyState string             `json:"relay_ready_state"`
	Steps           []FirstContactStep `json:"steps"`
}

type FirstContactStep struct {
	Role        string `json:"role"`
	Direction   string `json:"direction"`
	Message     string `json:"message"`
	WireSymbol  string `json:"wire_symbol"`
	FromState   string `json:"from_state"`
	ToState     string `json:"to_state"`
	PayloadSize int    `json:"payload_size"`
	Proof       bool   `json:"proof"`
	Decoy       bool   `json:"decoy"`
}

type MessageSymbol struct {
	Semantic       string `json:"semantic"`
	WireSymbol     string `json:"wire_symbol"`
	Direction      string `json:"direction"`
	MinPayloadSize int    `json:"min_payload_size"`
	MaxPayloadSize int    `json:"max_payload_size"`
}

type FrameGrammar struct {
	LengthMode        string   `json:"length_mode"`
	TypeMode          string   `json:"type_mode"`
	HeaderOrder       []string `json:"header_order"`
	FragmentationMode string   `json:"fragmentation_mode"`
	ChecksumMode      string   `json:"checksum_mode"`
	PaddingPlacement  string   `json:"padding_placement"`
}

type AuthSpec struct {
	Mode         string `json:"mode"`
	KeyID        string `json:"key_id"`
	TestKeyHex   string `json:"test_key_hex"`
	NonceBytes   int    `json:"nonce_bytes"`
	ProofMessage string `json:"proof_message"`
}

type SchedulerPolicy struct {
	Mode              string `json:"mode"`
	MaxBatchBytes     int    `json:"max_batch_bytes"`
	FlushIntervalMs   int    `json:"flush_interval_ms"`
	MaxInFlightFrames int    `json:"max_in_flight_frames"`
	PriorityMode      string `json:"priority_mode"`
}

type StreamPolicy struct {
	IDStrategy                string `json:"id_strategy"`
	IDEncodingMode            string `json:"id_encoding_mode"`
	MaxConcurrentStreams      int    `json:"max_concurrent_streams"`
	InitialStreamWindowBytes  int    `json:"initial_stream_window_bytes"`
	InitialSessionWindowBytes int    `json:"initial_session_window_bytes"`
	WindowUpdatePolicy        string `json:"window_update_policy"`
	PriorityPolicy            string `json:"priority_policy"`
	ClosePolicy               string `json:"close_policy"`
	ResetPolicy               string `json:"reset_policy"`
	MaxStreamID               uint32 `json:"max_stream_id"`
}

type ProxySemanticsPolicy struct {
	RelayIntentEncoding      string   `json:"relay_intent_encoding"`
	TargetDescriptorEncoding string   `json:"target_descriptor_encoding"`
	RequestClassEncoding     string   `json:"request_class_encoding"`
	ResponseModeEncoding     string   `json:"response_mode_encoding"`
	TargetErrorPolicy        string   `json:"target_error_policy"`
	TargetClosePolicy        string   `json:"target_close_policy"`
	TargetResetPolicy        string   `json:"target_reset_policy"`
	TargetMetadataPolicy     string   `json:"target_metadata_policy"`
	RelayOpenOrderingPolicy  string   `json:"relay_open_ordering_policy"`
	RelayIntentPaddingPolicy string   `json:"relay_intent_padding_policy"`
	TargetClassMapping       string   `json:"target_class_mapping"`
	TargetClasses            []string `json:"target_classes"`
	MaxRequestBytes          int      `json:"max_request_bytes"`
	MaxResponseBytes         int      `json:"max_response_bytes"`
}

type CarrierPolicy struct {
	CarrierFamily          string `json:"carrier_family"`
	EnvelopeEncoding       string `json:"envelope_encoding"`
	FlushPolicy            string `json:"flush_policy"`
	BatchPolicy            string `json:"batch_policy"`
	ChunkingPolicy         string `json:"chunking_policy"`
	ReliabilityPolicy      string `json:"reliability_policy"`
	ReorderPolicy          string `json:"reorder_policy"`
	BackpressurePolicy     string `json:"backpressure_policy"`
	PriorityMappingPolicy  string `json:"priority_mapping_policy"`
	EnvelopePaddingPolicy  string `json:"envelope_padding_policy"`
	TimingBucketPolicy     string `json:"timing_bucket_policy"`
	MaxEnvelopeBytes       int    `json:"max_envelope_bytes"`
	MaxMessagesPerEnvelope int    `json:"max_messages_per_envelope"`
	MaxCarrierQueueDepth   int    `json:"max_carrier_queue_depth"`
	MaxRetryCount          int    `json:"max_retry_count"`
}

type PaddingPolicy struct {
	Mode            string  `json:"mode"`
	MinPaddingBytes int     `json:"min_padding_bytes"`
	MaxPaddingBytes int     `json:"max_padding_bytes"`
	Probability     float64 `json:"probability"`
}

type InvalidInputPolicy struct {
	UnknownFirstMessage string `json:"unknown_first_message"`
	MalformedFrame      string `json:"malformed_frame"`
	FailedAuth          string `json:"failed_auth"`
	Replay              string `json:"replay"`
	DelayMsMin          int    `json:"delay_ms_min"`
	DelayMsMax          int    `json:"delay_ms_max"`
}

type SafetyLimits struct {
	MaxFrameBytes    int `json:"max_frame_bytes"`
	MaxPayloadBytes  int `json:"max_payload_bytes"`
	MaxStates        int `json:"max_states"`
	MaxTransitions   int `json:"max_transitions"`
	MaxSessionMillis int `json:"max_session_millis"`
}

func LoadProfile(path string) (*Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func SaveProfile(path string, p *Profile) error {
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}

func CanonicalHash(p *Profile) (string, error) {
	if p == nil {
		return "", fmt.Errorf("nil profile")
	}
	cp := *p
	cp.GenerationHash = ""
	raw, err := json.Marshal(cp)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func MessageBySemantic(p *Profile, semantic string) (MessageSymbol, bool) {
	for _, msg := range p.Messages {
		if msg.Semantic == semantic {
			return msg, true
		}
	}
	return MessageSymbol{}, false
}

func MessageByWireSymbol(p *Profile, wire string) (MessageSymbol, bool) {
	for _, msg := range p.Messages {
		if msg.WireSymbol == wire {
			return msg, true
		}
	}
	return MessageSymbol{}, false
}

func RelaySemantics() []string {
	return []string{
		SemanticOpenStream,
		SemanticData,
		SemanticClose,
		SemanticResetStream,
		SemanticWindowUpdate,
		SemanticSessionClose,
		SemanticAck,
		SemanticPadding,
		SemanticError,
		SemanticOpenRelay,
		SemanticTargetDescriptor,
		SemanticTargetData,
		SemanticTargetResponse,
		SemanticTargetError,
		SemanticTargetClose,
		SemanticTargetReset,
		SemanticTargetMetadata,
	}
}

func ProxySemantics() []string {
	return []string{
		SemanticOpenRelay,
		SemanticTargetDescriptor,
		SemanticTargetData,
		SemanticTargetResponse,
		SemanticTargetError,
		SemanticTargetClose,
		SemanticTargetReset,
		SemanticTargetMetadata,
	}
}

func SyntheticTargetClasses() []string {
	return []string{
		"echo",
		"discard",
		"fixed_response",
		"slow_response",
		"chunked_response",
		"large_object",
		"error_response",
		"reset_midstream",
		"drip_response",
		"jittery_response",
	}
}

func CarrierFamilies() []string {
	return []string{
		"stream_carrier",
		"message_carrier",
		"datagram_like_carrier",
		"chunked_carrier",
		"batch_carrier",
		"interactive_carrier",
		"long_poll_style_carrier",
		"lossy_reordered_carrier",
	}
}
