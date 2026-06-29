// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

const (
	MaxAdapterFlows         = 256
	MaxAdapterFlowBytes     = 8 * 1024 * 1024
	MaxAdapterBufferedBytes = 16 * 1024 * 1024
	MaxAdapterEvents        = 1 << 20
)

type AdapterKind string

const (
	AdapterKindIngress AdapterKind = "ingress"
	AdapterKindEgress  AdapterKind = "egress"
	AdapterKindCarrier AdapterKind = "carrier"
)

type FlowID string

type FlowState string

const (
	FlowNew        FlowState = "new"
	FlowOpening    FlowState = "opening"
	FlowOpen       FlowState = "open"
	FlowHalfClosed FlowState = "half_closed"
	FlowDraining   FlowState = "draining"
	FlowClosed     FlowState = "closed"
	FlowReset      FlowState = "reset"
	FlowFailed     FlowState = "failed"
)

type FlowDescriptor struct {
	ID             FlowID `json:"id"`
	Class          string `json:"class"`
	Direction      string `json:"direction"`
	RequestClass   string `json:"request_class"`
	PriorityClass  string `json:"priority_class"`
	TargetHint     string `json:"target_hint,omitempty"`
	MaxReadBytes   int    `json:"max_read_bytes"`
	MaxWriteBytes  int    `json:"max_write_bytes"`
	MetadataPolicy string `json:"metadata_policy"`
}

type AdapterConfig struct {
	Name             string      `json:"name"`
	Kind             AdapterKind `json:"kind"`
	RuntimeID        string      `json:"runtime_id"`
	MaxFlows         int         `json:"max_flows"`
	MaxFlowBytes     int         `json:"max_flow_bytes"`
	MaxBufferedBytes int         `json:"max_buffered_bytes"`
	MaxEvents        int         `json:"max_events"`
	TraceEnabled     bool        `json:"trace_enabled"`
	Capabilities     []string    `json:"capabilities"`
}

type AdapterCapabilities struct {
	SupportsHalfClose     bool `json:"supports_half_close"`
	SupportsReset         bool `json:"supports_reset"`
	SupportsBackpressure  bool `json:"supports_backpressure"`
	SupportsPriorities    bool `json:"supports_priorities"`
	SupportsMetadataOnly  bool `json:"supports_metadata_only"`
	SupportsFlowControl   bool `json:"supports_flow_control"`
	SupportsReplayDefense bool `json:"supports_replay_defense"`
}

type AdapterChunk struct {
	FlowID        FlowID `json:"flow_id"`
	Sequence      uint64 `json:"sequence"`
	ByteCount     int    `json:"byte_count"`
	Final         bool   `json:"final"`
	Reset         bool   `json:"reset"`
	MetadataClass string `json:"metadata_class,omitempty"`
	Backpressure  bool   `json:"backpressure,omitempty"`
}

func DefaultConfig(name string, kind AdapterKind) AdapterConfig {
	return AdapterConfig{
		Name:             name,
		Kind:             kind,
		RuntimeID:        "runtime-local",
		MaxFlows:         16,
		MaxFlowBytes:     2 * 1024 * 1024,
		MaxBufferedBytes: 2 * 1024 * 1024,
		MaxEvents:        4096,
		TraceEnabled:     true,
		Capabilities:     DefaultCapabilityNames(),
	}
}

func DefaultCapabilities() AdapterCapabilities {
	return AdapterCapabilities{
		SupportsHalfClose:     true,
		SupportsReset:         true,
		SupportsBackpressure:  true,
		SupportsPriorities:    true,
		SupportsMetadataOnly:  true,
		SupportsFlowControl:   true,
		SupportsReplayDefense: true,
	}
}
