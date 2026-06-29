// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import (
	"fmt"
	"strings"
)

const (
	MaxTransportFrameBytes      = 256 * 1024
	MaxTransportPayloadBytes    = 128 * 1024
	MaxTransportBufferedBytes   = 4 * 1024 * 1024
	MaxTransportFragments       = 64
	MaxTransportReassemblyBytes = 4 * 1024 * 1024
	MaxTransportPipeQueueDepth  = 1024
	MaxTransportEvents          = 1 << 18
)

type ByteTransportConfig struct {
	Name               string `json:"name"`
	RuntimeID          string `json:"runtime_id"`
	MaxFrameBytes      int    `json:"max_frame_bytes"`
	MaxPayloadBytes    int    `json:"max_payload_bytes"`
	MaxBufferedBytes   int    `json:"max_buffered_bytes"`
	MaxFragments       int    `json:"max_fragments"`
	MaxReassemblyBytes int    `json:"max_reassembly_bytes"`
	MaxPipeQueueDepth  int    `json:"max_pipe_queue_depth"`
	MaxEvents          int    `json:"max_events"`
	TraceEnabled       bool   `json:"trace_enabled"`
	DeterministicSeed  uint64 `json:"deterministic_seed"`
	AllowOutOfOrder    bool   `json:"allow_out_of_order"`
}

func DefaultConfig(name string) ByteTransportConfig {
	if name == "" {
		name = "byte-transport"
	}
	return ByteTransportConfig{
		Name:               name,
		RuntimeID:          "runtime-byte-transport",
		MaxFrameBytes:      64 * 1024,
		MaxPayloadBytes:    16 * 1024,
		MaxBufferedBytes:   512 * 1024,
		MaxFragments:       16,
		MaxReassemblyBytes: 512 * 1024,
		MaxPipeQueueDepth:  64,
		MaxEvents:          4096,
		TraceEnabled:       true,
		DeterministicSeed:  1,
	}
}

func ValidateConfig(cfg ByteTransportConfig) error {
	if cfg.Name == "" || strings.Contains(strings.ToLower(cfg.Name), "secret") || strings.Contains(strings.ToLower(cfg.Name), "token") {
		return fmt.Errorf("%w: name", ErrInvalidConfig)
	}
	if cfg.RuntimeID == "" {
		return fmt.Errorf("%w: runtime id", ErrInvalidConfig)
	}
	if cfg.MaxFrameBytes <= 0 || cfg.MaxFrameBytes > MaxTransportFrameBytes {
		return fmt.Errorf("%w: max frame bytes", ErrInvalidConfig)
	}
	if cfg.MaxPayloadBytes <= 0 || cfg.MaxPayloadBytes > MaxTransportPayloadBytes || cfg.MaxPayloadBytes > cfg.MaxFrameBytes {
		return fmt.Errorf("%w: max payload bytes", ErrInvalidConfig)
	}
	if cfg.MaxBufferedBytes <= 0 || cfg.MaxBufferedBytes > MaxTransportBufferedBytes {
		return fmt.Errorf("%w: max buffered bytes", ErrInvalidConfig)
	}
	if cfg.MaxFragments <= 0 || cfg.MaxFragments > MaxTransportFragments {
		return fmt.Errorf("%w: max fragments", ErrInvalidConfig)
	}
	if cfg.MaxReassemblyBytes <= 0 || cfg.MaxReassemblyBytes > MaxTransportReassemblyBytes {
		return fmt.Errorf("%w: max reassembly bytes", ErrInvalidConfig)
	}
	if cfg.MaxPipeQueueDepth <= 0 || cfg.MaxPipeQueueDepth > MaxTransportPipeQueueDepth {
		return fmt.Errorf("%w: max pipe queue depth", ErrInvalidConfig)
	}
	if cfg.MaxEvents <= 0 || cfg.MaxEvents > MaxTransportEvents {
		return fmt.Errorf("%w: max events", ErrInvalidConfig)
	}
	return nil
}
