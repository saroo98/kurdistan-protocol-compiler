// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

import (
	"fmt"
	"strings"

	"kurdistan/internal/adapter"
)

const (
	MaxLocalFlows         = 64
	MaxLocalBufferedBytes = 8 * 1024 * 1024
	MaxLocalChunkBytes    = 256 * 1024
	MaxLocalEvents        = 1 << 18
)

type LocalAdapterConfig struct {
	Name              string `json:"name"`
	RuntimeID         string `json:"runtime_id"`
	MaxFlows          int    `json:"max_flows"`
	MaxBufferedBytes  int    `json:"max_buffered_bytes"`
	MaxChunkBytes     int    `json:"max_chunk_bytes"`
	MaxEvents         int    `json:"max_events"`
	TraceEnabled      bool   `json:"trace_enabled"`
	DeterministicSeed uint64 `json:"deterministic_seed"`
}

func DefaultConfig(name string) LocalAdapterConfig {
	if name == "" {
		name = "local-adapter"
	}
	return LocalAdapterConfig{
		Name:              name,
		RuntimeID:         "runtime-local-adapter",
		MaxFlows:          16,
		MaxBufferedBytes:  512 * 1024,
		MaxChunkBytes:     64 * 1024,
		MaxEvents:         4096,
		TraceEnabled:      true,
		DeterministicSeed: 1,
	}
}

func ValidateConfig(cfg LocalAdapterConfig) error {
	if cfg.Name == "" || strings.Contains(strings.ToLower(cfg.Name), "secret") || strings.Contains(strings.ToLower(cfg.Name), "token") {
		return fmt.Errorf("%w: unsafe local adapter name", adapter.ErrInvalidConfig)
	}
	if cfg.RuntimeID == "" {
		return fmt.Errorf("%w: runtime id required", adapter.ErrInvalidConfig)
	}
	if cfg.MaxFlows <= 0 || cfg.MaxFlows > MaxLocalFlows {
		return fmt.Errorf("%w: max flows", adapter.ErrResourceLimit)
	}
	if cfg.MaxBufferedBytes <= 0 || cfg.MaxBufferedBytes > MaxLocalBufferedBytes {
		return fmt.Errorf("%w: max buffered bytes", adapter.ErrResourceLimit)
	}
	if cfg.MaxChunkBytes <= 0 || cfg.MaxChunkBytes > MaxLocalChunkBytes {
		return fmt.Errorf("%w: max chunk bytes", adapter.ErrResourceLimit)
	}
	if cfg.MaxEvents <= 0 || cfg.MaxEvents > MaxLocalEvents {
		return fmt.Errorf("%w: max events", adapter.ErrResourceLimit)
	}
	return nil
}

func AdapterConfig(cfg LocalAdapterConfig, kind adapter.AdapterKind) adapter.AdapterConfig {
	out := adapter.DefaultConfig(cfg.Name, kind)
	out.RuntimeID = cfg.RuntimeID
	out.MaxFlows = cfg.MaxFlows
	out.MaxFlowBytes = cfg.MaxChunkBytes
	out.MaxBufferedBytes = cfg.MaxBufferedBytes
	out.MaxEvents = cfg.MaxEvents
	out.TraceEnabled = cfg.TraceEnabled
	out.Capabilities = adapter.DefaultCapabilityNames()
	return out
}
