// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

import (
	"fmt"

	"kurdistan/internal/adapter"
)

const (
	SourceSmallBurst  = "small_burst_source"
	SourceLargeObject = "large_object_source"
	SourceSlowDrip    = "slow_drip_source"
	SourceMixedFlow   = "mixed_flow_source"
	SourceResetting   = "resetting_source"
	SourceHalfClose   = "half_close_source"
)

type LocalSourceChunk struct {
	FlowID        adapter.FlowID `json:"flow_id"`
	Sequence      uint64         `json:"sequence"`
	Data          []byte         `json:"-"`
	ByteCount     int            `json:"byte_count"`
	Final         bool           `json:"final"`
	Reset         bool           `json:"reset"`
	MetadataClass string         `json:"metadata_class"`
	Tick          int            `json:"tick"`
}

type SourcePlan struct {
	Model  string             `json:"model"`
	Chunks []LocalSourceChunk `json:"chunks"`
}

func GenerateSourcePlan(model string, flows int, cfg LocalAdapterConfig) (SourcePlan, error) {
	if err := ValidateConfig(cfg); err != nil {
		return SourcePlan{}, err
	}
	if flows <= 0 {
		flows = 1
	}
	if flows > cfg.MaxFlows {
		return SourcePlan{}, fmt.Errorf("%w: source flows", adapter.ErrResourceLimit)
	}
	plan := SourcePlan{Model: model}
	seq := uint64(0)
	add := func(flow int, bytes int, final, reset bool, tick int, class string) error {
		if bytes < 0 || bytes > cfg.MaxChunkBytes {
			return fmt.Errorf("%w: chunk size", ErrInvalidSourceChunk)
		}
		seq++
		chunk := LocalSourceChunk{
			FlowID:        adapter.FlowID(fmt.Sprintf("local-flow-%02d", flow)),
			Sequence:      seq,
			ByteCount:     bytes,
			Final:         final,
			Reset:         reset,
			MetadataClass: class,
			Tick:          tick,
		}
		if bytes > 0 {
			chunk.Data = deterministicBytes(cfg.DeterministicSeed+uint64(flow), bytes)
		}
		plan.Chunks = append(plan.Chunks, chunk)
		return nil
	}
	switch model {
	case SourceSmallBurst:
		for i := 1; i <= flows; i++ {
			if err := add(i, 64+int((cfg.DeterministicSeed+uint64(i))%32), true, false, i, "interactive"); err != nil {
				return SourcePlan{}, err
			}
		}
	case SourceLargeObject:
		for i := 0; i < 4; i++ {
			if err := add(1, cfg.MaxChunkBytes/2, i == 3, false, i, "bulk"); err != nil {
				return SourcePlan{}, err
			}
		}
	case SourceSlowDrip:
		for i := 0; i < 12; i++ {
			if err := add(1, 24+int((cfg.DeterministicSeed+uint64(i))%8), i == 11, false, i*2, "drip"); err != nil {
				return SourcePlan{}, err
			}
		}
	case SourceMixedFlow:
		for i := 1; i <= flows; i++ {
			bytes := 96
			class := "interactive"
			reset := false
			if i == 1 {
				bytes = cfg.MaxChunkBytes / 2
				class = "bulk"
			}
			if i == flows && flows > 2 {
				reset = true
			}
			if err := add(i, bytes, !reset, reset, i, class); err != nil {
				return SourcePlan{}, err
			}
		}
	case SourceResetting:
		if err := add(1, 128, false, false, 0, "partial"); err != nil {
			return SourcePlan{}, err
		}
		if err := add(1, 0, false, true, 1, "reset"); err != nil {
			return SourcePlan{}, err
		}
	case SourceHalfClose:
		if err := add(1, 128, true, false, 0, "half_close"); err != nil {
			return SourcePlan{}, err
		}
	default:
		return SourcePlan{}, fmt.Errorf("%w: unknown source model", adapter.ErrInvalidConfig)
	}
	return plan, nil
}

func deterministicBytes(seed uint64, n int) []byte {
	out := make([]byte, n)
	x := seed*1664525 + 1013904223
	for i := range out {
		x = x*1664525 + 1013904223
		out[i] = byte(x >> 24)
	}
	return out
}

func ValidateSourceChunk(chunk LocalSourceChunk, cfg LocalAdapterConfig) error {
	if chunk.FlowID == "" || chunk.Sequence == 0 {
		return fmt.Errorf("%w: id/sequence", ErrInvalidSourceChunk)
	}
	if chunk.ByteCount < 0 || chunk.ByteCount > cfg.MaxChunkBytes {
		return fmt.Errorf("%w: byte count", ErrInvalidSourceChunk)
	}
	if len(chunk.Data) > 0 && len(chunk.Data) != chunk.ByteCount {
		return fmt.Errorf("%w: data length", ErrInvalidSourceChunk)
	}
	return nil
}
