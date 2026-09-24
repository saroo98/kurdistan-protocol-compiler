// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// LOOM: real — deterministic padding engine; part of the protocol core.
package padding

import (
	"fmt"
	"math/rand"

	"kurdistan/internal/protocol/ir"
)

type Engine struct {
	policy ir.PaddingPolicy
	rng    *rand.Rand
}

func New(policy ir.PaddingPolicy, seed int64) *Engine {
	return &Engine{policy: policy, rng: rand.New(rand.NewSource(seed))}
}

// GenerateInto borrows dst exclusively. Its length must cover the policy's
// maximum before any random draw, even if this draw would select no padding.
func (e *Engine) GenerateInto(dst []byte) (int, error) {
	if e.policy.Mode == "none" {
		return 0, nil
	}
	if e.policy.MinPaddingBytes < 0 || e.policy.MaxPaddingBytes < e.policy.MinPaddingBytes || e.policy.MaxPaddingBytes-e.policy.MinPaddingBytes == int(^uint(0)>>1) {
		return 0, fmt.Errorf("invalid padding bounds")
	}
	if len(dst) < e.policy.MaxPaddingBytes {
		return 0, fmt.Errorf("padding destination too short")
	}
	size, selected, err := e.selectSize()
	if err != nil {
		return 0, err
	}
	if !selected {
		return 0, nil
	}
	e.fill(dst[:size])
	return size, nil
}

// ResetSeed reuses the owned random source. Engine is a single-owner object.
func (e *Engine) ResetSeed(seed int64) { e.rng.Seed(seed) }

func (e *Engine) Generate() ([]byte, error) {
	if e.policy.Mode == "none" {
		return nil, nil
	}
	size, selected, err := e.selectSize()
	if err != nil {
		return nil, err
	}
	if !selected {
		return nil, nil
	}
	out := make([]byte, size)
	e.fill(out)
	return out, nil
}

func (e *Engine) selectSize() (int, bool, error) {
	if e.policy.Mode == "probabilistic" && e.rng.Float64() > e.policy.Probability {
		return 0, false, nil
	}
	if e.policy.MaxPaddingBytes < e.policy.MinPaddingBytes {
		return 0, false, fmt.Errorf("invalid padding bounds")
	}
	size := e.policy.MinPaddingBytes
	if e.policy.MaxPaddingBytes > e.policy.MinPaddingBytes {
		size += e.rng.Intn(e.policy.MaxPaddingBytes - e.policy.MinPaddingBytes + 1)
	}
	return size, true, nil
}

func (e *Engine) fill(out []byte) {
	for i := range out {
		out[i] = byte(e.rng.Intn(256))
	}
}
