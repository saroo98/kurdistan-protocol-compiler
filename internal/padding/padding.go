// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package padding

import (
	"fmt"
	"math/rand"

	"kurdistan/internal/ir"
)

type Engine struct {
	policy ir.PaddingPolicy
	rng    *rand.Rand
}

func New(policy ir.PaddingPolicy, seed int64) *Engine {
	return &Engine{policy: policy, rng: rand.New(rand.NewSource(seed))}
}

func (e *Engine) Generate() ([]byte, error) {
	if e.policy.Mode == "none" {
		return nil, nil
	}
	if e.policy.Mode == "probabilistic" && e.rng.Float64() > e.policy.Probability {
		return nil, nil
	}
	if e.policy.MaxPaddingBytes < e.policy.MinPaddingBytes {
		return nil, fmt.Errorf("invalid padding bounds")
	}
	size := e.policy.MinPaddingBytes
	if e.policy.MaxPaddingBytes > e.policy.MinPaddingBytes {
		size += e.rng.Intn(e.policy.MaxPaddingBytes - e.policy.MinPaddingBytes + 1)
	}
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(e.rng.Intn(256))
	}
	return out, nil
}
