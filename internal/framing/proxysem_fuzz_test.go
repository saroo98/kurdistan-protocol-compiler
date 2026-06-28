// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package framing

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func FuzzProxySemanticFrameDecoder(f *testing.F) {
	p, err := compiler.Generate(909)
	if err != nil {
		f.Fatal(err)
	}
	frames, err := EncodeOperation(p, Operation{
		Semantic:      ir.SemanticOpenRelay,
		StreamID:      1,
		RelayIntentID: 1,
		TargetClass:   "echo",
		RequestClass:  "interactive",
		ResponseMode:  "immediate",
	}, 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(frames[0])
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, frame []byte) {
		if len(frame) > p.Limits.MaxFrameBytes+128 {
			frame = frame[:p.Limits.MaxFrameBytes+128]
		}
		_, _ = DecodeFrame(p, frame)
	})
}
