// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrier

import (
	"testing"

	"kurdistan/internal/compiler"
)

func FuzzCarrierEnvelopeDecode(f *testing.F) {
	f.Add("stream_carrier", uint64(1), 32, "data")
	f.Add("bad", uint64(0), -1, "bad")
	f.Fuzz(func(t *testing.T, family string, seq uint64, bytes int, kind string) {
		p, err := compiler.Generate(1)
		if err != nil {
			t.Fatal(err)
		}
		model, err := NewModel(p, p.CarrierPolicy.CarrierFamily)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = model.Decode([]Envelope{{
			CarrierFamily: family,
			Sequence:      seq,
			Kind:          kind,
			MessageCount:  1,
			ByteCount:     bytes,
			Messages:      []SemanticMessage{{StreamID: 1, Semantic: "data", ByteCount: max(0, min(bytes, 1024)), OriginalIndex: 1}},
		}})
	})
}
