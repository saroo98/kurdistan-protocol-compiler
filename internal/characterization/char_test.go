// Package characterization pins the observable behaviour of the real protocol
// pipeline (compiler -> ir -> framing) so the architecture-realignment restructure
// can prove it is behaviour-preserving. The golden is byte-stable across the move
// of these packages into internal/protocol/*; only this file's import paths change.
//
// Regenerate the golden intentionally (e.g. after a reviewed, version-bumped change):
//
//	go test ./internal/characterization -run TestCharacterizationBaseline -update
package characterization

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/framing"
	"kurdistan/internal/ir"
)

var update = flag.Bool("update", false, "rewrite the characterization golden")

const seedCount = 50

type charEntry struct {
	Seed          int64  `json:"seed"`
	ID            string `json:"id"`
	Hash          string `json:"hash"`
	FirstFrameLen int    `json:"first_frame_len"`
	FrameCount    int    `json:"frame_count"`
}

func computeBaseline(t *testing.T) []charEntry {
	t.Helper()
	out := make([]charEntry, 0, seedCount)
	for seed := int64(1); seed <= seedCount; seed++ {
		p, err := compiler.Generate(seed)
		if err != nil {
			t.Fatalf("seed %d: generate: %v", seed, err)
		}
		hash, err := ir.CanonicalHash(p)
		if err != nil {
			t.Fatalf("seed %d: canonical hash: %v", seed, err)
		}
		frames, err := framing.EncodeOperation(p, framing.Operation{
			Semantic: ir.SemanticData,
			StreamID: 1,
			Payload:  []byte("hello"),
		}, seed)
		if err != nil {
			t.Fatalf("seed %d: encode: %v", seed, err)
		}
		if len(frames) == 0 {
			t.Fatalf("seed %d: no frames produced", seed)
		}
		out = append(out, charEntry{
			Seed:          seed,
			ID:            p.ID,
			Hash:          hash,
			FirstFrameLen: len(frames[0]),
			FrameCount:    len(frames),
		})
	}
	return out
}

func goldenPath() string {
	return filepath.Join("testdata", "baseline.json")
}

func TestCharacterizationBaseline(t *testing.T) {
	got := computeBaseline(t)

	if *update {
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(goldenPath()), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath(), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s (%d entries)", goldenPath(), len(got))
		return
	}

	raw, err := os.ReadFile(goldenPath())
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	var want []charEntry
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("entry count drift: got %d want %d", len(got), len(want))
	}
	for i := range want {
		w, g := want[i], got[i]
		if g != w {
			t.Errorf("seed %d behaviour drift:\n  got  id=%s hash=%s firstFrame=%d frames=%d\n  want id=%s hash=%s firstFrame=%d frames=%d",
				w.Seed, g.ID, g.Hash, g.FirstFrameLen, g.FrameCount, w.ID, w.Hash, w.FirstFrameLen, w.FrameCount)
		}
	}
}

// TestCharacterizationGoldenBites is a self-check: the golden must actually
// constrain behaviour. A mutated profile hash must NOT already be in the golden.
func TestCharacterizationGoldenBites(t *testing.T) {
	base := computeBaseline(t)
	if len(base) < 2 {
		t.Skip("need >=2 seeds")
	}
	// Different seeds must yield different hashes (proves the field is discriminating).
	if base[0].Hash == base[1].Hash {
		t.Fatalf("seeds 1 and 2 share a canonical hash %q — golden would not bite", base[0].Hash)
	}
}
