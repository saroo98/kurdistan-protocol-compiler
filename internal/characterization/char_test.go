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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/protocol/ir"
)

var update = flag.Bool("update", false, "rewrite the characterization golden")

const seedCount = 50

type charEntry struct {
	Seed                       int64  `json:"seed"`
	ID                         string `json:"id"`
	Hash                       string `json:"hash"`
	ProfileVersion             string `json:"profile_version"`
	SecurityVersion            string `json:"security_version"`
	CompatibilitySchemaVersion string `json:"compatibility_schema_version"`
	CompilerSecurityVersion    string `json:"compiler_security_version"`
	MinimumRuntimeVersion      string `json:"minimum_runtime_version"`
	HandshakeVersion           string `json:"handshake_version"`
	PolicyEncodingVersion      string `json:"policy_encoding_version"`
	RecordVersion              string `json:"record_version"`
	FirstFrameLen              int    `json:"first_frame_len"`
	FrameCount                 int    `json:"frame_count"`
}

func validateCharacterizationVersionEvidenceV1(entry charEntry) error {
	want := map[string][2]string{
		"profile_version":              {entry.ProfileVersion, ir.SupportedVersion},
		"security_version":             {entry.SecurityVersion, ir.SupportedSecurityVersion},
		"compatibility_schema_version": {entry.CompatibilitySchemaVersion, ir.SupportedVersion},
		"compiler_security_version":    {entry.CompilerSecurityVersion, ir.SupportedSecurityVersion},
		"minimum_runtime_version":      {entry.MinimumRuntimeVersion, ir.SupportedSecurityVersion},
		"handshake_version":            {entry.HandshakeVersion, security.HandshakeVersionV1},
		"policy_encoding_version":      {entry.PolicyEncodingVersion, security.PolicyEncodingVersionV1},
		"record_version":               {entry.RecordVersion, security.RecordVersionV1},
	}
	for field, pair := range want {
		if pair[0] == "" || pair[0] != pair[1] {
			return fmt.Errorf("%s=%q want=%q", field, pair[0], pair[1])
		}
	}
	return nil
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
			Seed:                       seed,
			ID:                         p.ID,
			Hash:                       hash,
			ProfileVersion:             p.Version,
			SecurityVersion:            p.Security.SecurityVersion,
			CompatibilitySchemaVersion: p.Compatibility.SchemaVersion,
			CompilerSecurityVersion:    p.Compatibility.CompilerSecurityVersion,
			MinimumRuntimeVersion:      p.Compatibility.MinimumRuntimeVersion,
			HandshakeVersion:           security.HandshakeVersionV1,
			PolicyEncodingVersion:      security.PolicyEncodingVersionV1,
			RecordVersion:              security.RecordVersionV1,
			FirstFrameLen:              len(frames[0]),
			FrameCount:                 len(frames),
		})
		if err := validateCharacterizationVersionEvidenceV1(out[len(out)-1]); err != nil {
			t.Fatalf("seed %d version evidence: %v", seed, err)
		}
	}
	return out
}

func TestCharacterizationVersionObservabilityV1(t *testing.T) {
	if ir.LegacySchemaVersionV1 != "0.1.0-lab" || ir.NextSchemaVersionV1 != "0.2.0-lab" ||
		ir.LegacySecurityVersionV1 != "0.12.0-lab" || ir.NextSecurityVersionV1 != "0.13.0-lab" ||
		ir.SupportedVersion != ir.NextSchemaVersionV1 || ir.SupportedSecurityVersion != ir.NextSecurityVersionV1 ||
		ir.SupportedVersion == ir.LegacySchemaVersionV1 || ir.SupportedSecurityVersion == ir.LegacySecurityVersionV1 {
		t.Fatal("dormant-versus-active version authority drifted")
	}
	base := computeBaseline(t)[0]
	mutations := []struct {
		name string
		set  func(*charEntry, string)
	}{
		{"profile_version", func(v *charEntry, s string) { v.ProfileVersion = s }},
		{"security_version", func(v *charEntry, s string) { v.SecurityVersion = s }},
		{"compatibility_schema_version", func(v *charEntry, s string) { v.CompatibilitySchemaVersion = s }},
		{"compiler_security_version", func(v *charEntry, s string) { v.CompilerSecurityVersion = s }},
		{"minimum_runtime_version", func(v *charEntry, s string) { v.MinimumRuntimeVersion = s }},
		{"handshake_version", func(v *charEntry, s string) { v.HandshakeVersion = s }},
		{"policy_encoding_version", func(v *charEntry, s string) { v.PolicyEncodingVersion = s }},
		{"record_version", func(v *charEntry, s string) { v.RecordVersion = s }},
	}
	for _, mutation := range mutations {
		for _, value := range []string{"", "altered"} {
			changed := base
			mutation.set(&changed, value)
			if err := validateCharacterizationVersionEvidenceV1(changed); err == nil {
				t.Fatalf("%s accepted mutation %q", mutation.name, value)
			}
		}
	}
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
