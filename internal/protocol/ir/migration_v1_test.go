package ir_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

var _ func([]byte) (*ir.Profile, error) = ir.DecodeProfileV1
var _ func([]byte) (*ir.Profile, error) = ir.DecodeLegacyProfileForMigrationV1

func profileFixture(t *testing.T, legacy bool) *ir.Profile {
	t.Helper()
	p, err := compiler.Generate(38001)
	if err != nil {
		t.Fatal(err)
	}
	if legacy {
		p.Version = ir.LegacySchemaVersionV1
		p.Compatibility.SchemaVersion = ir.LegacySchemaVersionV1
		p.Security.SecurityVersion = ir.LegacySecurityVersionV1
		p.Compatibility.CompilerSecurityVersion = ir.LegacySecurityVersionV1
		p.Compatibility.MinimumRuntimeVersion = ir.LegacySecurityVersionV1
	}
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func rawProfile(t *testing.T, p *ir.Profile) []byte {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProfileDecodeV1AndMigrationRequired(t *testing.T) {
	p := profileFixture(t, false)
	got, err := ir.DecodeProfileV1(rawProfile(t, p))
	if err != nil || got == p || got.ID != p.ID {
		t.Fatalf("decode got=%v err=%v", got, err)
	}
	got.ID = "owned"
	if p.ID == got.ID {
		t.Fatal("decoder aliased input")
	}
	if _, err := ir.DecodeProfileV1(rawProfile(t, profileFixture(t, true))); !errors.Is(err, ir.ErrMigrationRequired) || err.Error() != ir.ErrMigrationRequired.Error() {
		t.Fatalf("legacy err=%v", err)
	}
}

func TestProfileDecodeV1InclusiveBoundaryAndMismatchSentinel(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		p := profileFixture(t, legacy)
		raw := rawProfile(t, p)
		raw = append(raw, bytes.Repeat([]byte(" "), (1<<20)-len(raw))...)
		if len(raw) != 1<<20 {
			t.Fatal("boundary construction")
		}
		if legacy {
			if _, err := ir.DecodeLegacyProfileForMigrationV1(raw); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := ir.DecodeProfileV1(raw); err != nil {
				t.Fatal(err)
			}
		}
		raw = append(raw, ' ')
		var err error
		if legacy {
			_, err = ir.DecodeLegacyProfileForMigrationV1(raw)
		} else {
			_, err = ir.DecodeProfileV1(raw)
		}
		if !errors.Is(err, ir.ErrProfileMalformed) || err.Error() != ir.ErrProfileMalformed.Error() {
			t.Fatal(err)
		}
	}
	if ir.ErrProfileMismatch.Error() != "profile mismatch" || !errors.Is(ir.ErrProfileMismatch, ir.ErrProfileMismatch) {
		t.Fatal("profile mismatch sentinel identity")
	}
}

func decodeExpectedProfileV1ForTest(raw []byte, expectedID, expectedHash string) (*ir.Profile, error) {
	p, err := ir.DecodeProfileV1(raw)
	if err != nil {
		return nil, err
	}
	if p.ID != expectedID || p.GenerationHash != expectedHash {
		return nil, ir.ErrProfileMismatch
	}
	return p, nil
}

func TestProfileDecodeV1PostDecodeExpectedMismatch(t *testing.T) {
	p := profileFixture(t, false)
	raw := rawProfile(t, p)
	if _, err := decodeExpectedProfileV1ForTest(raw, p.ID, p.GenerationHash); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"wrong", p.GenerationHash}, {p.ID, strings.Repeat("0", 64)}} {
		got, err := decodeExpectedProfileV1ForTest(raw, pair[0], pair[1])
		if got != nil || !errors.Is(err, ir.ErrProfileMismatch) || err.Error() != ir.ErrProfileMismatch.Error() {
			t.Fatalf("got=%v err=%v", got, err)
		}
	}
}

func TestProfileDecodeV1StrictClasses(t *testing.T) {
	current := profileFixture(t, false)
	valid := string(rawProfile(t, current))
	badSemantic := *current
	badSemantic.ID = ""
	badSemantic.GenerationHash = ""
	mixed := profileFixture(t, true)
	mixed.Version = ir.SupportedVersion
	future := profileFixture(t, false)
	future.Version = "99.0.0"
	cases := []struct {
		name, raw string
		want      error
	}{
		{"empty", "", ir.ErrProfileMalformed}, {"null", "null", ir.ErrProfileMalformed},
		{"trailing", valid + " {}", ir.ErrProfileMalformed},
		{"duplicate", strings.Replace(valid, "{", `{"version":"x",`, 1), ir.ErrProfileMalformed},
		{"unknown", strings.Replace(valid, "{", `{"unknown":1,`, 1), ir.ErrProfileMalformed},
		{"missing-version", strings.Replace(valid, `"version":"`+ir.SupportedVersion+`",`, "", 1), ir.ErrProfileMalformed},
		{"mixed", string(rawProfile(t, mixed)), ir.ErrProfileVersionMismatch},
		{"future", string(rawProfile(t, future)), ir.ErrProfileVersionUnsupported},
		{"invalid", string(rawProfile(t, &badSemantic)), ir.ErrProfileInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ir.DecodeProfileV1([]byte(tc.raw))
			if !errors.Is(err, tc.want) || err.Error() != tc.want.Error() {
				t.Fatalf("err=%v want=%v", err, tc.want)
			}
		})
	}
	if _, err := ir.DecodeProfileV1(make([]byte, (1<<20)+1)); !errors.Is(err, ir.ErrProfileMalformed) {
		t.Fatal(err)
	}
}

func TestLegacyBodyAndVersionTuple(t *testing.T) {
	legacy := profileFixture(t, true)
	got, err := ir.DecodeLegacyProfileForMigrationV1(rawProfile(t, legacy))
	if err != nil || got.Version != ir.LegacySchemaVersionV1 {
		t.Fatal(err)
	}
	got.ID = "owned"
	if legacy.ID == got.ID {
		t.Fatal("legacy decoder aliased")
	}
	legacy.GenerationHash = "bad"
	if _, err := ir.DecodeLegacyProfileForMigrationV1(rawProfile(t, legacy)); !errors.Is(err, ir.ErrProfileInvalid) {
		t.Fatal(err)
	}
	current := profileFixture(t, false)
	fields := []func(*ir.Profile){func(p *ir.Profile) { p.Version = "x" }, func(p *ir.Profile) { p.Compatibility.SchemaVersion = "x" }, func(p *ir.Profile) { p.Security.SecurityVersion = "x" }, func(p *ir.Profile) { p.Compatibility.CompilerSecurityVersion = "x" }, func(p *ir.Profile) { p.Compatibility.MinimumRuntimeVersion = "x" }}
	for _, mutate := range fields {
		copy := *current
		mutate(&copy)
		if ir.Validate(&copy) == nil {
			t.Fatal("Validate accepted tuple mismatch")
		}
	}
}

func TestLegacyBodyDecoderFullPrecedence(t *testing.T) {
	legacy := profileFixture(t, true)
	current := profileFixture(t, false)
	mixed := profileFixture(t, true)
	mixed.Version = ir.SupportedVersion
	future := profileFixture(t, true)
	future.Version = "99.0.0"
	future.Compatibility.SchemaVersion = "99.0.0"
	future.Security.SecurityVersion = "99.0.0"
	future.Compatibility.CompilerSecurityVersion = "99.0.0"
	future.Compatibility.MinimumRuntimeVersion = "99.0.0"
	invalid := profileFixture(t, true)
	invalid.GenerationHash = "bad"
	cases := []struct {
		name string
		raw  []byte
		want error
	}{{"empty", nil, ir.ErrProfileMalformed}, {"null", []byte("null"), ir.ErrProfileMalformed}, {"trailing", append(rawProfile(t, legacy), []byte(" {}")...), ir.ErrProfileMalformed}, {"duplicate", []byte(strings.Replace(string(rawProfile(t, legacy)), "{", `{"version":"x",`, 1)), ir.ErrProfileMalformed}, {"unknown", []byte(strings.Replace(string(rawProfile(t, legacy)), "{", `{"unknown":1,`, 1)), ir.ErrProfileMalformed}, {"missing-version", []byte(strings.Replace(string(rawProfile(t, legacy)), `"version":"`+ir.LegacySchemaVersionV1+`",`, "", 1)), ir.ErrProfileMalformed}, {"current", rawProfile(t, current), ir.ErrMigrationRequired}, {"mixed", rawProfile(t, mixed), ir.ErrProfileVersionMismatch}, {"future", rawProfile(t, future), ir.ErrProfileVersionUnsupported}, {"invalid", rawProfile(t, invalid), ir.ErrProfileInvalid}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ir.DecodeLegacyProfileForMigrationV1(tc.raw)
			if got != nil || !errors.Is(err, tc.want) || err.Error() != tc.want.Error() {
				t.Fatalf("got=%v err=%v want=%v", got, err, tc.want)
			}
		})
	}
}
