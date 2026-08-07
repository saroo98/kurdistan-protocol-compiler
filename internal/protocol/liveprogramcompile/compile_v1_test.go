// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package liveprogramcompile

import (
	"bytes"
	"strconv"
	"testing"

	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
)

func TestCompileV1ProjectsOnlyProductSafeValues(t *testing.T) {
	profile, err := compiler.Generate(27)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := ir.SecurityCapabilities()
	program, err := CompileV1(InputV1{Profile: profile, ClientMandatoryFeatures: capabilities[:2], RelayMandatoryFeatures: capabilities[:2], SelectedFeatures: capabilities})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := liveprogram.EncodeV1(program)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte(profile.ID), []byte(strconv.FormatInt(profile.Seed, 10)), []byte("lab_tcp"), []byte("hmac-sha256-transcript-test-only"), []byte("test-only-"), []byte(profile.Auth.TestKeyHex)} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatal("compiled live program contains prohibited source state")
		}
	}
	if err := liveprogram.ValidateV1(program); err != nil {
		t.Fatal(err)
	}
}

func TestCompileV1RejectsNilAndGenerationHashDrift(t *testing.T) {
	if _, err := CompileV1(InputV1{}); err == nil {
		t.Fatal("nil profile accepted")
	}
	profile, err := compiler.Generate(28)
	if err != nil {
		t.Fatal(err)
	}
	profile.GenerationHash = "00"
	if _, err := CompileV1(InputV1{Profile: profile, ClientMandatoryFeatures: []string{"multi_stream"}, RelayMandatoryFeatures: []string{"multi_stream"}, SelectedFeatures: []string{"multi_stream"}}); err == nil {
		t.Fatal("generation hash drift accepted")
	}
}
