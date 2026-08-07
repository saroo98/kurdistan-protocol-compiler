// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package ir_test

import (
	"encoding/hex"
	"testing"

	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
)

func TestBuildEffectiveSecurityPolicyFromProjectionV1BindsProgramIdentity(t *testing.T) {
	profile, err := compiler.Generate(41)
	if err != nil {
		t.Fatal(err)
	}
	var source [32]byte
	raw, err := hex.DecodeString(profile.GenerationHash)
	if err != nil {
		t.Fatal(err)
	}
	copy(source[:], raw)
	programID := liveprogram.DeriveProgramIDV1(source)
	capabilities := ir.SecurityCapabilities()
	got, err := ir.BuildEffectiveSecurityPolicyFromProjectionV1(programID, source, profile.Compatibility.CompilerSecurityVersion, profile.Compatibility.MinimumRuntimeVersion, profile.Security, capabilities[:2], capabilities[:2], capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if err := ir.ValidateEffectiveSecurityPolicy(got); err != nil {
		t.Fatal(err)
	}
	if got.ProfileID == profile.ID || got.ProfileHash != profile.GenerationHash || got.CompilerSecurityVersion != profile.Compatibility.CompilerSecurityVersion {
		t.Fatal("projection reconstruction did not bind the product-safe identity")
	}
}

func TestBuildEffectiveSecurityPolicyFromProjectionV1RejectsUnsafeInputs(t *testing.T) {
	var source [32]byte
	var id [16]byte
	if _, err := ir.BuildEffectiveSecurityPolicyFromProjectionV1(id, source, "", "", ir.SecurityPolicy{}, nil, nil, nil); err == nil {
		t.Fatal("unsafe projection accepted")
	}
}
