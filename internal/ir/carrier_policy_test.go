// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package ir_test

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func TestCarrierPolicyValidation(t *testing.T) {
	p, err := compiler.Generate(11031)
	if err != nil {
		t.Fatal(err)
	}
	if p.CarrierPolicy.CarrierFamily == "" || p.CarrierPolicy.MaxEnvelopeBytes == 0 {
		t.Fatalf("carrier policy not generated: %+v", p.CarrierPolicy)
	}
	if err := ir.Validate(p); err != nil {
		t.Fatal(err)
	}
	bad := *p
	bad.GenerationHash = ""
	bad.CarrierPolicy.CarrierFamily = "real_external_carrier"
	if err := ir.Validate(&bad); err == nil {
		t.Fatalf("invalid carrier family accepted")
	}
	bad = *p
	bad.GenerationHash = ""
	bad.CarrierPolicy.MaxEnvelopeBytes = p.Limits.MaxFrameBytes + 1
	if err := ir.Validate(&bad); err == nil {
		t.Fatalf("carrier envelope exceeding frame limit accepted")
	}
}
