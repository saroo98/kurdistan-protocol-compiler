// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
)

func TestAdapterBoundaryFlowMappingAndHygiene(t *testing.T) {
	p, err := compiler.Generate(15001)
	if err != nil {
		t.Fatal(err)
	}
	result, err := RunAdapterBoundary(context.Background(), p, AdapterBoundaryOptions{Scenario: "test", FlowCount: 3, BytesPerFlow: 128})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.FlowsOpened != 3 || result.Summary.RuntimeStreamsOpened != 3 {
		t.Fatalf("flow/runtime mapping mismatch: %+v", result.Summary)
	}
	if result.Summary.PayloadLogged || result.Summary.SecretLogged || len(result.Events) == 0 {
		t.Fatalf("unsafe or missing adapter trace summary: %+v", result.Summary)
	}
}

func TestAdapterBoundaryBackpressureResetAndFailure(t *testing.T) {
	p, err := compiler.Generate(15002)
	if err != nil {
		t.Fatal(err)
	}
	result, err := RunAdapterBoundary(context.Background(), p, AdapterBoundaryOptions{Scenario: "pressure", FlowCount: 3, BytesPerFlow: 4096, Backpressure: true, ResetFlow: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.BackpressureEvents == 0 || result.Summary.FlowsReset == 0 {
		t.Fatalf("expected backpressure and reset: %+v", result.Summary)
	}
	if _, err := RunAdapterBoundary(context.Background(), p, AdapterBoundaryOptions{CapabilityDowngrade: true}); err == nil {
		t.Fatalf("capability downgrade accepted")
	}
	if _, err := RunAdapterBoundary(context.Background(), p, AdapterBoundaryOptions{MalformedFlow: true}); err == nil {
		t.Fatalf("malformed flow accepted")
	}
}
