package ir_test

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func TestValidateGoodGeneratedProfile(t *testing.T) {
	p, err := compiler.Generate(12345)
	if err != nil {
		t.Fatal(err)
	}
	if err := ir.Validate(p); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsInvalidStateReference(t *testing.T) {
	p, _ := compiler.Generate(1)
	p.GenerationHash = ""
	p.Transitions[0].To = "missing"
	if err := ir.Validate(p); err == nil {
		t.Fatal("expected invalid state reference to fail")
	}
}

func TestValidateRejectsDuplicateWireSymbols(t *testing.T) {
	p, _ := compiler.Generate(1)
	p.GenerationHash = ""
	p.Messages[1].WireSymbol = p.Messages[0].WireSymbol
	if err := ir.Validate(p); err == nil {
		t.Fatal("expected duplicate wire symbol to fail")
	}
}

func TestValidateRejectsInvalidPaddingBounds(t *testing.T) {
	p, _ := compiler.Generate(1)
	p.GenerationHash = ""
	p.Padding.MinPaddingBytes = 10
	p.Padding.MaxPaddingBytes = 1
	if err := ir.Validate(p); err == nil {
		t.Fatal("expected invalid padding bounds to fail")
	}
}

func TestValidateRejectsInvalidSchedulerBounds(t *testing.T) {
	p, _ := compiler.Generate(1)
	p.GenerationHash = ""
	p.Scheduler.MaxBatchBytes = 0
	if err := ir.Validate(p); err == nil {
		t.Fatal("expected invalid scheduler bounds to fail")
	}
}
