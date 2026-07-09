package padding

import (
	"bytes"
	"testing"

	"kurdistan/internal/ir"
)

func TestNoPaddingMode(t *testing.T) {
	got, err := New(ir.PaddingPolicy{Mode: "none"}, 1).Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("expected no padding")
	}
}

func TestBoundedPaddingMode(t *testing.T) {
	engine := New(ir.PaddingPolicy{Mode: "bounded", MinPaddingBytes: 2, MaxPaddingBytes: 8, Probability: 1}, 1)
	for i := 0; i < 100; i++ {
		got, err := engine.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) < 2 || len(got) > 8 {
			t.Fatalf("padding size out of bounds: %d", len(got))
		}
	}
}

func TestProbabilisticPaddingMode(t *testing.T) {
	engine := New(ir.PaddingPolicy{Mode: "probabilistic", MinPaddingBytes: 1, MaxPaddingBytes: 4, Probability: 0.5}, 1)
	selected, skipped := false, false
	for i := 0; i < 100; i++ {
		got, err := engine.Generate()
		if err != nil {
			t.Fatal(err)
		}
		selected = selected || len(got) > 0
		skipped = skipped || len(got) == 0
	}
	if !selected || !skipped {
		t.Fatal("expected probabilistic padding to both select and skip")
	}
}

func TestDeterministicWithSeed(t *testing.T) {
	policy := ir.PaddingPolicy{Mode: "bounded", MinPaddingBytes: 1, MaxPaddingBytes: 8, Probability: 1}
	a, _ := New(policy, 99).Generate()
	b, _ := New(policy, 99).Generate()
	if !bytes.Equal(a, b) {
		t.Fatal("same seed produced different padding")
	}
}
