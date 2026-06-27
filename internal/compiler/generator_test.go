package compiler

import (
	"reflect"
	"testing"

	"kurdistan/internal/ir"
)

func TestSameSeedProducesSameProfile(t *testing.T) {
	a, err := Generate(99)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(99)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same seed produced different profiles")
	}
}

func TestDifferentSeedsProduceDifferentProfiles(t *testing.T) {
	a, _ := Generate(1)
	b, _ := Generate(2)
	if a.GenerationHash == b.GenerationHash {
		t.Fatal("different seeds produced same profile hash")
	}
}

func TestGeneratedTenProfilesValidate(t *testing.T) {
	for seed := int64(1); seed <= 10; seed++ {
		p, err := Generate(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if err := ir.Validate(p); err != nil {
			t.Fatalf("seed %d failed validation: %v", seed, err)
		}
		if err := ValidateDeterministic(p); err != nil {
			t.Fatalf("seed %d failed deterministic validation: %v", seed, err)
		}
	}
}

func TestGeneratedProfilesVaryPatternsAndFrameGrammars(t *testing.T) {
	patterns := map[string]bool{}
	grammars := map[string]bool{}
	for seed := int64(1); seed <= 20; seed++ {
		p, err := Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		patterns[p.FirstContact.PatternID] = true
		grammars[p.FrameGrammar.LengthMode+"|"+p.FrameGrammar.TypeMode+"|"+p.FrameGrammar.PaddingPlacement] = true
	}
	if len(patterns) < 3 {
		t.Fatalf("expected at least 3 first-contact patterns, got %d", len(patterns))
	}
	if len(grammars) < 3 {
		t.Fatalf("expected at least 3 frame grammar combinations, got %d", len(grammars))
	}
}
