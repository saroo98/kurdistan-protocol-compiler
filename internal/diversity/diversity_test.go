package diversity

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func TestAnalyzeProfilesReportsCorpusDiversity(t *testing.T) {
	profiles, err := GenerateProfiles(1, 40)
	if err != nil {
		t.Fatal(err)
	}
	report := AnalyzeProfiles(profiles)
	if report.ProfileCount != 40 {
		t.Fatalf("profile count = %d", report.ProfileCount)
	}
	if report.UniqueFirstContactPatterns < 3 {
		t.Fatalf("expected multiple first-contact patterns, got %d", report.UniqueFirstContactPatterns)
	}
	if report.UniqueFrameGrammarCombinations < 3 {
		t.Fatalf("expected multiple frame grammars, got %d", report.UniqueFrameGrammarCombinations)
	}
	if report.UniqueSchedulerCombinations < 3 {
		t.Fatalf("expected multiple scheduler combinations, got %d", report.UniqueSchedulerCombinations)
	}
	if report.UniquePaddingCombinations < 3 {
		t.Fatalf("expected multiple padding combinations, got %d", report.UniquePaddingCombinations)
	}
	if report.UniqueInvalidInputPolicyCombinations < 3 {
		t.Fatalf("expected multiple invalid-input combinations, got %d", report.UniqueInvalidInputPolicyCombinations)
	}
}

func TestCompareProfileStructureClassifiesStructuralDifference(t *testing.T) {
	a, _ := compiler.Generate(1)
	b, _ := compiler.Generate(2)
	report := CompareProfileStructure(a, b)
	if report.Classification != ClassStructurallyDifferent {
		t.Fatalf("classification = %q, want structural", report.Classification)
	}
}

func TestCompareProfileStructureClassifiesCosmeticOnlyDifference(t *testing.T) {
	a, _ := compiler.Generate(1)
	b := *a
	b.ID = "kp_cosmetic_only"
	b.Seed = 999
	b.GenerationHash = "different"
	b.Auth.KeyID = "test-only-cosmetic"
	b.Auth.TestKeyHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b.Messages = append([]ir.MessageSymbol(nil), a.Messages...)
	for i := range b.Messages {
		b.Messages[i].WireSymbol = b.Messages[i].WireSymbol + "_renamed"
	}
	b.FirstContact.Steps = append([]ir.FirstContactStep(nil), a.FirstContact.Steps...)
	for i := range b.FirstContact.Steps {
		b.FirstContact.Steps[i].WireSymbol = b.FirstContact.Steps[i].WireSymbol + "_renamed"
	}
	report := CompareProfileStructure(a, &b)
	if report.Classification != ClassCosmeticDifference {
		t.Fatalf("classification = %q, structural diffs=%v cosmetic diffs=%v", report.Classification, report.StructuralDifferences, report.CosmeticDifferences)
	}
}

func TestProfileIDAloneIsNotStructuralDifference(t *testing.T) {
	a, _ := compiler.Generate(1)
	b := *a
	b.ID = "kp_only_id_changed"
	report := CompareProfileStructure(a, &b)
	if report.Classification == ClassStructurallyDifferent {
		t.Fatalf("profile ID alone was structural: %+v", report)
	}
}
