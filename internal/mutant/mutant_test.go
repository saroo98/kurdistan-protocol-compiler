package mutant

import (
	"testing"

	"kurdistan/internal/diversity"
	"kurdistan/internal/ir"
)

func TestGenerateProfilesModesValidate(t *testing.T) {
	for _, mode := range Modes() {
		profiles, err := GenerateProfiles(mode, 1, 6)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if len(profiles) != 6 {
			t.Fatalf("%s: got %d profiles", mode, len(profiles))
		}
		for _, p := range profiles {
			if err := ir.Validate(p); err != nil {
				t.Fatalf("%s profile %s invalid: %v", mode, p.ID, err)
			}
		}
	}
}

func TestCosmeticSymbolsOnlyClassifiedCosmetic(t *testing.T) {
	profiles, err := GenerateProfiles(ModeCosmeticSymbolsOnly, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	report := diversity.CompareProfileStructure(profiles[0], profiles[1])
	if report.Classification != diversity.ClassCosmeticDifference {
		t.Fatalf("classification = %q, want cosmetic; report=%+v", report.Classification, report)
	}
}

func TestMutantCorpusShapes(t *testing.T) {
	tests := []struct {
		mode      string
		check     func(diversity.ProfileDiversityReport) bool
		wantLabel string
	}{
		{ModeFixedFrameGrammar, func(r diversity.ProfileDiversityReport) bool { return r.UniqueFrameGrammarCombinations == 1 }, "one frame grammar"},
		{ModeFixedScheduler, func(r diversity.ProfileDiversityReport) bool { return r.UniqueSchedulerCombinations == 1 }, "one scheduler"},
		{ModeFixedInvalidInput, func(r diversity.ProfileDiversityReport) bool { return r.UniqueInvalidInputPolicyCombinations == 1 }, "one invalid-input policy"},
		{ModeCosmeticSymbolsOnly, func(r diversity.ProfileDiversityReport) bool {
			return r.CosmeticDifferencePairs > 0 && r.StructurallyDifferentPairs == 0
		}, "cosmetic pairs only"},
	}
	for _, tt := range tests {
		profiles, err := GenerateProfiles(tt.mode, 10, 8)
		if err != nil {
			t.Fatalf("%s: %v", tt.mode, err)
		}
		report := diversity.AnalyzeProfiles(profiles)
		if !tt.check(report) {
			t.Fatalf("%s did not produce %s: %+v", tt.mode, tt.wantLabel, report)
		}
	}
}

func TestTraceFixturesArePayloadFree(t *testing.T) {
	profiles, err := GenerateProfiles(ModePaddingNoiseOnly, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	raw := TraceFixtures(ModePaddingNoiseOnly, profiles)
	for _, events := range raw {
		for _, ev := range events {
			if ev.PayloadBytes < 0 || ev.Note == "payload" {
				t.Fatalf("trace fixture leaked payload-like data: %+v", ev)
			}
		}
	}
}
