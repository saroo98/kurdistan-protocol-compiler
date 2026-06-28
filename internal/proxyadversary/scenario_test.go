// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyadversary

import (
	"context"
	"encoding/json"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/mutant"
)

func TestQuickProxyScenariosRunAndEmitSafeMetadata(t *testing.T) {
	ctx := context.Background()
	p, err := compiler.Generate(410)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range QuickScenarios() {
		t.Run(scenario.Type, func(t *testing.T) {
			run, err := RunScenario(ctx, p, scenario)
			if err != nil {
				t.Fatal(err)
			}
			if !run.Correct {
				t.Fatalf("scenario not correct: %+v", run.Checks)
			}
			if len(run.TargetClasses) < 1 {
				t.Fatalf("no target classes exercised")
			}
			raw, err := json.Marshal(run.Events)
			if err != nil {
				t.Fatal(err)
			}
			for _, marker := range ScenarioPayloadMarkers(run.Scenario) {
				if contains(raw, []byte(marker)) {
					t.Fatalf("trace leaked payload marker %q", marker)
				}
			}
		})
	}
}

func TestProxyFeatureExtractionAndCollapseScanner(t *testing.T) {
	ctx := context.Background()
	profiles, err := GenerateProfiles(500, 6)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := RunScenarioCorpus(ctx, profiles, []Scenario{DefaultScenario(ScenarioMixedTargets)})
	if err != nil {
		t.Fatal(err)
	}
	vector := ExtractProxyFeatures(runs[0].Events)
	if vector.Features["target_error_count"] == 0 {
		t.Fatalf("mixed scenario should include a safe target error feature")
	}
	report := ScanCollapse(ScenarioMixedTargets, runs, DefaultCollapseThresholds())
	if report.Conclusion != "passed" {
		t.Fatalf("normal generated profiles collapsed: %+v", report)
	}
}

func TestProxyCollapseScannerDetectsPaddingOnlyMutant(t *testing.T) {
	ctx := context.Background()
	profiles, err := mutant.GenerateProfiles(mutant.ModePaddingOnlyProxyDiversity, 700, 6)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := RunMutantScenarioCorpus(ctx, mutant.ModePaddingOnlyProxyDiversity, profiles, []Scenario{DefaultScenario(ScenarioMixedTargets)})
	if err != nil {
		t.Fatal(err)
	}
	report := ScanCollapse(ScenarioMixedTargets, runs, DefaultCollapseThresholds())
	if report.Conclusion != "failed" {
		t.Fatalf("padding-only proxy mutant was not flagged: %+v", report)
	}
}

func TestLargeResponseScenarioRespectsProfileProxyLimit(t *testing.T) {
	ctx := context.Background()
	p, err := compiler.Generate(411)
	if err != nil {
		t.Fatal(err)
	}
	p.GenerationHash = ""
	p.ProxySemantics.MaxResponseBytes = 128 * 1024
	run, err := RunScenario(ctx, p, DefaultScenario(ScenarioLargeResponseBackpressure))
	if err != nil {
		t.Fatal(err)
	}
	if !run.Correct {
		t.Fatalf("large response scenario failed under profile limit: %+v", run.Checks)
	}
}

func contains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
