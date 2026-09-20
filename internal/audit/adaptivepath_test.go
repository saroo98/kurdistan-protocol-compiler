// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/transport/adaptivepath"
)

func TestAdaptivePathGatesPass(t *testing.T) {
	set, err := adaptivepath.GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	comparison := adaptivepath.CompareFixtureSets(set, set)
	for _, gate := range AdaptivePathGates(set, comparison) {
		if !gate.Passed {
			t.Fatalf("%s failed: %s", gate.Name, gate.Summary)
		}
	}
}

func TestAdaptivePathMisuseGateDetectsCollapsedControl(t *testing.T) {
	set, err := adaptivepath.GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	set.CollapsedControl = adaptivepath.AdaptivePathMisuseReport{Conclusion: "passed"}
	gate := AdaptivePathMisuseDetectionGate(set)
	if gate.Passed {
		t.Fatalf("collapsed control was not required by misuse gate")
	}
}

func TestAdaptivePathTraceHygieneGateRejectsUnsafeFields(t *testing.T) {
	set, err := adaptivepath.GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gate := AdaptivePathTraceHygieneGate(set)
	if !gate.Passed {
		t.Fatalf("clean fixture rejected: %s", gate.Summary)
	}
	if err := adaptivepath.ScanForLeak(map[string]string{"endpoint": "synthetic"}); err == nil {
		t.Fatalf("endpoint field accepted")
	}
	if err := adaptivepath.ScanForLeak(map[string]string{"resolver_ip": "synthetic"}); err == nil {
		t.Fatalf("resolver field accepted")
	}
}

func TestAdaptivePathAuditQuickIncludesRequiredGates(t *testing.T) {
	report, err := RunAdaptivePathAudit(context.Background(), DefaultConfig("quick"))
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"adaptivepath_candidate_taxonomy",
		"adaptivepath_condition_model",
		"adaptivepath_freshness_uncertainty",
		"adaptivepath_viability_evaluation",
		"adaptivepath_decision_inputs",
		"adaptivepath_misuse_detection",
		"adaptivepath_generated_backend_parity",
		"adaptivepath_trace_hygiene",
		"adaptivepath_mutant_detection",
		"adaptivepath_public_docs",
	}
	for _, name := range required {
		if _, ok := gateByName(report.Gates, name); !ok {
			t.Fatalf("missing adaptivepath gate %s", name)
		}
	}
}

func TestAdaptivePathPublicDocsGatePasses(t *testing.T) {
	gate := AdaptivePathPublicDocsGate()
	if !gate.Passed {
		t.Fatalf("public docs gate failed: %v", gate.Details["failures"])
	}
}

func TestAdaptivePathPublicDocsGateRejectsRegressions(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	files := []string{"README.md", "docs/self-hosting/SECURITY.md", "website/src/components/document.mjs", "website/src/content/locales.mjs", "website/src/content/pages.mjs", "website/src/refinement/copy.json"}
	for _, tc := range []struct{ name, file, remove, add string }{
		{"missing template", files[2], "*", ""},
		{"missing main", files[2], `<main id="content"`, ""},
		{"missing language alternates", files[2], `hreflang="${locales[code].hreflang}"`, ""},
		{"missing Sorani", files[3], "hreflang:'ku-Arab'", ""},
		{"missing Kurmanji", files[3], "hreflang:'ku-Latn'", ""},
		{"missing release boundary", files[4], "This website does not offer a production APK", ""},
		{"missing localized availability", files[5], "ئەپەکەی ئەندرۆید بەم زووانە", ""},
		{"unsafe claim", files[4], "", "\nguaranteed bypass\n"},
		{"private marker", files[5], "", "\nprivate plan\n"},
		{"external script", files[2], "", "\n<script src=\"https://example.invalid/script.js\"></script>\n"},
		{"analytics", files[2], "", "\ngoogle-analytics\n"},
		{"unsafe fixture", files[2], "", "\nraw payload\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := t.TempDir()
			for _, file := range files {
				data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
				if err != nil {
					t.Fatal(err)
				}
				if file == tc.file {
					if tc.remove == "*" {
						continue
					}
					if tc.remove != "" {
						if !strings.Contains(string(data), tc.remove) {
							t.Fatal("mutation target not found")
						}
						data = []byte(strings.ReplaceAll(string(data), tc.remove, ""))
					}
					data = append(data, tc.add...)
				}
				destination := filepath.Join(target, filepath.FromSlash(file))
				if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(destination, data, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if result := adaptivePathPublicDocsGateAt(target); result.Passed {
				t.Fatal("unsafe or incomplete publication accepted")
			}
		})
	}
}

func BenchmarkAdaptivePathQuickAudit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		report, err := RunAdaptivePathAudit(context.Background(), DefaultConfig("quick"))
		if err != nil {
			b.Fatal(err)
		}
		if len(report.Gates) == 0 {
			b.Fatal("no gates")
		}
	}
}
