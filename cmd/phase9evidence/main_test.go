// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"encoding/json"
	"testing"
)

func TestCanonicalizeBOMRemovesVolatileIdentityAndSorts(t *testing.T) {
	bom := map[string]any{
		"serialNumber": "urn:uuid:random",
		"metadata": map[string]any{
			"timestamp": "now",
		},
		"components": []any{
			map[string]any{"bom-ref": "z"},
			map[string]any{"bom-ref": "a"},
		},
		"dependencies": []any{
			map[string]any{"ref": "z", "dependsOn": []any{"z", "a"}},
			map[string]any{"ref": "a"},
		},
	}
	canonicalizeBOM(bom)
	if _, ok := bom["serialNumber"]; ok {
		t.Fatal("serial number survived canonicalization")
	}
	metadata := bom["metadata"].(map[string]any)
	if _, ok := metadata["timestamp"]; ok {
		t.Fatal("timestamp survived canonicalization")
	}
	components := bom["components"].([]any)
	if components[0].(map[string]any)["bom-ref"] != "a" {
		t.Fatalf("components were not sorted: %#v", components)
	}
	dependencies := bom["dependencies"].([]any)
	if dependencies[0].(map[string]any)["ref"] != "a" {
		t.Fatalf("dependencies were not sorted: %#v", dependencies)
	}
	dependsOn := dependencies[1].(map[string]any)["dependsOn"].([]any)
	if dependsOn[0] != "a" {
		t.Fatalf("dependency targets were not sorted: %#v", dependsOn)
	}
}

func TestBuildSPDXRejectsUnlicensedExternalDependency(t *testing.T) {
	_, err := buildSPDX(map[string]any{
		"components": []any{
			map[string]any{
				"group": "example.org",
				"name":  "unlicensed",
				"purl":  "pkg:maven/example.org/unlicensed@1",
			},
		},
	})
	if err == nil {
		t.Fatal("unlicensed dependency was accepted")
	}
}

func TestBuildSPDXExcludesProjectModulesAndIsSerializable(t *testing.T) {
	document, err := buildSPDX(map[string]any{
		"components": []any{
			map[string]any{
				"group":    "org.kurdistanvpn",
				"name":     "app",
				"purl":     "pkg:maven/org.kurdistanvpn/app@0.9.0",
				"licenses": []any{map[string]any{"license": map[string]any{"id": "AGPL-3.0-or-later"}}},
			},
			map[string]any{
				"group":   "androidx.example",
				"name":    "library",
				"version": "1.0",
				"purl":    "pkg:maven/androidx.example/library@1.0",
				"licenses": []any{
					map[string]any{"license": map[string]any{"id": "Apache-2.0"}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Packages) != 1 || document.Packages[0].Name != "androidx.example:library" {
		t.Fatalf("unexpected packages: %#v", document.Packages)
	}
	if _, err := json.Marshal(document); err != nil {
		t.Fatal(err)
	}
}
