// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestVerifyCanonicalAndroidTextRejectsCRLFAndIgnoresBuildOutputs(t *testing.T) {
	root := t.TempDir()
	write := func(relative, content string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("android/app/src/main/example.kt", "line one\nline two\n")
	write("android/gradlew.bat", "@echo off\r\n")
	write("android/app/build/generated.xml", "<generated>\r\n")
	if err := verifyCanonicalAndroidText(root); err != nil {
		t.Fatalf("canonical tree rejected: %v", err)
	}

	write("android/app/gradle.lockfile", "entry=locked\r\n")
	err := verifyCanonicalAndroidText(root)
	if err == nil || !strings.Contains(err.Error(), "android/app/gradle.lockfile contains CR bytes") {
		t.Fatalf("CRLF lockfile error=%v", err)
	}
}

func TestVerifyReproducibilityArtifactSeparatesSameHostAndCrossHostClaims(t *testing.T) {
	root := t.TempDir()
	artifact := filepath.Join(root, "release.apk")
	contents := []byte("platform-specific unsigned artifact")
	if err := os.WriteFile(artifact, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(contents)
	report := reproducibilityReport{
		Artifact:      "release.apk",
		BuildASHA256:  hex.EncodeToString(sum[:]),
		ArtifactSize:  int64(len(contents)),
		ByteIdentical: true,
	}
	report.Environment.OperatingSystem = runtime.GOOS
	if _, err := verifyReproducibilityArtifact(root, report); err != nil {
		t.Fatalf("same-host artifact rejected: %v", err)
	}

	report.BuildASHA256 = strings.Repeat("0", 64)
	report.ArtifactSize++
	if _, err := verifyReproducibilityArtifact(root, report); err == nil {
		t.Fatal("same-host mismatch was accepted")
	}

	if runtime.GOOS == "windows" {
		report.Environment.OperatingSystem = "linux"
	} else {
		report.Environment.OperatingSystem = "windows"
	}
	if got, err := verifyReproducibilityArtifact(root, report); err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("cross-host unverified artifact should remain measurable without claiming equality: hash=%q err=%v", got, err)
	}
}
