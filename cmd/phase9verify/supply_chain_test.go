// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCIThirdPartyActionsAreExactSHAPins(t *testing.T) {
	data := readRepositoryFile(t, ".github", "workflows", "ci.yml")
	matches := regexp.MustCompile(`(?m)^\s*uses:\s*([^@\s]+)@([0-9a-f]+)(?:\s*#.*)?$`).FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		t.Fatal("no CI action references found")
	}
	expected := map[string]string{
		"actions/checkout":   "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
		"actions/setup-go":   "4a3601121dd01d1626a1e23e37211e3254c1c06c",
		"actions/setup-java": "f2beeb24e141e01a676f977032f5a29d81c9e27e",
	}
	for _, match := range matches {
		if len(match[2]) != 40 {
			t.Errorf("%s is not pinned to a full commit SHA", match[1])
			continue
		}
		want, ok := expected[match[1]]
		if !ok {
			t.Errorf("unreviewed CI action %s", match[1])
			continue
		}
		if match[2] != want {
			t.Errorf("%s pin=%s, want %s", match[1], match[2], want)
		}
	}
}

func TestGradleWrapperAndDependencyVerificationArePinned(t *testing.T) {
	properties := string(readRepositoryFile(t, "android", "gradle", "wrapper", "gradle-wrapper.properties"))
	for _, required := range []string{
		"distributionUrl=https\\://services.gradle.org/distributions/gradle-9.4.1-bin.zip",
		"distributionSha256Sum=2ab2958f2a1e51120c326cad6f385153bb11ee93b3c216c5fccebfdfbb7ec6cb",
		"validateDistributionUrl=true",
	} {
		if !strings.Contains(properties, required) {
			t.Errorf("Gradle wrapper is missing %q", required)
		}
	}
	jar := readRepositoryFile(t, "android", "gradle", "wrapper", "gradle-wrapper.jar")
	sum := sha256.Sum256(jar)
	if got, want := hex.EncodeToString(sum[:]), "55243ef57851f12b070ad14f7f5bb8302daceeebc5bce5ece5fa6edb23e1145c"; got != want {
		t.Errorf("Gradle wrapper JAR sha256=%s, want %s", got, want)
	}
	verification := string(readRepositoryFile(t, "android", "gradle", "verification-metadata.xml"))
	if !strings.Contains(verification, "<verify-metadata>true</verify-metadata>") ||
		!strings.Contains(verification, "<sha256 value=") {
		t.Fatal("Gradle dependency verification metadata is not checksum-enforcing")
	}
	for _, required := range []string{
		`<component group="org.jetbrains.kotlin" name="kotlin-gradle-plugins-bom" version="2.2.10">`,
		`<sha256 value="e4b7dd0b5570aa7ae6597d1f479bcea94e78e12735fa86f80afa95e7014efed6"`,
		`<sha256 value="c0a5a21a4e6eec4d8bb6a2c491fac42f35ab9f08dd2af6bedb085715ac805296"`,
	} {
		if !strings.Contains(verification, required) {
			t.Errorf("Gradle dependency verification metadata is missing %q", required)
		}
	}
	build := string(readRepositoryFile(t, "android", "build.gradle.kts"))
	if !strings.Contains(build, "lockMode.set(LockMode.STRICT)") {
		t.Fatal("Gradle dependency locking is not strict")
	}
}

func TestGradleWrapperIsExecutableInGit(t *testing.T) {
	command := exec.Command("git", "ls-files", "--stage", "--", "android/gradlew")
	command.Dir = filepath.Join("..", "..")
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(output), "100755 ") {
		t.Fatalf("android/gradlew Git mode must be 100755, got %q", strings.TrimSpace(string(output)))
	}
}

func TestVersionCatalogContainsNoDynamicVersions(t *testing.T) {
	catalog := string(readRepositoryFile(t, "android", "gradle", "libs.versions.toml"))
	dynamic := regexp.MustCompile(`(?m)^\s*[A-Za-z0-9_.-]+\s*=\s*"(?:latest[.-].*|\+|.*\.\+)"\s*$`)
	if match := dynamic.FindString(catalog); match != "" {
		t.Fatalf("dynamic dependency version found: %s", match)
	}
}

func readRepositoryFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
