// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSubjectManifestIsDeterministicAndBindsEveryByte(t *testing.T) {
	root := t.TempDir()
	writeSubjectFixture(t, root, "bin/runner.exe", "runner")
	writeSubjectFixture(t, root, "config/policy.json", "policy")
	first, err := BuildSubjectManifest("QHS", root, []string{"config/policy.json", "bin/runner.exe"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSubjectManifest("QHS", root, []string{"bin/runner.exe", "config/policy.json"})
	if err != nil {
		t.Fatal(err)
	}
	if first.RootSHA256 != second.RootSHA256 || !equalManifestEntries(first.Entries, second.Entries) {
		t.Fatalf("subject manifest is order dependent: first=%+v second=%+v", first, second)
	}
	writeSubjectFixture(t, root, "bin/runner.exe", "runner-mutated")
	mutated, err := BuildSubjectManifest("QHS", root, []string{"bin/runner.exe", "config/policy.json"})
	if err != nil {
		t.Fatal(err)
	}
	if mutated.RootSHA256 == first.RootSHA256 {
		t.Fatal("one-byte subject mutation preserved the root")
	}
}

func TestBuildSubjectManifestRejectsTraversalSymlinkHardlinkAndCaseCollision(t *testing.T) {
	root := t.TempDir()
	writeSubjectFixture(t, root, "one.bin", "one")
	writeSubjectFixture(t, root, "Case.bin", "case")
	writeSubjectFixture(t, root, "case.bin", "lower")
	for name, paths := range map[string][]string{
		"traversal":      {"../one.bin"},
		"absolute":       {filepath.Join(root, "one.bin")},
		"duplicate":      {"one.bin", "one.bin"},
		"case collision": {"Case.bin", "case.bin"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildSubjectManifest("PQS", root, paths); err == nil {
				t.Fatal("ambiguous subject path set accepted")
			}
		})
	}
	link := filepath.Join(root, "link.bin")
	if err := os.Symlink(filepath.Join(root, "one.bin"), link); err == nil {
		if _, err := BuildSubjectManifest("PQS", root, []string{"link.bin"}); err == nil {
			t.Fatal("symlinked subject accepted")
		}
	}
	hard := filepath.Join(root, "hard.bin")
	if err := os.Link(filepath.Join(root, "one.bin"), hard); err == nil {
		if _, err := BuildSubjectManifest("PQS", root, []string{"hard.bin", "one.bin"}); err == nil {
			t.Fatal("hardlinked duplicate subject bytes accepted")
		}
	}
}

func TestBuildSubjectManifestTreeInventoriesEveryRegularFileAndRejectsLinks(t *testing.T) {
	root := t.TempDir()
	writeSubjectFixture(t, root, "bin/runner", "runner")
	writeSubjectFixture(t, root, "config/policy.json", "policy")
	manifest, err := BuildSubjectManifestTree("QHS", root)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Entries) != 2 || manifest.Entries[0].Path != "bin/runner" || manifest.Entries[1].Path != "config/policy.json" {
		t.Fatalf("tree entries=%+v", manifest.Entries)
	}
	if err := os.Symlink(filepath.Join(root, "bin", "runner"), filepath.Join(root, "linked-runner")); err == nil {
		if _, err := BuildSubjectManifestTree("QHS", root); err == nil {
			t.Fatal("subject tree containing a symbolic link was accepted")
		}
	}
}

func TestVerifyCandidateArtifactBindsExactSubjectEntryBytes(t *testing.T) {
	root := t.TempDir()
	for _, subject := range []string{"PQS", "QHS", "QWS", "OVS"} {
		writeSubjectFixture(t, root, subject+"/artifact.bin", strings.ToLower(subject))
	}
	manifests := make([]SubjectManifest, 0, 4)
	for _, subject := range []string{"PQS", "QHS", "QWS", "OVS"} {
		manifest, err := BuildSubjectManifest(subject, filepath.Join(root, subject), []string{"artifact.bin"})
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, manifest)
	}
	candidate, err := NewCandidateManifest(SourceProvenance{
		Repository:        "saroo98/kurdistan-protocol-compiler",
		BaselineCommitSHA: strings.Repeat("9", 40), CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
		ChangedPathsSHA256: strings.Repeat("c", 64), ToolchainDeclarationsSHA256: strings.Repeat("d", 64),
		DependencyLocksSHA256: strings.Repeat("e", 64),
	}, strings.Repeat("f", 64), manifests)
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(root, "QHS", "artifact.bin")
	digest, err := VerifyCandidateArtifact(candidate, "QHS", "artifact.bin", artifact, 1<<20)
	if err != nil || digest != candidate.Subjects[1].Entries[0].SHA256 {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	if err := os.WriteFile(artifact, []byte("mutated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCandidateArtifact(candidate, "QHS", "artifact.bin", artifact, 1<<20); err == nil {
		t.Fatal("mutated candidate artifact was accepted")
	}
	if _, err := VerifyCandidateArtifact(candidate, "QHS", "missing.bin", artifact, 1<<20); err == nil {
		t.Fatal("undeclared candidate artifact was accepted")
	}
	if link := filepath.Join(root, "linked-artifact.bin"); os.Symlink(artifact, link) == nil {
		if _, err := VerifyCandidateArtifact(candidate, "QHS", "artifact.bin", link, 1<<20); err == nil {
			t.Fatal("symlinked candidate artifact was accepted")
		}
	}
}

func TestCandidateManifestBindsFiveIndependentRootsAndStrictSourceProvenance(t *testing.T) {
	root := t.TempDir()
	for _, subject := range []string{"PQS", "QHS", "QWS", "OVS"} {
		writeSubjectFixture(t, root, subject+"/artifact.bin", strings.ToLower(subject))
	}
	manifests := make([]SubjectManifest, 0, 4)
	for _, subject := range []string{"PQS", "QHS", "QWS", "OVS"} {
		manifest, err := BuildSubjectManifest(subject, root, []string{subject + "/artifact.bin"})
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, manifest)
	}
	source := SourceProvenance{
		Repository:        "saroo98/kurdistan-protocol-compiler",
		BaselineCommitSHA: strings.Repeat("9", 40), CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
		ChangedPathsSHA256:          strings.Repeat("c", 64),
		ToolchainDeclarationsSHA256: strings.Repeat("d", 64),
		DependencyLocksSHA256:       strings.Repeat("e", 64),
	}
	sourceRaw, err := MarshalSourceProvenance(source)
	if err != nil {
		t.Fatal(err)
	}
	decodedSource, err := DecodeSourceProvenance(bytes.NewReader(sourceRaw))
	if err != nil {
		t.Fatal(err)
	}
	if decodedSource != source {
		t.Fatalf("decoded source=%+v", decodedSource)
	}
	if _, err := DecodeSourceProvenance(bytes.NewReader(append(sourceRaw, '\n'))); err == nil {
		t.Fatal("noncanonical source provenance accepted")
	}
	candidate, err := NewCandidateManifest(source, strings.Repeat("f", 64), manifests)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Schema != CandidateManifestSchema || candidate.Roots.CandidateID == "" ||
		candidate.Roots.SourceSHA256 == candidate.Roots.ProductSHA256 || len(candidate.Subjects) != 4 {
		t.Fatalf("candidate manifest=%+v", candidate)
	}
	raw, err := MarshalCandidateManifest(candidate)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCandidateManifest(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Roots != candidate.Roots {
		t.Fatalf("decoded roots=%+v", decoded.Roots)
	}
	identity, err := CandidateIdentityFromManifest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Repository != source.Repository || identity.CommitSHA != source.CommitSHA || identity.TreeSHA != source.TreeSHA ||
		identity.Roots != candidate.Roots || identity.ComparisonSHA256 != candidate.ComparisonSHA256 {
		t.Fatalf("candidate identity=%+v", identity)
	}
	if _, err := DecodeCandidateManifest(bytes.NewReader(append(raw, '\n'))); err == nil {
		t.Fatal("noncanonical candidate manifest accepted")
	}

	changedSource := source
	changedSource.TreeSHA = strings.Repeat("e", 40)
	changed, err := NewCandidateManifest(changedSource, strings.Repeat("f", 64), manifests)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Roots.SourceSHA256 == candidate.Roots.SourceSHA256 || changed.Roots.CandidateID == candidate.Roots.CandidateID {
		t.Fatal("source provenance mutation preserved candidate identity")
	}

	for name, mutate := range map[string]func(*SourceProvenance){
		"toolchain declarations": func(value *SourceProvenance) { value.ToolchainDeclarationsSHA256 = strings.Repeat("1", 64) },
		"dependency locks":       func(value *SourceProvenance) { value.DependencyLocksSHA256 = strings.Repeat("2", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			mutatedSource := source
			mutate(&mutatedSource)
			mutated, err := NewCandidateManifest(mutatedSource, strings.Repeat("f", 64), manifests)
			if err != nil {
				t.Fatal(err)
			}
			if mutated.Roots.SourceSHA256 == candidate.Roots.SourceSHA256 || mutated.Roots.CandidateID == candidate.Roots.CandidateID {
				t.Fatal("source qualification input mutation preserved candidate identity")
			}
		})
	}
}

func TestNewSourceProvenanceBindsBaselineAndExactInventories(t *testing.T) {
	changed := []string{"android/app/build.gradle.kts", "go.mod"}
	toolchains := []ManifestEntry{
		{Path: "android/gradle/wrapper/gradle-wrapper.properties", Size: 12, SHA256: strings.Repeat("1", 64)},
		{Path: "go.mod", Size: 24, SHA256: strings.Repeat("2", 64)},
	}
	locks := []ManifestEntry{
		{Path: "android/gradle/verification-metadata.xml", Size: 36, SHA256: strings.Repeat("3", 64)},
		{Path: "go.sum", Size: 48, SHA256: strings.Repeat("4", 64)},
	}
	value, err := NewSourceProvenance(
		"saroo98/kurdistan-protocol-compiler",
		strings.Repeat("a", 40),
		strings.Repeat("b", 40),
		strings.Repeat("c", 40),
		changed,
		toolchains,
		locks,
	)
	if err != nil {
		t.Fatal(err)
	}
	if value.BaselineCommitSHA != strings.Repeat("a", 40) || value.CommitSHA != strings.Repeat("b", 40) ||
		value.TreeSHA != strings.Repeat("c", 40) || !hex64Pattern.MatchString(value.ChangedPathsSHA256) ||
		!hex64Pattern.MatchString(value.ToolchainDeclarationsSHA256) || !hex64Pattern.MatchString(value.DependencyLocksSHA256) {
		t.Fatalf("source provenance=%+v", value)
	}

	mutations := []struct {
		name       string
		changed    []string
		toolchains []ManifestEntry
		locks      []ManifestEntry
	}{
		{name: "unsorted paths", changed: []string{"go.mod", "android/app/build.gradle.kts"}, toolchains: toolchains, locks: locks},
		{name: "duplicate paths", changed: []string{"go.mod", "go.mod"}, toolchains: toolchains, locks: locks},
		{name: "unsafe paths", changed: []string{"../go.mod"}, toolchains: toolchains, locks: locks},
		{name: "unsorted toolchains", changed: changed, toolchains: []ManifestEntry{toolchains[1], toolchains[0]}, locks: locks},
		{name: "overlapping inventories", changed: changed, toolchains: toolchains, locks: []ManifestEntry{toolchains[0]}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			if _, err := NewSourceProvenance(
				"saroo98/kurdistan-protocol-compiler",
				strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40),
				mutation.changed, mutation.toolchains, mutation.locks,
			); err == nil {
				t.Fatal("invalid source inventory accepted")
			}
		})
	}
}

func TestEnvironmentDigestIsBoundedAndExcludedFromCandidateIdentity(t *testing.T) {
	first := EnvironmentContext{
		Schema: EnvironmentSchema, HostOS: "windows", HostArch: "amd64", HostBootClass: "BOUND_CURRENT_BOOT",
		AndroidClass: "EMULATOR", AndroidAPI: 36, AndroidABI: "x86_64",
		VPSOS: "linux", VPSArch: "amd64", ProviderClass: "PRIMARY",
		TimeSource: "OWNER_VPS_INTERVAL_REQUIRED", PowerPolicy: "RUNNER_SYSTEM_REQUIRED", PythonSHA256: strings.Repeat("1", 64),
		ADBSHA256: strings.Repeat("2", 64), SSHSHA256: strings.Repeat("3", 64), SCPSHA256: strings.Repeat("4", 64),
		PowerShellSHA256:  strings.Repeat("5", 64),
		PrivateCommitment: strings.Repeat("f", 64),
	}
	second := first
	second.ProviderClass = "UNRELATED_SECONDARY"
	firstDigest, err := EnvironmentDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := EnvironmentDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest == secondDigest {
		t.Fatal("environment change preserved its digest")
	}
	if _, err := EnvironmentDigest(EnvironmentContext{Schema: EnvironmentSchema, PrivateCommitment: "hostname.example"}); err == nil {
		t.Fatal("unsafe environment context accepted")
	}
	unsupportedVPS := first
	unsupportedVPS.VPSArch = "arm64"
	if _, err := EnvironmentDigest(unsupportedVPS); err == nil {
		t.Fatal("unbuilt Phase 17 VPS architecture was accepted")
	}
	raw, err := MarshalEnvironmentContext(first)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnvironmentContext(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if decoded != first {
		t.Fatalf("decoded environment=%+v", decoded)
	}
	if _, err := DecodeEnvironmentContext(bytes.NewReader(append(raw, '\n'))); err == nil {
		t.Fatal("noncanonical environment context accepted")
	}
}

func TestEnvironmentContextAcceptsCurrentPhysicalAPIWithoutWideningEmulatorMatrix(t *testing.T) {
	physical := EnvironmentContext{
		Schema: EnvironmentSchema, HostOS: "windows", HostArch: "amd64", HostBootClass: "BOUND_CURRENT_BOOT",
		AndroidClass: "PHYSICAL", AndroidAPI: 37, AndroidABI: "arm64-v8a",
		VPSOS: "linux", VPSArch: "amd64", ProviderClass: "PRIMARY",
		TimeSource: "OWNER_VPS_INTERVAL_REQUIRED", PowerPolicy: "RUNNER_SYSTEM_REQUIRED",
		PythonSHA256: strings.Repeat("1", 64), ADBSHA256: strings.Repeat("2", 64),
		SSHSHA256: strings.Repeat("3", 64), SCPSHA256: strings.Repeat("4", 64), PowerShellSHA256: strings.Repeat("5", 64),
		PrivateCommitment: strings.Repeat("f", 64),
	}
	if _, err := EnvironmentDigest(physical); err != nil {
		t.Fatalf("current physical API rejected: %v", err)
	}

	emulator := physical
	emulator.AndroidClass = "EMULATOR"
	emulator.AndroidABI = "x86_64"
	if _, err := EnvironmentDigest(emulator); err == nil {
		t.Fatal("unqualified emulator API accepted")
	}
}

func writeSubjectFixture(t *testing.T, root, relative, value string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatal(err)
	}
}

func equalManifestEntries(left, right []ManifestEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
