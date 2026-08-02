// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteArtifactMetadataBindsSortedHashes(t *testing.T) {
	root := t.TempDir()
	writeArtifactFixture(t, root, "artifacts/z.bin", "last")
	writeArtifactFixture(t, root, "artifacts/a.bin", "first")
	output := filepath.Join(root, "metadata", "device.json")
	err := writeArtifactMetadata(
		root,
		versionProperties{Name: "0.9.0", Code: 1},
		"DEVICE_TEST_SET",
		[]artifactSpec{
			{Name: "test-apk", Pattern: "artifacts/z.bin"},
			{Name: "app-apk", Pattern: "artifacts/a.bin"},
		},
		output,
	)
	if err != nil {
		t.Fatalf("write artifact metadata: %v", err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Schema        string `json:"schema"`
		Subject       string `json:"subject"`
		Authoritative bool   `json:"authoritative"`
		Release       struct {
			VersionName string `json:"versionName"`
			VersionCode int    `json:"versionCode"`
		} `json:"release"`
		Artifacts []struct {
			Name   string `json:"name"`
			Path   string `json:"path"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256([]byte("first"))
	if got.Schema != "kpc-android-artifact-metadata-v1" || got.Subject != "DEVICE_TEST_SET" || got.Authoritative ||
		got.Release.VersionName != "0.9.0" || got.Release.VersionCode != 1 || len(got.Artifacts) != 2 ||
		got.Artifacts[0].Name != "app-apk" || got.Artifacts[0].Path != "artifacts/a.bin" || got.Artifacts[0].Size != 5 ||
		got.Artifacts[0].SHA256 != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("unexpected artifact metadata: %+v", got)
	}
}

func TestRunWritesRequestedOfflineArtifactMetadata(t *testing.T) {
	root := t.TempDir()
	copyReleaseFixture(t, root)
	writeArtifactFixture(t, root, "artifacts/app.apk", "unsigned engineering bytes")
	var stdout, stderr bytes.Buffer
	err := runCommand([]string{
		"-root", root,
		"-artifact-subject", "UNSIGNED_ENGINEERING_CANDIDATE",
		"-artifact", "unsigned-apk=artifacts/app.apk",
		"-artifact-metadata", "build/ci/candidate.json",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run command: %v (stderr %q)", err, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "build", "ci", "candidate.json")); err != nil {
		t.Fatalf("artifact metadata was not written: %v", err)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("OFFLINE CONFIGURATION ONLY")) {
		t.Fatalf("missing offline-only result: %q", stdout.String())
	}
}

func TestWriteArtifactMetadataRejectsAmbiguousArtifactGlob(t *testing.T) {
	root := t.TempDir()
	writeArtifactFixture(t, root, "artifacts/one.apk", "one")
	writeArtifactFixture(t, root, "artifacts/two.apk", "two")
	err := writeArtifactMetadata(
		root,
		versionProperties{Name: "0.9.0", Code: 1},
		"DEVICE_TEST_SET",
		[]artifactSpec{{Name: "app-apk", Pattern: "artifacts/*.apk"}},
		filepath.Join(root, "metadata.json"),
	)
	if err == nil {
		t.Fatal("ambiguous artifact glob passed")
	}
}

func TestWriteArtifactMetadataRejectsSymlinkArtifact(t *testing.T) {
	root := t.TempDir()
	writeArtifactFixture(t, root, "artifacts/real.apk", "real")
	link := filepath.Join(root, "artifacts", "linked.apk")
	if err := os.Symlink(filepath.Join(root, "artifacts", "real.apk"), link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	err := writeArtifactMetadata(
		root,
		versionProperties{Name: "0.9.0", Code: 1},
		"DEVICE_TEST_SET",
		[]artifactSpec{{Name: "app-apk", Pattern: "artifacts/linked.apk"}},
		filepath.Join(root, "metadata.json"),
	)
	if err == nil {
		t.Fatal("symbolic-link artifact passed")
	}
}

func TestWriteArtifactMetadataRejectsArtifactThroughSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	writeArtifactFixture(t, root, "real/app.apk", "real")
	link := filepath.Join(root, "artifacts")
	if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	err := writeArtifactMetadata(
		root,
		versionProperties{Name: "0.9.0", Code: 1},
		"DEVICE_TEST_SET",
		[]artifactSpec{{Name: "app-apk", Pattern: "artifacts/app.apk"}},
		filepath.Join(root, "metadata.json"),
	)
	if err == nil {
		t.Fatal("artifact below a symbolic-link parent passed")
	}
}

func TestWriteArtifactMetadataRejectsSymlinkOutputTarget(t *testing.T) {
	root := t.TempDir()
	writeArtifactFixture(t, root, "artifacts/app.apk", "app")
	writeArtifactFixture(t, root, "protected.json", "unchanged")
	output := filepath.Join(root, "metadata.json")
	if err := os.Symlink(filepath.Join(root, "protected.json"), output); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	err := writeArtifactMetadata(
		root,
		versionProperties{Name: "0.9.0", Code: 1},
		"DEVICE_TEST_SET",
		[]artifactSpec{{Name: "app-apk", Pattern: "artifacts/app.apk"}},
		output,
	)
	if err == nil {
		t.Fatal("symbolic-link output target passed")
	}
	raw, readErr := os.ReadFile(filepath.Join(root, "protected.json"))
	if readErr != nil || string(raw) != "unchanged" {
		t.Fatalf("symlink target changed: content=%q err=%v", raw, readErr)
	}
}

func TestWriteArtifactMetadataRejectsSymlinkOutputParent(t *testing.T) {
	root := t.TempDir()
	writeArtifactFixture(t, root, "artifacts/app.apk", "app")
	if err := os.Mkdir(filepath.Join(root, "real-output"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "output")
	if err := os.Symlink(filepath.Join(root, "real-output"), link); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	err := writeArtifactMetadata(
		root,
		versionProperties{Name: "0.9.0", Code: 1},
		"DEVICE_TEST_SET",
		[]artifactSpec{{Name: "app-apk", Pattern: "artifacts/app.apk"}},
		filepath.Join(link, "metadata.json"),
	)
	if err == nil {
		t.Fatal("symbolic-link output parent passed")
	}
	if _, statErr := os.Stat(filepath.Join(root, "real-output", "metadata.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("metadata unexpectedly written through symlink: %v", statErr)
	}
}

func TestWriteArtifactMetadataReplacesRegularOutputAtomically(t *testing.T) {
	root := t.TempDir()
	writeArtifactFixture(t, root, "artifacts/app.apk", "app")
	output := filepath.Join(root, "metadata.json")
	writeArtifactFixture(t, root, "metadata.json", "old")
	err := writeArtifactMetadata(
		root,
		versionProperties{Name: "0.9.0", Code: 1},
		"DEVICE_TEST_SET",
		[]artifactSpec{{Name: "app-apk", Pattern: "artifacts/app.apk"}},
		output,
	)
	if err != nil {
		t.Fatalf("replace regular output: %v", err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(artifactMetadataSchema)) {
		t.Fatalf("output was not replaced with metadata: %q", raw)
	}
}

func writeArtifactFixture(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyReleaseFixture(t *testing.T, root string) {
	t.Helper()
	fixtureRoot := filepath.Join("testdata", "valid")
	for _, relative := range []string{
		versionPropertiesPath,
		productsPath,
		"android/build.gradle.kts",
		"android/app/build.gradle.kts",
	} {
		raw, err := os.ReadFile(filepath.Join(fixtureRoot, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		writeArtifactFixture(t, root, relative, string(raw))
	}
}
