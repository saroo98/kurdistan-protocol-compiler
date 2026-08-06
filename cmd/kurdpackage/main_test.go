// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestArchiveIsDeterministicAndStrictlyVerified(t *testing.T) {
	files := fixturePackageFiles(t, false)
	one := filepath.Join(t.TempDir(), "one.tar.gz")
	two := filepath.Join(t.TempDir(), "two.tar.gz")
	if err := writeArchive(one, "kurd-node-test-linux-amd64", files); err != nil {
		t.Fatal(err)
	}
	if err := writeArchive(two, "kurd-node-test-linux-amd64", files); err != nil {
		t.Fatal(err)
	}
	oneBytes, _ := os.ReadFile(one)
	twoBytes, _ := os.ReadFile(two)
	if !bytes.Equal(oneBytes, twoBytes) {
		t.Fatal("same package inputs produced different archive bytes")
	}
	manifest, err := verifyArchive(one)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Arch != "amd64" || manifest.Signed || manifest.RelayDataPlane {
		t.Fatalf("manifest authority mismatch: %+v", manifest)
	}

	invalid := filepath.Join(t.TempDir(), "invalid.tar.gz")
	if err := writeArchive(invalid, "kurd-node-test-linux-amd64", fixturePackageFiles(t, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArchive(invalid); err == nil {
		t.Fatal("package with forged checksum inventory was accepted")
	}

	extra := filepath.Join(t.TempDir(), "extra.tar.gz")
	extraFiles := fixturePackageFiles(t, false)
	extraFiles = append(extraFiles, packageFile{Path: "unexpected.bin", Mode: 0o644, Data: []byte("not in the authenticated inventories")})
	sort.Slice(extraFiles, func(left, right int) bool { return extraFiles[left].Path < extraFiles[right].Path })
	if err := writeArchive(extra, "kurd-node-test-linux-amd64", extraFiles); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArchive(extra); err == nil {
		t.Fatal("package with an unmanifested extra file was accepted")
	}
}

func fixturePackageFiles(t *testing.T, forge bool) []packageFile {
	t.Helper()
	files := []packageFile{
		{Path: "bin/kurd-node", Mode: 0o755, Data: []byte("node")},
		{Path: "bin/kurdctl", Mode: 0o755, Data: []byte("ctl")},
		{Path: "install.sh", Mode: 0o755, Data: []byte("install")},
		{Path: "preflight.sh", Mode: 0o755, Data: []byte("preflight")},
		{Path: "rollback.sh", Mode: 0o755, Data: []byte("rollback")},
		{Path: "uninstall.sh", Mode: 0o755, Data: []byte("uninstall")},
		{Path: "upgrade.sh", Mode: 0o755, Data: []byte("upgrade")},
		{Path: "systemd/kurd-node.service", Mode: 0o644, Data: []byte("service")},
		{Path: "THIRD_PARTY_MODULES.json", Mode: 0o644, Data: []byte("{}")},
		{Path: "docs/INSTALL.md", Mode: 0o644, Data: []byte("install")},
		{Path: "docs/CONTAINER.md", Mode: 0o644, Data: []byte("container")},
	}
	manifest := packageManifest{Schema: "kurd-node-native-package-v1", Version: "test", OS: "linux", Arch: "amd64", GoVersion: "go version go1.26.5 test", SourceCommit: strings.Repeat("a", 40), Files: []fileDigest{}}
	for _, file := range files {
		manifest.Files = append(manifest.Files, digestFile(file))
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, packageFile{Path: "manifest.json", Mode: 0o644, Data: encoded})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	var sums strings.Builder
	for _, file := range files {
		digest := digestFile(file).SHA256
		if forge && file.Path == "bin/kurd-node" {
			raw, _ := hex.DecodeString(digest)
			raw[0] ^= 1
			digest = hex.EncodeToString(raw)
		}
		sums.WriteString(digest + "  " + file.Path + "\n")
	}
	files = append(files, packageFile{Path: "SHA256SUMS", Mode: 0o644, Data: []byte(sums.String())})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	return files
}
