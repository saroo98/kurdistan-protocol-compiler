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
	if manifest.Arch != "amd64" || manifest.Signed || !manifest.RelayDataPlane {
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

func TestNativePackageRequiresExactLiveDataPlaneAssets(t *testing.T) {
	root := repositoryRootV1(t)
	for path, mode := range requiredNativeFilesV1 {
		source := nativeSourceForPackagePathV1(path)
		if source == "" {
			t.Fatalf("required package path has no source mapping: %s", path)
		}
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(source)))
		if err != nil || info.IsDir() {
			t.Fatalf("required native asset %s: %v", source, err)
		}
		if strings.HasSuffix(source, ".sh") != (mode == 0o755) {
			t.Fatalf("mode policy mismatch for %s: %o", path, mode)
		}
	}

	compose, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "container", "compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(compose)
	if !strings.Contains(text, `org.kurdistan.relay-data-plane: "false"`) || !strings.Contains(text, "network_mode: none") {
		t.Fatal("container deployment did not remain explicitly authority-only")
	}
}

func TestNativeShellAssetsRemainFailClosedAndSecretSafe(t *testing.T) {
	root := repositoryRootV1(t)
	native := filepath.Join(root, "deploy", "selfhost", "native")
	entries, err := filepath.Glob(filepath.Join(native, "*.sh"))
	if err != nil || len(entries) != 5 {
		t.Fatalf("native shell inventory=%d err=%v", len(entries), err)
	}
	for _, path := range entries {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(encoded)
		if !strings.HasPrefix(text, "#!/bin/sh\nset -eu\n") {
			t.Fatalf("%s lacks strict POSIX shell preamble", filepath.Base(path))
		}
		for _, forbidden := range []string{"eval ", "curl |", "wget |", "--private-key", "--password", "--token", "flush ruleset"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden shell pattern %q", filepath.Base(path), forbidden)
			}
		}
		for _, forbidden := range []string{"rm -rf $", "cp -p $", "mv $", "install $"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains an unquoted high-risk path expansion %q", filepath.Base(path), forbidden)
			}
		}
		if strings.Contains(text, "nft -f") && (!strings.Contains(text, "nft -c -f") || strings.Index(text, "nft -c -f") > strings.Index(text, "nft -f")) {
			t.Fatalf("%s applies nftables without an earlier atomic syntax check", filepath.Base(path))
		}
	}
	rollback, err := os.ReadFile(filepath.Join(native, "rollback.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rollback), "preflight.sh --runtime") || !strings.Contains(string(rollback), "state-v2") {
		t.Fatal("rollback does not preflight or enforce the state-v2 compatibility boundary")
	}
	rollbackText := string(rollback)
	validationAt := strings.Index(rollbackText, "PREVIOUS_NFT_INVALID")
	stopAt := strings.Index(rollbackText, "systemctl stop kurd-node.socket")
	migrationAt := strings.Index(rollbackText, "kurdctl migration rollback")
	if validationAt < 0 || stopAt < 0 || migrationAt < 0 || !(validationAt < stopAt && stopAt < migrationAt) {
		t.Fatal("rollback must validate the previous package, stop live writers, then mutate state")
	}
	installScript, err := os.ReadFile(filepath.Join(native, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	installText := string(installScript)
	if !strings.Contains(installText, "systemd_root=") || !strings.Contains(installText, `systemd-analyze --root="$systemd_root" verify`) {
		t.Fatal("install must verify the candidate units and executables in an isolated root before host mutation")
	}
	upgradeScript, err := os.ReadFile(filepath.Join(native, "upgrade.sh"))
	if err != nil {
		t.Fatal(err)
	}
	upgradeText := string(upgradeScript)
	migrateAt := strings.Index(upgradeText, "kurdctl migration apply")
	mutationAt := strings.Index(upgradeText, "v2_mutated=true")
	doctorAt := strings.Index(upgradeText, "kurdctl doctor")
	if migrateAt < 0 || mutationAt < 0 || doctorAt < 0 || !(migrateAt < mutationAt && mutationAt < doctorAt) {
		t.Fatal("upgrade must close automatic v1 rollback immediately after the first successful v2 mutation")
	}
}

func TestPreflightFailureFixtureInventory(t *testing.T) {
	root := repositoryRootV1(t)
	encoded, err := os.ReadFile(filepath.Join(root, "cmd", "kurdpackage", "testdata", "preflight-failures.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Schema string `json:"schema"`
		Cases  []struct {
			Name string `json:"name"`
			Code string `json:"code"`
		} `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil || fixture.Schema != "kurd-node-preflight-failure-fixtures-v1" {
		t.Fatalf("fixture decode: %v", err)
	}
	want := []string{"NO_TUN", "TIME_NOT_SYNCED", "NO_IPV4_ROUTE", "NO_IPV6_ROUTE", "MULTIPLE_EGRESS", "PORT_CONFLICT", "NFT_MISSING", "UNBOUND_MISSING", "NETWORKD_MISSING", "KERNEL_UNSUPPORTED", "LOW_DISK", "LOW_MEMORY"}
	if len(fixture.Cases) != len(want) {
		t.Fatalf("fixture cases=%d want=%d", len(fixture.Cases), len(want))
	}
	preflight, err := os.ReadFile(filepath.Join(root, "deploy", "selfhost", "native", "preflight.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for index, code := range want {
		if fixture.Cases[index].Code != code || fixture.Cases[index].Name == "" || !strings.Contains(string(preflight), code) {
			t.Fatalf("fixture %d=%+v code=%s", index, fixture.Cases[index], code)
		}
	}
}

func repositoryRootV1(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
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
		{Path: "systemd/kurd-node.socket", Mode: 0o644, Data: []byte("socket")},
		{Path: "systemd/kurd-node-network.service", Mode: 0o644, Data: []byte("network-service")},
		{Path: "systemd/kurd-node.sysusers.conf", Mode: 0o644, Data: []byte("sysusers")},
		{Path: "systemd/kurd-node.tmpfiles.conf", Mode: 0o644, Data: []byte("tmpfiles")},
		{Path: "networkd/80-kurd0.netdev", Mode: 0o640, Data: []byte("netdev")},
		{Path: "networkd/80-kurd0.network", Mode: 0o644, Data: []byte("network")},
		{Path: "sysctl/90-kurd-node.conf", Mode: 0o644, Data: []byte("sysctl")},
		{Path: "nftables/kurd-node.nft", Mode: 0o600, Data: []byte("nft")},
		{Path: "unbound/kurd-node-unbound.conf", Mode: 0o644, Data: []byte("unbound")},
		{Path: "THIRD_PARTY_MODULES.json", Mode: 0o644, Data: []byte("{}")},
		{Path: "docs/INSTALL.md", Mode: 0o644, Data: []byte("install")},
		{Path: "docs/CONTAINER.md", Mode: 0o644, Data: []byte("container")},
		{Path: "docs/LIVE-DATA-PLANE.md", Mode: 0o644, Data: []byte("live data plane")},
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	manifest := packageManifest{Schema: "kurd-node-native-package-v1", Version: "test", OS: "linux", Arch: "amd64", GoVersion: "go version go1.26.5 test", SourceCommit: strings.Repeat("a", 40), RelayDataPlane: true, StateVersion: 2, Files: []fileDigest{}}
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
