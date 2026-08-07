// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command kurdpackage builds and verifies deterministic Phase 17 native
// engineering packages. Distribution signing remains a Phase 19 authority.
package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxArchiveBytes = 128 << 20

var nativeSourceMappingsV1 = map[string]string{
	"deploy/selfhost/native/kurd-node.service":         "systemd/kurd-node.service",
	"deploy/selfhost/native/kurd-node.socket":          "systemd/kurd-node.socket",
	"deploy/selfhost/native/kurd-node-network.service": "systemd/kurd-node-network.service",
	"deploy/selfhost/native/kurd-node.sysusers.conf":   "systemd/kurd-node.sysusers.conf",
	"deploy/selfhost/native/kurd-node.tmpfiles.conf":   "systemd/kurd-node.tmpfiles.conf",
	"deploy/selfhost/native/80-kurd0.netdev":           "networkd/80-kurd0.netdev",
	"deploy/selfhost/native/80-kurd0.network":          "networkd/80-kurd0.network",
	"deploy/selfhost/native/90-kurd-node.conf":         "sysctl/90-kurd-node.conf",
	"deploy/selfhost/native/kurd-node.nft":             "nftables/kurd-node.nft",
	"deploy/selfhost/native/kurd-node-unbound.conf":    "unbound/kurd-node-unbound.conf",
	"deploy/selfhost/native/install.sh":                "install.sh",
	"deploy/selfhost/native/preflight.sh":              "preflight.sh",
	"deploy/selfhost/native/rollback.sh":               "rollback.sh",
	"deploy/selfhost/native/uninstall.sh":              "uninstall.sh",
	"deploy/selfhost/native/upgrade.sh":                "upgrade.sh",
	"docs/self-hosting/QUICKSTART.md":                  "docs/QUICKSTART.md",
	"docs/self-hosting/INSTALL.md":                     "docs/INSTALL.md",
	"docs/self-hosting/CONTAINER.md":                   "docs/CONTAINER.md",
	"docs/self-hosting/SECURITY.md":                    "docs/SECURITY.md",
	"docs/self-hosting/LIVE-DATA-PLANE.md":             "docs/LIVE-DATA-PLANE.md",
	"docs/self-hosting/BACKUP-RESTORE.md":              "docs/BACKUP-RESTORE.md",
	"docs/self-hosting/UPGRADE-ROLLBACK.md":            "docs/UPGRADE-ROLLBACK.md",
	"docs/self-hosting/TROUBLESHOOTING.md":             "docs/TROUBLESHOOTING.md",
	"LICENSE":                                          "docs/LICENSE",
	"NOTICE":                                           "docs/NOTICE",
}

var requiredNativeFilesV1 = map[string]int64{
	"systemd/kurd-node.service":         0o644,
	"systemd/kurd-node.socket":          0o644,
	"systemd/kurd-node-network.service": 0o644,
	"systemd/kurd-node.sysusers.conf":   0o644,
	"systemd/kurd-node.tmpfiles.conf":   0o644,
	"networkd/80-kurd0.netdev":          0o640,
	"networkd/80-kurd0.network":         0o644,
	"sysctl/90-kurd-node.conf":          0o644,
	"nftables/kurd-node.nft":            0o600,
	"unbound/kurd-node-unbound.conf":    0o644,
}

type packageFile struct {
	Path string
	Mode int64
	Data []byte
}

type fileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type packageManifest struct {
	Schema         string       `json:"schema"`
	Version        string       `json:"version"`
	OS             string       `json:"os"`
	Arch           string       `json:"arch"`
	GoVersion      string       `json:"goVersion"`
	SourceCommit   string       `json:"sourceCommit"`
	Dirty          bool         `json:"dirty"`
	Signed         bool         `json:"signed"`
	RelayDataPlane bool         `json:"relayDataPlane"`
	StateVersion   uint64       `json:"stateVersion"`
	Files          []fileDigest `json:"files"`
}

type moduleRecord struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Sum      string `json:"sum"`
	GoModSum string `json:"goModSum"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "kurdpackage:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: kurdpackage <build|verify>")
	}
	switch args[0] {
	case "build":
		set := flag.NewFlagSet("build", flag.ContinueOnError)
		set.SetOutput(io.Discard)
		root := set.String("root", ".", "repository root")
		out := set.String("out", ".tools/phase17/packages", "output directory")
		version := set.String("version", "0.17.0-dev", "package version")
		arches := set.String("arches", "amd64,arm64", "comma-separated Linux architectures")
		if set.Parse(args[1:]) != nil || set.NArg() != 0 {
			return errors.New("invalid build arguments")
		}
		paths, err := buildPackages(*root, *out, *version, strings.Split(*arches, ","))
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(map[string]any{"schema": "kurd-node-package-set-v1", "signed": false, "relayDataPlane": true, "archives": paths})
	case "verify":
		set := flag.NewFlagSet("verify", flag.ContinueOnError)
		set.SetOutput(io.Discard)
		archive := set.String("archive", "", "package archive")
		if set.Parse(args[1:]) != nil || set.NArg() != 0 || *archive == "" {
			return errors.New("invalid verify arguments")
		}
		manifest, err := verifyArchive(*archive)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(manifest)
	default:
		return errors.New("unknown command")
	}
}

func buildPackages(root, out, version string, arches []string) ([]string, error) {
	root, err := filepath.Abs(root)
	if err != nil || version == "" || strings.ContainsAny(version, "/\\\r\n") {
		return nil, errors.New("invalid package root or version")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	commit, dirty, err := gitIdentity(root)
	if err != nil {
		return nil, err
	}
	goVersionRaw, err := exec.Command("go", "version").Output()
	if err != nil {
		return nil, err
	}
	modules, err := listModules(root)
	if err != nil {
		return nil, err
	}
	moduleJSON, err := json.MarshalIndent(struct {
		Schema  string         `json:"schema"`
		Modules []moduleRecord `json:"modules"`
	}{"kurd-node-third-party-modules-v1", modules}, "", "  ")
	if err != nil {
		return nil, err
	}
	moduleJSON = append(moduleJSON, '\n')
	var outputs []string
	seen := map[string]bool{}
	for _, arch := range arches {
		arch = strings.TrimSpace(arch)
		if arch != "amd64" && arch != "arm64" || seen[arch] {
			return nil, fmt.Errorf("invalid or duplicate architecture %q", arch)
		}
		seen[arch] = true
		temporary, err := os.MkdirTemp("", "kurd-node-package-*")
		if err != nil {
			return nil, err
		}
		files, buildErr := packageFiles(root, temporary, version, arch, commit, dirty, strings.TrimSpace(string(goVersionRaw)), moduleJSON)
		if buildErr != nil {
			os.RemoveAll(temporary)
			return nil, buildErr
		}
		archive := filepath.Join(out, fmt.Sprintf("kurd-node-%s-linux-%s.tar.gz", version, arch))
		if err := writeArchive(archive, fmt.Sprintf("kurd-node-%s-linux-%s", version, arch), files); err != nil {
			os.RemoveAll(temporary)
			return nil, err
		}
		os.RemoveAll(temporary)
		if _, err := verifyArchive(archive); err != nil {
			return nil, err
		}
		outputs = append(outputs, archive)
	}
	return outputs, nil
}

func packageFiles(root, temporary, version, arch, commit string, dirty bool, goVersion string, moduleJSON []byte) ([]packageFile, error) {
	files := []packageFile{}
	for _, command := range []string{"kurd-node", "kurdctl"} {
		output := filepath.Join(temporary, command)
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -buildid=", "-o", output, "./cmd/"+command)
		cmd.Dir = root
		cmd.Env = append(withoutEnv(os.Environ(), "GOOS", "GOARCH", "CGO_ENABLED"), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
		if result, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("build %s/%s: %w: %s", command, arch, err, result)
		}
		data, err := os.ReadFile(output)
		if err != nil {
			return nil, err
		}
		files = append(files, packageFile{Path: "bin/" + command, Mode: 0o755, Data: data})
	}
	keys := make([]string, 0, len(nativeSourceMappingsV1))
	for source := range nativeSourceMappingsV1 {
		keys = append(keys, source)
	}
	sort.Strings(keys)
	for _, source := range keys {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(source)))
		if err != nil {
			return nil, err
		}
		packagePath := nativeSourceMappingsV1[source]
		files = append(files, packageFile{Path: packagePath, Mode: nativeModeForPackagePathV1(packagePath), Data: data})
	}
	files = append(files, packageFile{Path: "THIRD_PARTY_MODULES.json", Mode: 0o644, Data: moduleJSON})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	manifest := packageManifest{Schema: "kurd-node-native-package-v1", Version: version, OS: "linux", Arch: arch, GoVersion: goVersion, SourceCommit: commit, Dirty: dirty, Signed: false, RelayDataPlane: true, StateVersion: 2}
	for _, file := range files {
		manifest.Files = append(manifest.Files, digestFile(file))
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	files = append(files, packageFile{Path: "manifest.json", Mode: 0o644, Data: append(manifestJSON, '\n')})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	var sums strings.Builder
	for _, file := range files {
		digest := sha256.Sum256(file.Data)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(digest[:]), file.Path)
	}
	files = append(files, packageFile{Path: "SHA256SUMS", Mode: 0o644, Data: []byte(sums.String())})
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	return files, nil
}

func writeArchive(destination, rootName string, files []packageFile) error {
	if rootName == "" || strings.ContainsAny(rootName, "/\\") {
		return errors.New("invalid archive root")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	failed := true
	defer func() {
		file.Close()
		if failed {
			os.Remove(destination)
		}
	}()
	zipper, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	zipper.Header.ModTime = time.Unix(0, 0).UTC()
	zipper.Header.OS = 255
	tarWriter := tar.NewWriter(zipper)
	for _, entry := range files {
		header := &tar.Header{Name: rootName + "/" + filepath.ToSlash(entry.Path), Mode: entry.Mode, Size: int64(len(entry.Data)), ModTime: time.Unix(0, 0).UTC(), AccessTime: time.Unix(0, 0).UTC(), ChangeTime: time.Unix(0, 0).UTC(), Uid: 0, Gid: 0, Uname: "root", Gname: "root", Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tarWriter.Write(entry.Data); err != nil {
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := zipper.Close(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	failed = false
	return nil
}

func verifyArchive(path string) (packageManifest, error) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() <= 0 || info.Size() > maxArchiveBytes {
		return packageManifest{}, errors.New("archive size or type rejected")
	}
	file, err := os.Open(path)
	if err != nil {
		return packageManifest{}, err
	}
	defer file.Close()
	zipper, err := gzip.NewReader(file)
	if err != nil {
		return packageManifest{}, err
	}
	defer zipper.Close()
	reader := tar.NewReader(zipper)
	entries := map[string][]byte{}
	root := ""
	total := int64(0)
	previousName := ""
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > maxArchiveBytes ||
			header.Uid != 0 || header.Gid != 0 || header.Uname != "root" || header.Gname != "root" || !header.ModTime.Equal(time.Unix(0, 0).UTC()) {
			return packageManifest{}, errors.New("archive entry rejected")
		}
		name := filepath.ToSlash(header.Name)
		if previousName != "" && name <= previousName {
			return packageManifest{}, errors.New("archive ordering rejected")
		}
		previousName = name
		parts := strings.Split(name, "/")
		if len(parts) < 2 || parts[0] == "" || strings.Contains(parts[0], "..") || strings.Contains(name, "\\") {
			return packageManifest{}, errors.New("archive path rejected")
		}
		if root == "" {
			root = parts[0]
		}
		if parts[0] != root {
			return packageManifest{}, errors.New("multiple archive roots")
		}
		relative := strings.Join(parts[1:], "/")
		if relative == "" || relative != filepath.ToSlash(filepath.Clean(relative)) || strings.HasPrefix(relative, "../") {
			return packageManifest{}, errors.New("non-canonical archive path")
		}
		if _, duplicate := entries[relative]; duplicate {
			return packageManifest{}, errors.New("duplicate archive entry")
		}
		wantMode := nativeModeForPackagePathV1(relative)
		if header.Mode != wantMode {
			return packageManifest{}, fmt.Errorf("archive mode rejected for %s", relative)
		}
		total += header.Size
		if total > maxArchiveBytes {
			return packageManifest{}, errors.New("expanded archive size rejected")
		}
		value, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(value)) != header.Size {
			return packageManifest{}, errors.New("truncated archive entry")
		}
		entries[relative] = value
	}
	for _, required := range []string{"bin/kurd-node", "bin/kurdctl", "install.sh", "preflight.sh", "rollback.sh", "uninstall.sh", "upgrade.sh", "manifest.json", "SHA256SUMS", "THIRD_PARTY_MODULES.json", "docs/INSTALL.md", "docs/CONTAINER.md", "docs/LIVE-DATA-PLANE.md"} {
		if len(entries[required]) == 0 {
			return packageManifest{}, fmt.Errorf("missing package file %s", required)
		}
	}
	for required, mode := range requiredNativeFilesV1 {
		if len(entries[required]) == 0 || nativeModeForPackagePathV1(required) != mode {
			return packageManifest{}, fmt.Errorf("missing native package asset %s", required)
		}
	}
	if err := verifySums(entries["SHA256SUMS"], entries); err != nil {
		return packageManifest{}, err
	}
	var manifest packageManifest
	decoder := json.NewDecoder(strings.NewReader(string(entries["manifest.json"])))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || manifest.Schema != "kurd-node-native-package-v1" || manifest.Version == "" ||
		manifest.OS != "linux" || manifest.Arch != "amd64" && manifest.Arch != "arm64" || !validHex(manifest.SourceCommit, 40) ||
		!strings.HasPrefix(manifest.GoVersion, "go version go") || manifest.Signed || !manifest.RelayDataPlane || manifest.StateVersion != 2 {
		return packageManifest{}, errors.New("package manifest rejected")
	}
	if len(manifest.Files) != len(entries)-2 {
		return packageManifest{}, errors.New("package manifest inventory incomplete")
	}
	seenManifest := map[string]bool{}
	previousManifestPath := ""
	for _, expected := range manifest.Files {
		value, ok := entries[expected.Path]
		if !ok || expected.Path == "manifest.json" || expected.Path == "SHA256SUMS" || seenManifest[expected.Path] ||
			expected.Path <= previousManifestPath || digestFile(packageFile{Path: expected.Path, Data: value}) != expected {
			return packageManifest{}, fmt.Errorf("manifest digest mismatch for %s", expected.Path)
		}
		seenManifest[expected.Path] = true
		previousManifestPath = expected.Path
	}
	return manifest, nil
}

func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func verifySums(encoded []byte, entries map[string][]byte) error {
	scanner := bufio.NewScanner(strings.NewReader(string(encoded)))
	seen := map[string]bool{}
	previousPath := ""
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return errors.New("checksum line rejected")
		}
		digest, path := line[:64], line[66:]
		value, ok := entries[path]
		if !ok || seen[path] || path <= previousPath {
			return errors.New("checksum path rejected")
		}
		previousPath = path
		observed := sha256.Sum256(value)
		if hex.EncodeToString(observed[:]) != digest {
			return errors.New("checksum mismatch")
		}
		seen[path] = true
	}
	if scanner.Err() != nil || len(seen) != len(entries)-1 {
		return errors.New("checksum inventory incomplete")
	}
	return nil
}

func nativeModeForPackagePathV1(path string) int64 {
	if mode, ok := requiredNativeFilesV1[path]; ok {
		return mode
	}
	if strings.HasPrefix(path, "bin/") || strings.HasSuffix(path, ".sh") {
		return 0o755
	}
	return 0o644
}

func nativeSourceForPackagePathV1(path string) string {
	for source, packagePath := range nativeSourceMappingsV1 {
		if packagePath == path {
			return source
		}
	}
	return ""
}

func digestFile(file packageFile) fileDigest {
	digest := sha256.Sum256(file.Data)
	return fileDigest{Path: file.Path, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(file.Data))}
}

func gitIdentity(root string) (string, bool, error) {
	command := exec.Command("git", "rev-parse", "HEAD")
	command.Dir = root
	value, err := command.Output()
	if err != nil {
		return "", false, err
	}
	commit := strings.TrimSpace(string(value))
	if len(commit) != 40 {
		return "", false, errors.New("invalid Git commit")
	}
	command = exec.Command("git", "status", "--porcelain")
	command.Dir = root
	status, err := command.Output()
	return commit, len(status) != 0, err
}

func listModules(root string) ([]moduleRecord, error) {
	command := exec.Command("go", "list", "-m", "-json", "all")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	var result []moduleRecord
	for {
		var value struct {
			Path, Version, Sum, GoModSum string
			Replace                      *struct{ Path, Dir string }
		}
		if err := decoder.Decode(&value); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		if value.Replace != nil && value.Replace.Dir != "" {
			return nil, errors.New("local module replacement is not packageable")
		}
		result = append(result, moduleRecord{Path: value.Path, Version: value.Version, Sum: value.Sum, GoModSum: value.GoModSum})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Path < result[right].Path })
	return result, nil
}

func withoutEnv(environment []string, names ...string) []string {
	blocked := map[string]bool{}
	for _, name := range names {
		blocked[strings.ToUpper(name)] = true
	}
	result := make([]string, 0, len(environment))
	for _, value := range environment {
		name := value
		if index := strings.IndexByte(value, '='); index >= 0 {
			name = value[:index]
		}
		if !blocked[strings.ToUpper(name)] {
			result = append(result, value)
		}
	}
	return result
}
