// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"kurdistan/internal/testkit/evidenceoverlay"
)

const phase17InventoryCommit = "7d583d186c7e5fbb6fc1e9843049ad8edb940a0a"
const phase17InventoryTree = "7d641e7d780f2d628a147baee24b05a305cfdeaf"
const currentDeviceManifestPath = "android/config/phase18-current-device-tests.txt"

const phase17InventorySHA256 = "ae6107c91182b4c74e4263bc64af1859c6963ed6a9a89495e34454a9e9e84e3c"

var (
	packageDeclaration = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)\s*$`)
	classDeclaration   = regexp.MustCompile(`(?m)^\s*(?:internal\s+|public\s+|private\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
	testDeclaration    = regexp.MustCompile(`(?m)^[ \t]*@Test(?:[ \t]*\r?\n[ \t]*|[ \t]+)fun[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(`)
)

func verifyDeviceTestInventory(root string) error {
	if err := verifyPhase17HistoricalDeviceInventory(root); err != nil {
		return err
	}
	return verifyCurrentDeviceInventory(root)
}

func verifyPhase17HistoricalDeviceInventory(root string) error {
	const manifestPath = "android/config/phase17-required-device-tests.txt"
	current, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(manifestPath)))
	if err != nil {
		return err
	}
	if err := verifyFrozenDeviceManifestDigest(current); err != nil {
		return err
	}
	subject, err := evidenceoverlay.OpenExactSubject(root, phase17InventoryCommit, phase17InventoryTree)
	if err != nil {
		return err
	}
	manifestFile, err := subject.Read(manifestPath)
	if err != nil {
		return err
	}
	if err := verifyFrozenDeviceManifestDigest(manifestFile.Content); err != nil {
		return err
	}
	manifest, _, err := parseDeviceManifest(manifestFile.Content)
	if err != nil {
		return err
	}
	files := map[string][]byte{}
	for _, path := range subject.Paths() {
		if !strings.HasPrefix(path, "android/app/src/androidTest/kotlin/") || !strings.HasSuffix(path, ".kt") {
			continue
		}
		file, err := subject.Read(path)
		if err != nil {
			return err
		}
		files[path] = file.Content
	}
	source, err := discoverAndroidDeviceTestFiles(files)
	if err != nil {
		return err
	}
	return verifyExactDeviceInventory(manifest, source)
}

func verifyFrozenDeviceManifestDigest(raw []byte) error {
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != phase17InventorySHA256 {
		return errors.New("Phase 17 required device-test inventory digest is not authoritative")
	}
	return nil
}

func verifyCurrentDeviceInventory(root string) error {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(currentDeviceManifestPath)))
	if err != nil {
		return err
	}
	frozen, err := os.ReadFile(filepath.Join(root, "android/config/phase17-required-device-tests.txt"))
	if err != nil {
		return err
	}
	if err := verifyFrozenDeviceManifestDigest(frozen); err != nil {
		return err
	}
	manifest, err := validateCurrentDeviceManifest(raw, frozen)
	if err != nil {
		return err
	}
	source, err := discoverAndroidDeviceTests(filepath.Join(root, "android/app/src/androidTest/kotlin"))
	if err != nil {
		return err
	}
	return verifyExactDeviceInventory(manifest, source)
}

func validateCurrentDeviceManifest(raw, frozen []byte) (map[string]int, error) {
	manifest, _, err := parseDeviceManifest(raw)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, '\r') || raw[len(raw)-1] != '\n' {
		return nil, errors.New("current inventory must be canonical LF with final newline")
	}
	original, _, err := parseDeviceManifest(frozen)
	if err != nil {
		return nil, err
	}
	previous := ""
	records := map[string]bool{}
	for _, line := range strings.Split(string(raw[:len(raw)-1]), "\n") {
		name := line
		if strings.HasPrefix(line, "minSdk=") {
			_, name, _ = strings.Cut(line, " ")
		}
		if strings.TrimSpace(line) != line || name <= previous || !validTestName(name) {
			return nil, errors.New("current inventory is not in canonical name order")
		}
		previous = name
		records[line] = true
	}
	for _, line := range strings.Split(strings.TrimSpace(string(frozen)), "\n") {
		if !records[line] {
			return nil, errors.New("frozen inventory record or minimum lane changed")
		}
	}
	const locale = "org.kurdistanvpn.app.ProductLocaleLifecycleDeviceTest#applicationLocaleRecreationKeepsRealActivityAndFilterModalInTheSameLanguage"
	for name, lane := range manifest {
		if _, old := original[name]; old {
			continue
		}
		want := 26
		if name == locale {
			want = 34
		}
		if lane != want {
			return nil, fmt.Errorf("current inventory minimum lane changed for %s", name)
		}
	}
	return manifest, nil
}

func verifyExactDeviceInventory(manifest map[string]int, source map[string]struct{}) error {
	for name := range manifest {
		if _, ok := source[name]; !ok {
			return fmt.Errorf("required device test %q does not exist in source", name)
		}
	}
	for name := range source {
		if _, ok := manifest[name]; !ok {
			return fmt.Errorf("unexpected device test %q is absent from the exact inventory", name)
		}
	}
	return nil
}

func readDeviceManifest(path string) (map[string]int, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read required device-test inventory: %w", err)
	}
	return parseDeviceManifest(raw)
}

func parseDeviceManifest(raw []byte) (map[string]int, []byte, error) {
	var err error
	if len(raw) == 0 || len(raw) > 256<<10 || !utf8.Valid(raw) {
		return nil, nil, errors.New("required device-test inventory is empty or oversized")
	}
	result := make(map[string]int)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		minimum := 26
		if strings.HasPrefix(line, "minSdk=") {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				return nil, nil, fmt.Errorf("invalid required device-test line %q", line)
			}
			minimum, err = strconv.Atoi(strings.TrimPrefix(parts[0], "minSdk="))
			if err != nil || minimum != 26 && minimum != 34 && minimum != 36 {
				return nil, nil, fmt.Errorf("invalid minimum SDK in %q", line)
			}
			line = strings.TrimSpace(parts[1])
		}
		if !validTestName(line) {
			return nil, nil, fmt.Errorf("invalid required device-test name %q", line)
		}
		if _, duplicate := result[line]; duplicate {
			return nil, nil, fmt.Errorf("duplicate required device test %q", line)
		}
		result[line] = minimum
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	if len(result) == 0 {
		return nil, nil, errors.New("required device-test inventory contains no tests")
	}
	return result, raw, nil
}

func discoverAndroidDeviceTests(root string) (map[string]struct{}, error) {
	files := map[string][]byte{}
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("Android device-test source alias: %s", path)
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".kt") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 512<<10 {
			return fmt.Errorf("Android device-test source is not bounded regular text: %s", path)
		}
		total += info.Size()
		if total > 8<<20 {
			return errors.New("Android device-test sources exceed the bounded inventory budget")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if int64(len(raw)) != info.Size() {
			return errors.New("Android device-test source changed during read")
		}
		files[path] = raw
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover Android device tests: %w", err)
	}
	return discoverAndroidDeviceTestFiles(files)
}

func discoverAndroidDeviceTestFiles(files map[string][]byte) (map[string]struct{}, error) {
	result := map[string]struct{}{}
	total := 0
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw := files[path]
		total += len(raw)
		if len(raw) > 512<<10 || total > 8<<20 || !utf8.Valid(raw) {
			return nil, errors.New("Android device-test source exceeds bounded UTF-8 inventory budget")
		}
		packageMatch := packageDeclaration.FindSubmatch(raw)
		classMatch := classDeclaration.FindSubmatch(raw)
		tests := testDeclaration.FindAllSubmatch(raw, -1)
		if len(tests) == 0 {
			continue
		}
		if len(packageMatch) != 2 || len(classMatch) != 2 {
			return nil, fmt.Errorf("cannot identify test package/class in %s", path)
		}
		className := string(packageMatch[1]) + "." + string(classMatch[1])
		for _, test := range tests {
			name := className + "#" + string(test[1])
			if _, duplicate := result[name]; duplicate {
				return nil, fmt.Errorf("duplicate Android device test %q", name)
			}
			result[name] = struct{}{}
		}
	}
	return result, nil
}

func validTestName(value string) bool {
	parts := strings.Split(value, "#")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '.' || character == '#' {
			continue
		}
		return false
	}
	return true
}
