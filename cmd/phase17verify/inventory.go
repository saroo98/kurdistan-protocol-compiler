// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const phase17InventorySHA256 = "5834931fd2ce09585372bd09afc386d7eb55a3d7b9cb8c9938df6d4a0c24c4e7"

var (
	packageDeclaration = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)\s*$`)
	classDeclaration   = regexp.MustCompile(`(?m)^\s*(?:internal\s+|public\s+|private\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)\b`)
	testDeclaration    = regexp.MustCompile(`(?m)^\s*@Test\s*\r?\n\s*fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
)

func verifyDeviceTestInventory(root string) error {
	manifestPath := filepath.Join(root, "android", "config", "phase17-required-device-tests.txt")
	manifest, raw, err := readDeviceManifest(manifestPath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil && hex.EncodeToString(digest[:]) != phase17InventorySHA256 {
		return errors.New("Phase 17 required device-test inventory digest is not authoritative")
	}
	source, err := discoverAndroidDeviceTests(filepath.Join(root, "android", "app", "src", "androidTest", "kotlin"))
	if err != nil {
		return err
	}
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
	if len(raw) == 0 || len(raw) > 256<<10 {
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
	result := make(map[string]struct{})
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".kt") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > 512<<10 {
			return fmt.Errorf("Android device-test source is oversized: %s", path)
		}
		total += info.Size()
		if total > 8<<20 {
			return errors.New("Android device-test sources exceed the bounded inventory budget")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		packageMatch := packageDeclaration.FindSubmatch(raw)
		classMatch := classDeclaration.FindSubmatch(raw)
		tests := testDeclaration.FindAllSubmatch(raw, -1)
		if len(tests) == 0 {
			return nil
		}
		if len(packageMatch) != 2 || len(classMatch) != 2 {
			return fmt.Errorf("cannot identify test package/class in %s", path)
		}
		className := string(packageMatch[1]) + "." + string(classMatch[1])
		for _, test := range tests {
			name := className + "#" + string(test[1])
			if _, duplicate := result[name]; duplicate {
				return fmt.Errorf("duplicate Android device test %q", name)
			}
			result[name] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover Android device tests: %w", err)
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
