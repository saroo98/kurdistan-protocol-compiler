// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func makeJunction(t *testing.T, link, target string) {
	t.Helper()
	if strings.ContainsAny(link, " \t") || strings.ContainsAny(target, " \t") {
		t.Skip("junction test requires a space-free temporary path")
	}
	command := "mklink /J " + link + " " + target
	output, err := exec.Command(os.Getenv("ComSpec"), "/c", command).CombinedOutput()
	if err != nil {
		t.Skipf("junction creation unavailable: %v: %s", err, output)
	}
}

func TestWindowsRootedPathsRejectJunctionSwaps(t *testing.T) {
	t.Run("parent", func(t *testing.T) {
		base := t.TempDir()
		parent := filepath.Join(base, "trusted")
		attack := filepath.Join(base, "attack")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(attack, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, "input")
		if err := os.WriteFile(path, []byte("trusted"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(attack, "input"), []byte("attack"), 0o600); err != nil {
			t.Fatal(err)
		}
		retained := parent + "-retained"
		got, err := readBoundedLocalWithHook(path, func() {
			if err := os.Rename(parent, retained); err != nil {
				t.Fatal(err)
			}
			makeJunction(t, parent, attack)
		})
		if err != nil || string(got) != "trusted" {
			t.Fatalf("input followed replacement junction: data=%q err=%v", got, err)
		}
	})

	t.Run("final", func(t *testing.T) {
		base := t.TempDir()
		path := filepath.Join(base, "output")
		attack := filepath.Join(base, "attack")
		if err := os.Mkdir(attack, 0o700); err != nil {
			t.Fatal(err)
		}
		err := writeNewLocalWithHook(path, []byte("trusted"), func() {
			makeJunction(t, path, attack)
		})
		if err == nil {
			t.Fatal("accepted final junction output replacement")
		}
		if _, err := os.Lstat(filepath.Join(attack, "output")); !os.IsNotExist(err) {
			t.Fatalf("output followed final junction: %v", err)
		}
	})
}
