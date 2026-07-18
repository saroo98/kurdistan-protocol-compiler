// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGenerateRequiresFreshOutputDirectory(t *testing.T) {
	out := filepath.Join(t.TempDir(), "fixtures")
	if err := generate(out); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(out, "canonical-profile-v1.hex"))
	if err != nil {
		t.Fatal(err)
	}
	if err := generate(out); err == nil {
		t.Fatal("generator accepted an existing output directory")
	}
	after, err := os.ReadFile(filepath.Join(out, "canonical-profile-v1.hex"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("generator changed an existing fixture")
	}
}

func TestWriteRefusesExistingFixedFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixtures")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "canonical-profile-v1.hex")
	if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := write(dir, "canonical-profile-v1.hex", []byte("replacement")); err == nil {
		t.Fatal("fixed fixture path was overwritten")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "preserve" {
		t.Fatalf("existing fixture changed: %q", got)
	}
}

func TestCLIReturnsFailureForExistingOutput(t *testing.T) {
	out := filepath.Join(t.TempDir(), "fixtures")
	first := exec.Command("go", "run", ".", "--out", out)
	if raw, err := first.CombinedOutput(); err != nil {
		t.Fatalf("first CLI generation failed: %v\n%s", err, raw)
	}
	second := exec.Command("go", "run", ".", "--out", out)
	if raw, err := second.CombinedOutput(); err == nil {
		t.Fatalf("second CLI generation unexpectedly passed:\n%s", raw)
	}
}
