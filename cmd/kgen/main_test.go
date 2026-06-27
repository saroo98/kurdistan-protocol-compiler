package main

import (
	"os"
	"path/filepath"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func TestRunGeneratesAndRefusesOverwrite(t *testing.T) {
	p, err := compiler.Generate(12345)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(t.TempDir(), "profile.json")
	if err := ir.SaveProfile(profilePath, p); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "generated")

	if code := run([]string{"--profile", profilePath, "--out", out}); code != 0 {
		t.Fatalf("run generate exit = %d, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(out, "manifest.json")); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	if code := run([]string{"--profile", profilePath, "--out", out}); code == 0 {
		t.Fatalf("run overwrite without force exit = 0, want failure")
	}
	if code := run([]string{"--profile", profilePath, "--out", out, "--force"}); code != 0 {
		t.Fatalf("run force exit = %d, want 0", code)
	}
}

func TestRunRejectsInvalidProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(path, []byte(`{"version":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--profile", path, "--out", filepath.Join(t.TempDir(), "out")}); code == 0 {
		t.Fatalf("run accepted invalid profile")
	}
}
