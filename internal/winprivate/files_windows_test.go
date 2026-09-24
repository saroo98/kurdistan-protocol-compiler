// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package winprivate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRootRequiresAbsoluteLocalDrive(t *testing.T) {
	path := t.TempDir()
	want := filepath.VolumeName(path) + string(os.PathSeparator)
	if got, err := Root(path); err != nil || got != want {
		t.Fatalf("root=%q err=%v, want %q", got, err, want)
	}
	for _, path := range []string{"relative", `\rooted`, `\\server\share\file`, `\\?\` + path, `\\.\` + path} {
		if got, err := Root(path); got != "" || err == nil || err.Error() != "absolute local drive path required" {
			t.Fatalf("Root(%q)=%q, %v", path, got, err)
		}
	}
}

func TestDirectoryPostVerificationFailureRetainsCreatedDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "created")
	injected := errors.New("injected")
	calls := 0
	created, err := createDirectoryWithOperations(path, creationOperations{verify: func(got string, directory bool) error {
		calls++
		if got != path || !directory {
			t.Fatalf("verification subject=%q directory=%t", got, directory)
		}
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			t.Fatalf("verification ran before directory creation: %v", err)
		}
		return injected
	}})
	if !created || !errors.Is(err, ErrUnsafe) || errors.Is(err, injected) || calls != 1 {
		t.Fatalf("created=%t err=%v verification calls=%d", created, err, calls)
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatalf("created directory not retained: %v", err)
	}
}

func TestFilePostVerificationFailureRemovesOnlyNewFile(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "created")
	existing := filepath.Join(parent, "existing")
	if err := os.WriteFile(existing, []byte("previous"), 0600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected")
	calls := 0
	err := writeFileWithOperations(path, []byte("value"), creationOperations{verify: func(got string, directory bool) error {
		calls++
		if got != path || directory {
			t.Fatalf("verification subject=%q directory=%t", got, directory)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("verification ran before creation: %v", err)
		}
		return injected
	}})
	if !errors.Is(err, injected) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new file retained: %v", err)
	}
	if value, err := os.ReadFile(existing); err != nil || string(value) != "previous" {
		t.Fatalf("existing file changed: %v", err)
	}
}

func TestNilCreationVerifierCreatesNothing(t *testing.T) {
	parent := t.TempDir()
	directory, file := filepath.Join(parent, "directory"), filepath.Join(parent, "file")
	if created, err := createDirectoryWithOperations(directory, creationOperations{}); created || !errors.Is(err, ErrUnsafe) {
		t.Fatalf("created=%t err=%v", created, err)
	}
	if err := writeFileWithOperations(file, []byte("value"), creationOperations{}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("err=%v", err)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("created entries=%v err=%v", entries, err)
	}
}

func TestExclusiveCollisionsPreserveExistingSubjects(t *testing.T) {
	parent := t.TempDir()
	directory, file := filepath.Join(parent, "directory"), filepath.Join(parent, "file")
	if created, err := CreateDirectory(directory); !created || err != nil {
		t.Fatalf("created=%t err=%v", created, err)
	}
	if err := WriteFileExclusive(file, []byte("previous")); err != nil {
		t.Fatal(err)
	}
	if err := Verify(directory, true); err != nil {
		t.Fatal(err)
	}
	if err := Verify(file, false); err != nil {
		t.Fatal(err)
	}
	if created, err := CreateDirectory(directory); created || !errors.Is(err, ErrExists) {
		t.Fatalf("created=%t err=%v", created, err)
	}
	if err := WriteFileExclusive(file, []byte("replacement")); !errors.Is(err, ErrExists) {
		t.Fatalf("collision=%v", err)
	}
	if value, err := os.ReadFile(file); err != nil || string(value) != "previous" {
		t.Fatalf("collision changed file: %v", err)
	}
	if err := EnsureDirectory(directory); err != nil {
		t.Fatalf("private collision rejected: %v", err)
	}
	if err := EnsureDirectory(file); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("file accepted as directory: %v", err)
	}
}

func TestCreationAndEnsureRejectReparseComponents(t *testing.T) {
	parent := t.TempDir()
	target, link := filepath.Join(parent, "target"), filepath.Join(parent, "junction")
	if created, err := CreateDirectory(target); !created || err != nil {
		t.Fatalf("created=%t err=%v", created, err)
	}
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("create bounded directory junction: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if err := os.Remove(link); err != nil {
			t.Errorf("remove junction: %v", err)
		}
	})
	if created, err := CreateDirectory(filepath.Join(link, "new-directory")); created || !errors.Is(err, ErrUnsafe) {
		t.Fatalf("reparse directory created=%t err=%v", created, err)
	}
	if err := WriteFileExclusive(filepath.Join(link, "new-file"), []byte("value")); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("reparse file=%v", err)
	}
	if err := EnsureDirectory(link); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("reparse ensure=%v", err)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("reparse target mutated: %v %v", entries, err)
	}
}
