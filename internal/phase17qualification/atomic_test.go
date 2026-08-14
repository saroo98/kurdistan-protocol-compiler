// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteExclusiveFilePublishesCompleteBytesAndPreservesExistingTarget(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "receipt.json")
	want := []byte(`{"status":"complete"}`)
	if err := WriteExclusiveFile(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("published bytes=%q, want %q", got, want)
	}
	if err := WriteExclusiveFile(path, []byte("replacement")); err == nil {
		t.Fatal("exclusive publication replaced an existing target")
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("existing target changed to %q", got)
	}
}

func TestWriteExclusiveFilePublicationFailureLeavesNoTargetOrTemporaryFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "receipt.json")
	injected := errors.New("injected publication failure")
	ops := defaultAtomicFileOps()
	ops.publish = func(_, _ string) error { return injected }
	if err := writeExclusiveFileWithOps(path, directory, []byte("complete"), ops); !errors.Is(err, injected) {
		t.Fatalf("error=%v, want injected publication failure", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed publication left target: %v", err)
	}
	assertDirectoryEmpty(t, directory)
}

func TestWriteExclusiveFileDirectorySyncFailureRollsBackPublishedTarget(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "receipt.json")
	injected := errors.New("injected directory sync failure")
	ops := defaultAtomicFileOps()
	ops.syncDirectory = func(string) error { return injected }
	if err := writeExclusiveFileWithOps(path, directory, []byte("complete"), ops); !errors.Is(err, injected) {
		t.Fatalf("error=%v, want injected directory sync failure", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory sync failure left an unconfirmed target: %v", err)
	}
	assertDirectoryEmpty(t, directory)
}

func TestWriteExclusiveFileDoesNotReportFailureAfterDurableCommitPoint(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "receipt.json")
	ops := defaultAtomicFileOps()
	remove := ops.remove
	removeCalls := 0
	ops.remove = func(path string) error {
		removeCalls++
		if removeCalls == 1 {
			return errors.New("injected post-commit cleanup failure")
		}
		return remove(path)
	}
	if err := writeExclusiveFileWithOps(path, directory, []byte("complete"), ops); err != nil {
		t.Fatalf("durably published target reported false failure: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "complete" {
		t.Fatalf("target=%q err=%v", got, err)
	}
}

func assertDirectoryEmpty(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory contains crash residue: %+v", entries)
	}
}
