// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func TestWriteExclusiveAtomicPublishesExactlyOneCompleteResult(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "field-result.json")
	start := make(chan struct{})
	results := make(chan error, 2)
	values := [][]byte{[]byte("first-result"), []byte("second-result")}
	var group sync.WaitGroup
	for _, value := range values {
		value := append([]byte(nil), value...)
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- writeExclusiveAtomic(path, value, 0o600, syncFieldEvidenceDirectory)
		}()
	}
	close(start)
	group.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful result publications=%d, want exactly one", succeeded)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, values[0]) && !bytes.Equal(raw, values[1]) {
		t.Fatalf("partial or unexpected result=%q", raw)
	}
}

func TestWriteExclusiveAtomicFailsClosedWhenDirectorySyncFails(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "field-result.json")
	want := errors.New("synthetic directory sync failure")
	called := 0
	err := writeExclusiveAtomic(path, []byte("complete-result"), 0o600, func(got string) error {
		called++
		if got != directory {
			t.Fatalf("synced directory=%q, want %q", got, directory)
		}
		return want
	})
	if !errors.Is(err, want) || called != 1 {
		t.Fatalf("error=%v sync calls=%d", err, called)
	}
	if raw, readErr := os.ReadFile(path); readErr != nil || string(raw) != "complete-result" {
		t.Fatalf("published result after sync failure=%q error=%v", raw, readErr)
	}
}

func TestWriteExclusiveAtomicFailsClosedBeforePublicationForStorageAndPermissionFaults(t *testing.T) {
	for name, mutate := range map[string]func(*atomicEvidenceOps, error){
		"disk full while writing": func(operations *atomicEvidenceOps, want error) {
			operations.write = func(*os.File, []byte) (int, error) { return 0, want }
		},
		"permission denied while creating": func(operations *atomicEvidenceOps, want error) {
			operations.createTemp = func(string, string) (*os.File, error) { return nil, want }
		},
		"publication interrupted before link": func(operations *atomicEvidenceOps, want error) {
			operations.link = func(string, string) error { return want }
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "field-result.json")
			want := syscall.ENOSPC
			if name == "permission denied while creating" {
				want = syscall.EACCES
			}
			operations := systemAtomicEvidenceOps()
			mutate(&operations, want)
			err := writeExclusiveAtomicWithOps(path, []byte("complete-result"), 0o600, syncFieldEvidenceDirectory, operations)
			if !errors.Is(err, want) {
				t.Fatalf("error=%v, want %v", err, want)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed publication created destination: %v", err)
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("failed publication retained temporary entries: %v", entries)
			}
		})
	}
}
