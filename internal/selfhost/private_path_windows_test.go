// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package selfhost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestWindowsSelfhostSecretsAreProtectedAtCreation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-state")
	if err := createSelfhostPrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if err := verifySelfhostPrivatePath(directory, true); err != nil {
		t.Fatalf("created directory was not born private: %v", err)
	}
	path := filepath.Join(directory, "registry.key")
	if err := writeSelfhostPrivateFileExclusive(path, []byte("01234567890123456789012345678901")); err != nil {
		t.Fatal(err)
	}
	if err := verifySelfhostPrivatePath(path, false); err != nil {
		t.Fatalf("created key was not born private: %v", err)
	}
	if value, err := os.ReadFile(path); err != nil || len(value) != 32 {
		t.Fatalf("len=%d err=%v", len(value), err)
	}
}

func TestEnsureSelfhostPrivateDirectoryIsConcurrencySafe(t *testing.T) {
	const (
		rounds  = 32
		workers = 32
	)

	root := t.TempDir()
	for round := 0; round < rounds; round++ {
		directory := filepath.Join(root, fmt.Sprintf("private-%02d", round))
		start := make(chan struct{})
		results := make(chan error, workers)
		var group sync.WaitGroup
		for worker := 0; worker < workers; worker++ {
			group.Add(1)
			go func() {
				defer group.Done()
				<-start
				results <- ensureSelfhostPrivateDirectory(directory)
			}()
		}

		close(start)
		group.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Fatalf("round %d: concurrent private-directory preparation failed: %v", round, err)
			}
		}
	}
}

func TestEnsureSelfhostPrivateDirectoryRejectsUnprotectedExistingDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "unprotected")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ensureSelfhostPrivateDirectory(directory); !errors.Is(err, ErrRecipientRegistry) {
		t.Fatalf("unprotected existing directory error=%v, want recipient-registry rejection", err)
	}
}
