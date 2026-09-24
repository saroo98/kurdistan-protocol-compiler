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

	"kurdistan/internal/winprivate"
)

func TestWindowsSelfhostSecretsAreProtectedAtCreation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-state")
	if err := createSelfhostPrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if err := winprivate.Verify(directory, true); err != nil {
		t.Fatalf("created directory was not born private: %v", err)
	}
	path := filepath.Join(directory, "registry.key")
	if err := writeSelfhostPrivateFileExclusive(path, []byte("01234567890123456789012345678901")); err != nil {
		t.Fatal(err)
	}
	if err := winprivate.Verify(path, false); err != nil {
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

func TestSelfhostWindowsErrorMappingRetainsNestedCausesAndJoinOrder(t *testing.T) {
	injected := errors.New("injected")
	closed := errors.New("closed")
	err := mapSelfhostWindowsError(errors.Join(
		&winprivate.OpError{Op: "publish", Err: &winprivate.OpError{Op: "verify", Err: injected}},
		&winprivate.OpError{Op: "close", Err: closed},
	))
	if !errors.Is(err, ErrRecipientRegistry) || !errors.Is(err, injected) || !errors.Is(err, closed) {
		t.Fatalf("lost domain/native categories: %v", err)
	}
	if err.Error() != "selfhost: recipient registry rejected\nselfhost: publish: selfhost: recipient registry rejected\nselfhost: verify: injected\nselfhost: recipient registry rejected\nselfhost: close: closed" {
		t.Fatalf("changed join order: %v", err)
	}
	if err := mapSelfhostWindowsError(&winprivate.OpError{Op: "invalid handle"}); err != ErrRecipientRegistry {
		t.Fatalf("nil cause classification: %v", err)
	}
	for _, input := range []error{winprivate.ErrUnsafe, winprivate.ErrExists, winprivate.ErrIncomplete} {
		if err := mapSelfhostWindowsError(input); err != ErrRecipientRegistry {
			t.Fatalf("domain mapping: %v", err)
		}
	}
	if err := mapSelfhostWindowsError(nil); err != nil {
		t.Fatalf("nil mapped to %v", err)
	}
}

func TestSelfhostWindowsCreationCollisionsRetainDomainErrorsAndContent(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := createSelfhostPrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "artifact")
	if err := writeSelfhostPrivateFileExclusive(path, []byte("previous")); err != nil {
		t.Fatal(err)
	}
	if err := createSelfhostPrivateDirectory(directory); err != ErrBusy {
		t.Fatalf("directory collision: %v", err)
	}
	if err := writeSelfhostPrivateFileExclusive(path, []byte("replacement")); err != ErrRecipientRegistry {
		t.Fatalf("file collision: %v", err)
	}
	if value, err := os.ReadFile(path); err != nil || string(value) != "previous" {
		t.Fatalf("collision changed artifact: %v", err)
	}
	if err := createSelfhostPrivateDirectory("relative"); err != ErrRecipientRegistry {
		t.Fatalf("directory rejection: %v", err)
	}
	if err := writeSelfhostPrivateFileExclusive(filepath.Join(directory, "empty"), nil); err != ErrRecipientRegistry {
		t.Fatalf("empty-file rejection: %v", err)
	}
}
