// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package selfhost

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"kurdistan/internal/winprivate"
)

func TestApplyRestorePublishesPrivateWindowsTreeBeforeRecovery(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	restored := filepath.Join(root, "restored")
	recovery := filepath.Join(root, "offline", "recovery")
	backup := filepath.Join(root, "offline", "backup")
	passphrase := []byte("private publication regression")
	now := time.Unix(1_800_200_000, 0).UTC()
	if _, err := Initialize(InitOptions{DataDir: source, DeploymentName: "private-publication", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(source, recovery, passphrase, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	summary, err := CreateBackup(BackupOptions{DataDir: source, Destination: backup, Passphrase: passphrase, Now: now.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyRestore(RestoreOptions{BackupPath: backup, DataDir: restored, ExpectedDigest: summary.Digest, Passphrase: passphrase, Now: now.Add(3 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		name      string
		path      string
		directory bool
	}{
		{name: "restored directory", path: restored, directory: true},
		{name: "restored master key", path: filepath.Join(restored, masterKeyFileName)},
		{name: "restored state", path: filepath.Join(restored, stateFileName)},
	} {
		if err := winprivate.Verify(target.path, target.directory); err != nil {
			t.Fatalf("%s was published without the private Windows descriptor: %v", target.name, err)
		}
	}
	if err := ConfirmRecovery(restored, recovery, passphrase, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("restored authority publication failed: %v", err)
	}
	if err := winprivate.Verify(filepath.Join(restored, recipientAuthorityFileName), false); err != nil {
		t.Fatalf("restored recipient authority is not private: %v", err)
	}
}

func TestPrepareRestoreStagingFailsClosedBeforeSensitiveContent(t *testing.T) {
	root := t.TempDir()
	previousAuthority := filepath.Join(root, "previous-authority")
	previousBytes := []byte("previous valid authority")
	if err := os.WriteFile(previousAuthority, previousBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "DACL application failure", err: windows.ERROR_ACCESS_DENIED},
		{name: "DACL verification failure", err: windows.ERROR_INVALID_SECURITY_DESCR},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := filepath.Join(root, strings.ReplaceAll(test.name, " ", "-"))
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			protectCalls, removeCalls := 0, 0
			staging, err := prepareRestoreStagingWithOperations(
				parent,
				func(path string, directory bool) error {
					protectCalls++
					if !directory {
						t.Fatal("restore staging protection was not classified as a directory")
					}
					entries, readErr := os.ReadDir(path)
					if readErr != nil || len(entries) != 0 {
						t.Fatalf("sensitive content existed before DACL protection: entries=%d err=%v", len(entries), readErr)
					}
					return test.err
				},
				func(path string) error {
					removeCalls++
					return os.RemoveAll(path)
				},
			)
			if staging != "" || !errors.Is(err, test.err) {
				t.Fatalf("staging=%q error=%v, want empty staging and %v", staging, err, test.err)
			}
			if protectCalls != 1 || removeCalls != 1 {
				t.Fatalf("protect=%d remove=%d, want exactly once", protectCalls, removeCalls)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed staging remained visible: entries=%d err=%v", len(entries), err)
			}
			actual, err := os.ReadFile(previousAuthority)
			if err != nil || string(actual) != string(previousBytes) {
				t.Fatalf("previous authority changed: len=%d err=%v", len(actual), err)
			}
		})
	}
}

func TestPrepareRestoreStagingIsPrivateAndEmptyBeforeUse(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	protectCalls, removeCalls := 0, 0
	staging, err := prepareRestoreStagingWithOperations(
		parent,
		func(path string, directory bool) error {
			protectCalls++
			if entries, err := os.ReadDir(path); err != nil || len(entries) != 0 {
				t.Fatalf("staging was not empty before protection: entries=%d err=%v", len(entries), err)
			}
			return protectSelfhostPrivatePath(path, directory)
		},
		func(path string) error {
			removeCalls++
			return os.RemoveAll(path)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(staging)
	if protectCalls != 1 || removeCalls != 0 {
		t.Fatalf("protect=%d remove=%d, want protect=1 remove=0", protectCalls, removeCalls)
	}
	if err := winprivate.Verify(staging, true); err != nil {
		t.Fatalf("prepared staging directory is not private: %v", err)
	}
}

func TestRepeatedWindowsRestoreAndRollbackRemainDeterministic(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	recovery := filepath.Join(root, "offline", "recovery")
	backup := filepath.Join(root, "offline", "backup")
	passphrase := []byte("repeatable restore regression")
	now := time.Unix(1_800_300_000, 0).UTC()
	if _, err := Initialize(InitOptions{DataDir: source, DeploymentName: "repeatable", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(source, recovery, passphrase, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	summary, err := CreateBackup(BackupOptions{DataDir: source, Destination: backup, Passphrase: passphrase, Now: now.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	var firstState []byte
	for index := 0; index < 2; index++ {
		destination := filepath.Join(root, "restored-"+string(rune('a'+index)))
		options := RestoreOptions{BackupPath: backup, DataDir: destination, ExpectedDigest: summary.Digest, Passphrase: passphrase, Now: now.Add(3 * time.Minute)}
		if err := ApplyRestore(options); err != nil {
			t.Fatalf("restore %d: %v", index, err)
		}
		state, err := os.ReadFile(filepath.Join(destination, stateFileName))
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			firstState = state
		} else if string(state) != string(firstState) {
			t.Fatal("identical restore inputs produced different durable state")
		}
		if err := ConfirmRecovery(destination, recovery, passphrase, now.Add(4*time.Minute)); err != nil {
			t.Fatalf("confirm restore %d: %v", index, err)
		}
		if _, err := PreviewRestore(RestoreOptions{BackupPath: backup, DataDir: destination, Passphrase: passphrase, Now: now.Add(5 * time.Minute)}); !errors.Is(err, ErrRollback) {
			t.Fatalf("restore %d rollback error=%v", index, err)
		}
	}
}
