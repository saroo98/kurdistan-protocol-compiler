// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStaleLockRepairIsExplicitAgedAndStateChecked(t *testing.T) {
	now := time.Now().UTC()
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("correct horse battery staple")
	if _, err := Initialize(InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dataDir, lockDirectoryName)
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RepairStaleLock(dataDir, "wrong", now.Add(10*time.Minute)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("wrong confirmation error = %v", err)
	}
	if err := RepairStaleLock(dataDir, "stale-lock", now.Add(time.Minute)); !errors.Is(err, ErrBusy) {
		t.Fatalf("fresh lock error = %v", err)
	}
	stale := now.Add(-10 * time.Minute)
	if err := os.Chtimes(lockPath, stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := RepairStaleLock(dataDir, "stale-lock", now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock still exists: %v", err)
	}
	if _, err := LoadStatus(dataDir); err != nil {
		t.Fatalf("state changed during lock repair: %v", err)
	}
}

func TestStaleLockRepairRejectsUnexpectedContents(t *testing.T) {
	now := time.Now().UTC()
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	if _, err := Initialize(InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: []byte("correct horse battery staple"), Now: now}); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dataDir, lockDirectoryName)
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lockPath, "unexpected"), []byte("do not remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := now.Add(-10 * time.Minute)
	if err := os.Chtimes(lockPath, stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := RepairStaleLock(dataDir, "stale-lock", now); !errors.Is(err, ErrBusy) {
		t.Fatalf("unexpected lock contents error = %v", err)
	}
}
