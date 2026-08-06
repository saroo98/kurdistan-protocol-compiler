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

func TestEncryptedBackupRestoreAndRollbackProtection(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "source")
	restored := filepath.Join(base, "restored")
	recovery := filepath.Join(base, "offline", "recovery")
	backup := filepath.Join(base, "offline", "node.kurd-backup")
	passphrase := []byte("correct horse battery staple")
	now := time.Unix(1_800_000_000, 0).UTC()
	if _, err := Initialize(InitOptions{DataDir: source, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(source, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	issued, err := CreateProfile(source, CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	created, err := CreateBackup(BackupOptions{DataDir: source, Destination: backup, Passphrase: passphrase, Now: now.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewRestore(RestoreOptions{BackupPath: backup, DataDir: restored, Passphrase: passphrase, Now: now.Add(3 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Digest != created.Digest || preview.ProfileCount != 1 {
		t.Fatalf("restore preview mismatch: created=%+v preview=%+v", created, preview)
	}
	if err := ApplyRestore(RestoreOptions{BackupPath: backup, DataDir: restored, ExpectedDigest: preview.Digest, Passphrase: passphrase, Now: now.Add(3 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(restored, recovery, passphrase, now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := SetDrained(restored, false, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundleAgainstCurrentState(restored, issued.Artifact, now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := PreviewRestore(RestoreOptions{BackupPath: backup, DataDir: restored, Passphrase: passphrase, Now: now.Add(7 * time.Minute)}); !errors.Is(err, ErrRollback) {
		t.Fatalf("existing-state rollback preview error = %v", err)
	}
}

func TestBackupRejectsWrongPassphraseTamperAndUnsafePaths(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	backup := filepath.Join(base, "offline", "node.kurd-backup")
	passphrase := []byte("correct horse battery staple")
	now := time.Unix(1_800_000_000, 0).UTC()
	if _, err := Initialize(InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateBackup(BackupOptions{DataDir: dataDir, Destination: filepath.Join(dataDir, "unsafe"), Passphrase: passphrase, Now: now.Add(time.Minute)}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("backup inside data directory error = %v", err)
	}
	if _, err := CreateBackup(BackupOptions{DataDir: dataDir, Destination: backup, Passphrase: passphrase, Now: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := PreviewRestore(RestoreOptions{BackupPath: backup, DataDir: filepath.Join(base, "wrong"), Passphrase: []byte("wrong passphrase value"), Now: now.Add(2 * time.Minute)}); !errors.Is(err, ErrRecoveryRejected) {
		t.Fatalf("wrong backup passphrase error = %v", err)
	}
	raw, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(backup, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PreviewRestore(RestoreOptions{BackupPath: backup, DataDir: filepath.Join(base, "tampered"), Passphrase: passphrase, Now: now.Add(2 * time.Minute)}); !errors.Is(err, ErrRecoveryRejected) {
		t.Fatalf("tampered backup error = %v", err)
	}
}

func TestClockRollbackAndLargeForwardJumpFailClosed(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	now := time.Unix(1_800_000_000, 0).UTC()
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("correct horse battery staple")
	if _, err := Initialize(InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := SetDrained(dataDir, true, now.Add(-10*time.Minute)); !errors.Is(err, ErrClockUnhealthy) {
		t.Fatalf("clock rollback error = %v", err)
	}
	if err := SetDrained(dataDir, true, now.Add(91*24*time.Hour)); !errors.Is(err, ErrClockUnhealthy) {
		t.Fatalf("clock forward jump error = %v", err)
	}
	if err := RepairClock(dataDir, RecoveryActionOptions{RecoveryPath: recovery, RecoveryPassphrase: []byte("wrong passphrase value"), Now: now.Add(91 * 24 * time.Hour)}); !errors.Is(err, ErrRecoveryRejected) {
		t.Fatalf("unauthorized clock repair error = %v", err)
	}
	if err := RepairClock(dataDir, RecoveryActionOptions{RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now.Add(91 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := SetDrained(dataDir, true, now.Add(91*24*time.Hour+time.Minute)); err != nil {
		t.Fatal(err)
	}
}
