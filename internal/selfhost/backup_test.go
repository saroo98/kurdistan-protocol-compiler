// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPhase16BackupRemainsReadableAndRestoresAsV2(t *testing.T) {
	backupPath := filepath.Join("testdata", "phase16-v1", "backup.kurd-backup")
	passphrase := []byte("phase16 deterministic fixture passphrase")
	summary, err := VerifyBackup(backupPath, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Schema != backupSchemaV1 || summary.Digest != "bf4a3189044d73656aa964883f47e7bf69b77ba8d9530eca18955f869bf190ed" {
		t.Fatalf("legacy backup summary=%+v", summary)
	}
	destination := filepath.Join(t.TempDir(), "restored")
	now := time.Unix(summary.CreatedAt+60, 0)
	preview, err := PreviewRestore(RestoreOptions{BackupPath: backupPath, DataDir: destination, Passphrase: passphrase, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyRestore(RestoreOptions{BackupPath: backupPath, DataDir: destination, ExpectedDigest: preview.Digest, Passphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	state, master, err := loadState(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	if state.Version != stateVersionV2 || state.MigrationEpoch != migrationEpochV2 || !state.Drained || state.RecoveryConfirmed || state.Revision != summary.Revision+1 {
		t.Fatalf("restored state=%+v", state)
	}
}

func TestBackupSealerRejectsNonV2Payloads(t *testing.T) {
	payload := backupPayload{
		Schema: backupSchemaV1, DeploymentID: "deployment.fixture", AuditHead: "audit", Revision: 1, CreatedAt: 1,
		StateVersion: stateVersionV1, MasterKey: make([]byte, 32), StateFile: []byte{1},
	}
	if _, err := sealBackup(payload, []byte("valid backup passphrase")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("legacy payload sealed by v2 sealer: %v", err)
	}
}

func TestV2BackupPreservesTLSAddressPoolsAndQuarantine(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	now := time.Unix(1_760_000_100, 0).UTC()
	if err := withStateTransaction(dataDir, "fixture-quarantine", "profiles.fixture", now.Unix(), func(state *persistedState, _ []byte) error {
		state.Assignments = []addressAssignmentV1{{
			Family: addressFamilyIPv4, Address: []byte{10, 77, 0, 2}, ProfileID: "profiles.fixture", ContentID: "content.fixture",
			Generation: 1, State: addressStateQuarantined, AssignedAt: now.Unix(), ProfileValidUntil: now.Add(time.Hour).Unix(),
			ReleaseAt: now.Add(time.Hour + addressQuarantine).Unix(),
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "state-v2.kurd-backup")
	passphrase := []byte("v2 backup test passphrase")
	summary, err := CreateBackup(BackupOptions{DataDir: dataDir, Destination: backupPath, Passphrase: passphrase, Now: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "restored")
	restoreAt := now.Add(2 * time.Minute)
	if err := ApplyRestore(RestoreOptions{BackupPath: backupPath, DataDir: destination, ExpectedDigest: summary.Digest, Passphrase: passphrase, Now: restoreAt}); err != nil {
		t.Fatal(err)
	}
	original, originalMaster, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	zero(originalMaster)
	restored, restoredMaster, err := loadState(destination)
	if err != nil {
		t.Fatal(err)
	}
	zero(restoredMaster)
	if !reflect.DeepEqual(restored.TLS, original.TLS) || !reflect.DeepEqual(restored.IPv4Pool, original.IPv4Pool) ||
		!reflect.DeepEqual(restored.IPv6Pool, original.IPv6Pool) || !reflect.DeepEqual(restored.Assignments, original.Assignments) ||
		restored.Generation != original.Generation || restored.Revision != original.Revision+1 || !restored.Drained || restored.RecoveryConfirmed {
		t.Fatal("v2 backup restore changed protected relay-capable state")
	}
}

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
