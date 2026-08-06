// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

func CreateBackup(options BackupOptions) (BackupSummary, error) {
	now := options.Now.UTC()
	if options.DataDir == "" || options.Destination == "" || !validPassphrase(options.Passphrase) || now.IsZero() ||
		recoveryInsideDataDir(options.DataDir, options.Destination) {
		return BackupSummary{}, ErrInvalidInput
	}
	state, master, err := loadState(options.DataDir)
	if err != nil {
		return BackupSummary{}, err
	}
	defer zero(master)
	if err := validateClockTransition(state.LastObservedAt, now.Unix()); err != nil {
		return BackupSummary{}, err
	}
	stateFile, err := os.ReadFile(filepath.Join(options.DataDir, stateFileName))
	if err != nil || len(stateFile) == 0 || len(stateFile) > maxStateBytes {
		return BackupSummary{}, ErrStateCorrupt
	}
	auditHead := state.Audit[len(state.Audit)-1].Digest
	payload := backupPayload{
		Schema: backupSchema, DeploymentID: state.DeploymentID, AuditHead: auditHead,
		Revision: state.Revision, Generation: state.Generation, CreatedAt: now.Unix(),
		MasterKey: append([]byte(nil), master...), StateFile: stateFile,
	}
	encoded, err := sealBackup(payload, options.Passphrase)
	zero(payload.MasterKey)
	if err != nil {
		return BackupSummary{}, err
	}
	if err := os.MkdirAll(filepath.Dir(options.Destination), 0o700); err != nil {
		return BackupSummary{}, err
	}
	if err := writeExclusive(options.Destination, encoded, 0o600); err != nil {
		return BackupSummary{}, err
	}
	return backupSummary(payload, encoded, len(state.Profiles)), nil
}

func VerifyBackup(path string, passphrase []byte) (BackupSummary, error) {
	payload, encoded, state, err := readBackup(path, passphrase)
	if err != nil {
		return BackupSummary{}, err
	}
	defer zero(payload.MasterKey)
	return backupSummary(payload, encoded, len(state.Profiles)), nil
}

func PreviewRestore(options RestoreOptions) (BackupSummary, error) {
	if options.BackupPath == "" || options.DataDir == "" || !validPassphrase(options.Passphrase) || options.Now.IsZero() {
		return BackupSummary{}, ErrInvalidInput
	}
	payload, encoded, state, err := readBackup(options.BackupPath, options.Passphrase)
	if err != nil {
		return BackupSummary{}, err
	}
	defer zero(payload.MasterKey)
	now := options.Now.UTC().Unix()
	if payload.CreatedAt > now+300 {
		return BackupSummary{}, ErrClockUnhealthy
	}
	if _, err := os.Stat(options.DataDir); err == nil {
		current, master, loadErr := loadState(options.DataDir)
		if loadErr != nil {
			return BackupSummary{}, ErrAlreadyInitialized
		}
		zero(master)
		if current.DeploymentID != payload.DeploymentID || current.Revision >= payload.Revision || current.Generation > payload.Generation {
			return BackupSummary{}, ErrRollback
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return BackupSummary{}, err
	}
	return backupSummary(payload, encoded, len(state.Profiles)), nil
}

func ApplyRestore(options RestoreOptions) error {
	preview, err := PreviewRestore(options)
	if err != nil {
		return err
	}
	if options.ExpectedDigest == "" || options.ExpectedDigest != preview.Digest {
		return ErrRecoveryRejected
	}
	if _, err := os.Stat(options.DataDir); err == nil || !errors.Is(err, os.ErrNotExist) {
		return ErrAlreadyInitialized
	}
	payload, _, state, err := readBackup(options.BackupPath, options.Passphrase)
	if err != nil || payload.DeploymentID != preview.DeploymentID {
		return ErrRecoveryRejected
	}
	defer zero(payload.MasterKey)
	parent := filepath.Dir(options.DataDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, ".kurd-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o700); err != nil {
		return err
	}
	state.RecoveryConfirmed = false
	state.Drained = true
	state.LastObservedAt = options.Now.UTC().Unix()
	state.Revision++
	if err := appendAudit(&state, state.LastObservedAt, "restore-quarantine", state.DeploymentID); err != nil {
		return err
	}
	state.PublicationOutbox = []publicationOutboxEntry{{Revision: state.Revision, CreatedAt: state.LastObservedAt, Action: "restore-quarantine"}}
	if err := os.WriteFile(filepath.Join(staging, masterKeyFileName), payload.MasterKey, 0o600); err != nil {
		return err
	}
	if err := saveState(staging, payload.MasterKey, state); err != nil {
		return err
	}
	if _, err := loadStateWithKey(staging, payload.MasterKey); err != nil {
		return err
	}
	if err := os.Rename(staging, options.DataDir); err != nil {
		return err
	}
	return nil
}

func readBackup(path string, passphrase []byte) (backupPayload, []byte, persistedState, error) {
	encoded, err := os.ReadFile(path)
	if err != nil || len(encoded) == 0 || len(encoded) > maxBackupBytes {
		return backupPayload{}, nil, persistedState{}, ErrRecoveryRejected
	}
	payload, err := openBackup(encoded, passphrase)
	if err != nil || len(payload.MasterKey) != 32 || len(payload.StateFile) == 0 || len(payload.StateFile) > maxStateBytes {
		return backupPayload{}, nil, persistedState{}, ErrRecoveryRejected
	}
	state, err := decodeStateFile(payload.StateFile, payload.MasterKey)
	if err != nil || state.DeploymentID != payload.DeploymentID || state.Revision != payload.Revision || state.Generation != payload.Generation ||
		state.Audit[len(state.Audit)-1].Digest != payload.AuditHead {
		zero(payload.MasterKey)
		return backupPayload{}, nil, persistedState{}, ErrRecoveryRejected
	}
	return payload, encoded, state, nil
}

func sealBackup(payload backupPayload, passphrase []byte) ([]byte, error) {
	plain, err := encodeCanonical(payload)
	if err != nil || len(plain) > maxBackupBytes {
		return nil, ErrInvalidInput
	}
	salt, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(12)
	if err != nil {
		return nil, err
	}
	key := argon2.IDKey(passphrase, salt, recoveryIterations, recoveryMemoryKiB, recoveryParallelism, 32)
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	envelope := backupEnvelope{
		Schema: backupSchema, KDFMemoryKiB: recoveryMemoryKiB, KDFIterations: recoveryIterations, KDFParallelism: recoveryParallelism,
		Salt: salt, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plain, backupAAD(salt, nonce)),
	}
	return encodeCanonical(envelope)
}

func openBackup(encoded, passphrase []byte) (backupPayload, error) {
	if !validPassphrase(passphrase) {
		return backupPayload{}, ErrRecoveryRejected
	}
	var envelope backupEnvelope
	if decodeCanonical(encoded, &envelope, maxBackupBytes) != nil || envelope.Schema != backupSchema ||
		envelope.KDFMemoryKiB != recoveryMemoryKiB || envelope.KDFIterations != recoveryIterations || envelope.KDFParallelism != recoveryParallelism ||
		len(envelope.Salt) != 16 || len(envelope.Nonce) != 12 {
		return backupPayload{}, ErrRecoveryRejected
	}
	key := argon2.IDKey(passphrase, envelope.Salt, envelope.KDFIterations, envelope.KDFMemoryKiB, envelope.KDFParallelism, 32)
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return backupPayload{}, ErrRecoveryRejected
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return backupPayload{}, ErrRecoveryRejected
	}
	plain, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, backupAAD(envelope.Salt, envelope.Nonce))
	if err != nil {
		return backupPayload{}, ErrRecoveryRejected
	}
	var payload backupPayload
	if decodeCanonical(plain, &payload, maxBackupBytes) != nil || payload.Schema != backupSchema || !validID(payload.DeploymentID) ||
		payload.Revision == 0 || payload.CreatedAt <= 0 || payload.AuditHead == "" {
		return backupPayload{}, ErrRecoveryRejected
	}
	return payload, nil
}

func backupAAD(salt, nonce []byte) []byte {
	return []byte(fmt.Sprintf("%s|argon2id|%d|%d|%d|%x|%x", backupSchema, recoveryMemoryKiB, recoveryIterations, recoveryParallelism, salt, nonce))
}

func backupSummary(payload backupPayload, encoded []byte, profileCount int) BackupSummary {
	return BackupSummary{
		Schema: backupSchema, DeploymentID: payload.DeploymentID, Digest: artifactDigest(encoded), AuditHead: payload.AuditHead,
		Revision: payload.Revision, Generation: payload.Generation, CreatedAt: payload.CreatedAt, ProfileCount: profileCount,
	}
}
