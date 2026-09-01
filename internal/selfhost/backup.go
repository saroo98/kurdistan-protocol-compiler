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
	registryKey, registryState, err := readRecipientRegistryForBackup(options.RegistryDir, state.RecipientUses.RegistryID)
	if err != nil {
		return BackupSummary{}, err
	}
	defer zero(registryKey)
	auditHead := state.Audit[len(state.Audit)-1].Digest
	payload := backupPayload{
		Schema: backupSchema, DeploymentID: state.DeploymentID, AuditHead: auditHead,
		Revision: state.Revision, Generation: state.Generation, CreatedAt: now.Unix(),
		StateVersion: state.Version, MigrationEpoch: state.MigrationEpoch,
		MasterKey: append([]byte(nil), master...), StateFile: stateFile,
		RecipientRegistryKey: append([]byte(nil), registryKey...), RecipientRegistryState: append([]byte(nil), registryState...),
	}
	encoded, err := sealBackup(payload, options.Passphrase)
	zero(payload.MasterKey)
	zero(payload.RecipientRegistryKey)
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
	defer zero(payload.RecipientRegistryKey)
	return backupSummary(payload, encoded, state.profileCount()), nil
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
	defer zero(payload.RecipientRegistryKey)
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
		if current.DeploymentID != payload.DeploymentID || payload.StateVersion != stateVersionV2 || current.MigrationEpoch > payload.MigrationEpoch || current.Revision >= payload.Revision || current.Generation > payload.Generation {
			return BackupSummary{}, ErrRollback
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return BackupSummary{}, err
	}
	return backupSummary(payload, encoded, state.profileCount()), nil
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
	payload, _, backupState, err := readBackup(options.BackupPath, options.Passphrase)
	if err != nil || payload.DeploymentID != preview.DeploymentID {
		return ErrRecoveryRejected
	}
	defer zero(payload.MasterKey)
	defer zero(payload.RecipientRegistryKey)
	parent := filepath.Dir(options.DataDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	staging, err := prepareRestoreStaging(parent)
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	masterPath := filepath.Join(staging, masterKeyFileName)
	if err := os.WriteFile(masterPath, payload.MasterKey, 0o600); err != nil {
		return err
	}
	if err := protectSelfhostPrivatePath(masterPath, false); err != nil {
		return err
	}
	if backupState.v2 != nil {
		if err := saveState(staging, payload.MasterKey, *backupState.v2); err != nil {
			return err
		}
	} else {
		if backupState.v1 == nil || payload.StateVersion != stateVersionV1 {
			return ErrRecoveryRejected
		}
		if err := os.WriteFile(filepath.Join(staging, stateFileName), payload.StateFile, 0o600); err != nil {
			return err
		}
		if err := MigrateToV2(staging, options.Now.UTC()); err != nil {
			return err
		}
	}
	if err := withStateTransaction(staging, "restore-quarantine", payload.DeploymentID, options.Now.UTC().Unix(), func(state *persistedState, _ []byte) error {
		state.RecoveryConfirmed = false
		state.Drained = true
		return nil
	}); err != nil {
		return err
	}
	if err := protectSelfhostPrivatePath(filepath.Join(staging, stateFileName), false); err != nil {
		return err
	}
	if _, err := loadStateWithKey(staging, payload.MasterKey); err != nil {
		return err
	}
	registryCreated := false
	if len(payload.RecipientRegistryKey) != 0 {
		relativeRegistry, nested := pathWithin(options.DataDir, options.RegistryDir)
		registryTarget := options.RegistryDir
		if nested {
			registryTarget = filepath.Join(staging, relativeRegistry)
		}
		created, restoreErr := restoreOwnerRecipientRegistry(registryTarget, payload.RecipientRegistryKey, payload.RecipientRegistryState, backupState.recipientRegistryID())
		if restoreErr != nil {
			return restoreErr
		}
		registryCreated = created && !nested
	}
	if err := os.Rename(staging, options.DataDir); err != nil {
		if registryCreated {
			_ = os.RemoveAll(options.RegistryDir)
			_ = syncDirectory(filepath.Dir(options.RegistryDir))
		}
		return err
	}
	return syncDirectory(parent)
}

func prepareRestoreStaging(parent string) (string, error) {
	return prepareRestoreStagingWithOperations(parent, protectSelfhostPrivatePath, os.RemoveAll)
}

func prepareRestoreStagingWithOperations(parent string, protect func(string, bool) error, remove func(string) error) (string, error) {
	if parent == "" || protect == nil || remove == nil {
		return "", ErrRecoveryRejected
	}
	staging, err := os.MkdirTemp(parent, ".kurd-restore-*")
	if err != nil {
		return "", err
	}
	if err := protect(staging, true); err != nil {
		if removeErr := remove(staging); removeErr != nil {
			return "", errors.Join(err, fmt.Errorf("selfhost: remove rejected restore staging: %w", removeErr))
		}
		return "", err
	}
	return staging, nil
}

type decodedBackupState struct {
	v1 *persistedStateV1
	v2 *persistedState
}

func (state decodedBackupState) profileCount() int {
	if state.v2 != nil {
		return len(state.v2.Profiles)
	}
	if state.v1 != nil {
		return len(state.v1.Profiles)
	}
	return 0
}

func (state decodedBackupState) recipientRegistryID() string {
	if state.v2 != nil {
		return state.v2.RecipientUses.RegistryID
	}
	return ""
}

func readBackup(path string, passphrase []byte) (backupPayload, []byte, decodedBackupState, error) {
	encoded, err := os.ReadFile(path)
	if err != nil || len(encoded) == 0 || len(encoded) > maxBackupBytes {
		return backupPayload{}, nil, decodedBackupState{}, ErrRecoveryRejected
	}
	payload, err := openBackup(encoded, passphrase)
	if err != nil || len(payload.MasterKey) != 32 || len(payload.StateFile) == 0 || len(payload.StateFile) > maxStateBytes {
		return backupPayload{}, nil, decodedBackupState{}, ErrRecoveryRejected
	}
	if payload.StateVersion == stateVersionV1 {
		state, decodeErr := decodeStateFileV1(payload.StateFile, payload.MasterKey)
		if decodeErr != nil || state.DeploymentID != payload.DeploymentID || state.Revision != payload.Revision || state.Generation != payload.Generation || state.Audit[len(state.Audit)-1].Digest != payload.AuditHead {
			zero(payload.MasterKey)
			return backupPayload{}, nil, decodedBackupState{}, ErrRecoveryRejected
		}
		return payload, encoded, decodedBackupState{v1: &state}, nil
	}
	state, err := decodeStateFile(payload.StateFile, payload.MasterKey)
	if err != nil || payload.StateVersion != stateVersionV2 || payload.MigrationEpoch != state.MigrationEpoch || state.DeploymentID != payload.DeploymentID || state.Revision != payload.Revision || state.Generation != payload.Generation || state.Audit[len(state.Audit)-1].Digest != payload.AuditHead {
		zero(payload.MasterKey)
		zero(payload.RecipientRegistryKey)
		return backupPayload{}, nil, decodedBackupState{}, ErrRecoveryRejected
	}
	if err := validateBackupRecipientRegistry(payload, state.RecipientUses.RegistryID); err != nil {
		zero(payload.MasterKey)
		zero(payload.RecipientRegistryKey)
		return backupPayload{}, nil, decodedBackupState{}, err
	}
	return payload, encoded, decodedBackupState{v2: &state}, nil
}

func sealBackup(payload backupPayload, passphrase []byte) ([]byte, error) {
	if payload.Schema != backupSchemaV3 || payload.StateVersion != stateVersionV2 || payload.MigrationEpoch == 0 ||
		!validID(payload.DeploymentID) || payload.Revision == 0 || payload.CreatedAt <= 0 || payload.AuditHead == "" ||
		len(payload.MasterKey) != 32 || len(payload.StateFile) == 0 || len(payload.StateFile) > maxStateBytes ||
		len(payload.RecipientRegistryKey) != 0 && len(payload.RecipientRegistryKey) != 32 || len(payload.RecipientRegistryState) > maxStateBytes ||
		!validPassphrase(passphrase) {
		return nil, ErrInvalidInput
	}
	plain, err := encodeCanonical(payload)
	if err != nil || len(plain) > maxBackupBytes {
		return nil, ErrInvalidInput
	}
	defer zero(plain)
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
		Salt: salt, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plain, backupAADV3(salt, nonce)),
	}
	return encodeCanonical(envelope)
}

func openBackup(encoded, passphrase []byte) (backupPayload, error) {
	if !validPassphrase(passphrase) {
		return backupPayload{}, ErrRecoveryRejected
	}
	var envelope backupEnvelope
	if decodeCanonical(encoded, &envelope, maxBackupBytes) != nil || envelope.Schema != backupSchemaV1 && envelope.Schema != backupSchemaV2 && envelope.Schema != backupSchemaV3 ||
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
	aad := backupAADV2(envelope.Salt, envelope.Nonce)
	if envelope.Schema == backupSchemaV1 {
		aad = backupAADV1(envelope.Salt, envelope.Nonce)
	} else if envelope.Schema == backupSchemaV3 {
		aad = backupAADV3(envelope.Salt, envelope.Nonce)
	}
	plain, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return backupPayload{}, ErrRecoveryRejected
	}
	defer zero(plain)
	if envelope.Schema == backupSchemaV1 {
		var legacy backupPayloadV1
		if decodeCanonical(plain, &legacy, maxBackupBytes) != nil || legacy.Schema != backupSchemaV1 || !validID(legacy.DeploymentID) || legacy.Revision == 0 || legacy.CreatedAt <= 0 || legacy.AuditHead == "" {
			return backupPayload{}, ErrRecoveryRejected
		}
		return backupPayload{
			Schema: legacy.Schema, DeploymentID: legacy.DeploymentID, AuditHead: legacy.AuditHead, Revision: legacy.Revision, Generation: legacy.Generation,
			CreatedAt: legacy.CreatedAt, StateVersion: stateVersionV1, MasterKey: legacy.MasterKey, StateFile: legacy.StateFile,
		}, nil
	}
	if envelope.Schema == backupSchemaV2 {
		var legacy backupPayloadV2
		if decodeCanonical(plain, &legacy, maxBackupBytes) != nil || legacy.Schema != backupSchemaV2 || !validID(legacy.DeploymentID) ||
			legacy.Revision == 0 || legacy.CreatedAt <= 0 || legacy.AuditHead == "" || legacy.StateVersion != stateVersionV2 || legacy.MigrationEpoch == 0 {
			return backupPayload{}, ErrRecoveryRejected
		}
		return backupPayload{
			Schema: legacy.Schema, DeploymentID: legacy.DeploymentID, AuditHead: legacy.AuditHead,
			Revision: legacy.Revision, Generation: legacy.Generation, CreatedAt: legacy.CreatedAt,
			StateVersion: legacy.StateVersion, MigrationEpoch: legacy.MigrationEpoch,
			MasterKey: legacy.MasterKey, StateFile: legacy.StateFile,
		}, nil
	}
	var payload backupPayload
	if decodeCanonical(plain, &payload, maxBackupBytes) != nil || payload.Schema != backupSchemaV3 || !validID(payload.DeploymentID) ||
		payload.Revision == 0 || payload.CreatedAt <= 0 || payload.AuditHead == "" || payload.StateVersion != stateVersionV2 || payload.MigrationEpoch == 0 {
		return backupPayload{}, ErrRecoveryRejected
	}
	return payload, nil
}

func backupAADV1(salt, nonce []byte) []byte {
	return []byte(fmt.Sprintf("%s|argon2id|%d|%d|%d|%x|%x", backupSchemaV1, recoveryMemoryKiB, recoveryIterations, recoveryParallelism, salt, nonce))
}

func backupAADV2(salt, nonce []byte) []byte {
	return []byte(fmt.Sprintf("%s|argon2id|%d|%d|%d|%x|%x", backupSchemaV2, recoveryMemoryKiB, recoveryIterations, recoveryParallelism, salt, nonce))
}

func backupAADV3(salt, nonce []byte) []byte {
	return []byte(fmt.Sprintf("%s|argon2id|%d|%d|%d|%x|%x", backupSchemaV3, recoveryMemoryKiB, recoveryIterations, recoveryParallelism, salt, nonce))
}

func readRecipientRegistryForBackup(directory, expectedRegistryID string) ([]byte, []byte, error) {
	if directory == "" {
		if expectedRegistryID == "" {
			return nil, nil, nil
		}
		return nil, nil, ErrRecipientRegistry
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) && expectedRegistryID == "" {
		return nil, nil, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || protectSelfhostPrivatePath(directory, true) != nil {
		return nil, nil, ErrRecipientRegistry
	}
	keyPath := filepath.Join(directory, ownerRecipientRegistryKey)
	statePath := filepath.Join(directory, ownerRecipientRegistryState)
	key, keyErr := os.ReadFile(keyPath)
	stateRaw, stateErr := os.ReadFile(statePath)
	if keyErr != nil || stateErr != nil || protectSelfhostPrivatePath(keyPath, false) != nil || protectSelfhostPrivatePath(statePath, false) != nil {
		zero(key)
		return nil, nil, ErrRecipientRegistry
	}
	registry, decodeErr := decodeOwnerRecipientRegistry(key, stateRaw)
	if decodeErr != nil || expectedRegistryID != "" && registry.RegistryID != expectedRegistryID {
		zero(key)
		return nil, nil, ErrRecipientRegistry
	}
	return key, stateRaw, nil
}

func validateBackupRecipientRegistry(payload backupPayload, expectedRegistryID string) error {
	keyPresent := len(payload.RecipientRegistryKey) != 0
	statePresent := len(payload.RecipientRegistryState) != 0
	if keyPresent != statePresent {
		return ErrRecoveryRejected
	}
	if !keyPresent {
		if expectedRegistryID != "" {
			return ErrRecoveryRejected
		}
		return nil
	}
	if payload.Schema != backupSchemaV3 {
		return ErrRecoveryRejected
	}
	registry, err := decodeOwnerRecipientRegistry(payload.RecipientRegistryKey, payload.RecipientRegistryState)
	if err != nil || expectedRegistryID != "" && registry.RegistryID != expectedRegistryID {
		return ErrRecoveryRejected
	}
	return nil
}

func restoreOwnerRecipientRegistry(directory string, key, stateRaw []byte, expectedRegistryID string) (bool, error) {
	if directory == "" || expectedRegistryID == "" {
		return false, ErrRecoveryRejected
	}
	registry, err := decodeOwnerRecipientRegistry(key, stateRaw)
	if err != nil || registry.RegistryID != expectedRegistryID {
		return false, ErrRecoveryRejected
	}
	if _, statErr := os.Lstat(directory); statErr == nil {
		existing, existingKey, loadErr := loadOrInitializeOwnerRecipientRegistry(directory, expectedRegistryID)
		zero(existingKey)
		if loadErr != nil || existing.RegistryID != expectedRegistryID {
			return false, ErrRecipientRegistry
		}
		return false, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, ErrRecipientRegistry
	}
	parent := filepath.Dir(directory)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return false, ErrRecipientRegistry
	}
	if err := createSelfhostPrivateDirectory(directory); err != nil {
		return false, ErrRecipientRegistry
	}
	remove := true
	defer func() {
		if remove {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := writeSelfhostPrivateFileExclusive(filepath.Join(directory, ownerRecipientRegistryKey), key); err != nil {
		return false, ErrRecipientRegistry
	}
	if err := writeSelfhostPrivateFileExclusive(filepath.Join(directory, ownerRecipientRegistryState), stateRaw); err != nil {
		return false, ErrRecipientRegistry
	}
	loaded, loadedKey, err := loadOrInitializeOwnerRecipientRegistry(directory, expectedRegistryID)
	zero(loadedKey)
	if err != nil || loaded.RegistryID != expectedRegistryID || syncDirectory(directory) != nil || syncDirectory(parent) != nil {
		return false, ErrRecipientRegistry
	}
	remove = false
	return true, nil
}

func pathWithin(parent, child string) (string, bool) {
	if parent == "" || child == "" {
		return "", false
	}
	parentAbsolute, parentErr := filepath.Abs(parent)
	childAbsolute, childErr := filepath.Abs(child)
	if parentErr != nil || childErr != nil {
		return "", false
	}
	relative, err := filepath.Rel(parentAbsolute, childAbsolute)
	if err != nil || relative == "." || !filepath.IsLocal(relative) {
		return "", false
	}
	return relative, true
}

func backupSummary(payload backupPayload, encoded []byte, profileCount int) BackupSummary {
	return BackupSummary{
		Schema: payload.Schema, DeploymentID: payload.DeploymentID, Digest: artifactDigest(encoded), AuditHead: payload.AuditHead,
		Revision: payload.Revision, Generation: payload.Generation, CreatedAt: payload.CreatedAt, ProfileCount: profileCount,
	}
}
