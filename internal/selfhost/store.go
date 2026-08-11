// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"kurdistan/internal/product/profile"
)

func initializeStore(dataDir string, master []byte, state persistedState, recipientAuthority []byte) error {
	if len(master) != 32 || dataDir == "" || len(recipientAuthority) == 0 {
		return ErrInvalidInput
	}
	if _, err := os.Stat(filepath.Join(dataDir, stateFileName)); err == nil {
		return ErrAlreadyInitialized
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dataDir), 0o700); err != nil {
		return err
	}
	if err := ensureSelfhostPrivateDirectory(dataDir); err != nil {
		return err
	}
	masterPath := filepath.Join(dataDir, masterKeyFileName)
	if err := writeSelfhostPrivateFileExclusive(masterPath, master); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(masterPath)
			removeRecipientAuthority(dataDir)
		}
	}()
	if err := installRecipientAuthority(dataDir, recipientAuthority, true); err != nil {
		return err
	}
	if err := appendAudit(&state, state.Root.ValidFrom, "initialize", state.DeploymentID); err != nil {
		return err
	}
	state.Revision = 1
	state.PublicationOutbox = []publicationOutboxEntry{{Revision: state.Revision, CreatedAt: state.Root.ValidFrom, Action: "initialize"}}
	if err := saveState(dataDir, master, state); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func loadMasterKey(dataDir string) ([]byte, error) {
	info, err := os.Stat(filepath.Join(dataDir, masterKeyFileName))
	if err != nil || info.IsDir() || info.Size() != 32 {
		return nil, ErrStateCorrupt
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, ErrStateCorrupt
	}
	key, err := os.ReadFile(filepath.Join(dataDir, masterKeyFileName))
	if err != nil || len(key) != 32 {
		return nil, ErrStateCorrupt
	}
	return key, nil
}

func loadState(dataDir string) (persistedState, []byte, error) {
	master, err := loadMasterKey(dataDir)
	if err != nil {
		return persistedState{}, nil, err
	}
	state, err := loadStateWithKey(dataDir, master)
	if err != nil {
		zero(master)
		return persistedState{}, nil, err
	}
	return state, master, nil
}

func loadStateWithKey(dataDir string, master []byte) (persistedState, error) {
	raw, err := os.ReadFile(filepath.Join(dataDir, stateFileName))
	if err != nil || len(raw) == 0 || len(raw) > maxStateBytes {
		return persistedState{}, ErrStateCorrupt
	}
	return decodeStateFile(raw, master)
}

func decodeStateFile(raw, master []byte) (persistedState, error) {
	var envelope stateEnvelope
	if decodeCanonical(raw, &envelope, maxStateBytes) != nil {
		return persistedState{}, ErrStateCorrupt
	}
	if envelope.Version > stateVersionV2 {
		return persistedState{}, ErrNewerSchema
	}
	if envelope.Version == stateVersionV1 {
		return persistedState{}, ErrMigration
	}
	if envelope.Version != stateVersionV2 || !verifyStateMAC(stateMACV2(master, envelope.Payload), envelope.MAC) {
		return persistedState{}, ErrStateCorrupt
	}
	var state persistedState
	if decodeCanonical(envelope.Payload, &state, maxStateBytes) != nil || validateState(state, master) != nil {
		return persistedState{}, ErrStateCorrupt
	}
	return state, nil
}

func decodeStateFileV1(raw, master []byte) (persistedStateV1, error) {
	var envelope stateEnvelope
	if decodeCanonical(raw, &envelope, maxStateBytes) != nil || envelope.Version != stateVersionV1 ||
		!verifyStateMAC(stateMACV1(master, envelope.Payload), envelope.MAC) {
		return persistedStateV1{}, ErrStateCorrupt
	}
	var state persistedStateV1
	if decodeCanonical(envelope.Payload, &state, maxStateBytes) != nil || validateStateV1(state) != nil {
		return persistedStateV1{}, ErrStateCorrupt
	}
	return state, nil
}

func saveState(dataDir string, master []byte, state persistedState) error {
	return saveStateWithHooks(dataDir, master, state, nil)
}

type stateWritePhase string

const (
	stateWriteBeforeTemporary stateWritePhase = "before-temporary-write"
	stateWriteDuringTemporary stateWritePhase = "during-temporary-write"
	stateWriteBeforeSync      stateWritePhase = "before-temporary-sync"
	stateWriteBeforeRename    stateWritePhase = "before-rename"
	stateWriteAfterRename     stateWritePhase = "after-rename"
	stateWriteBeforeDirSync   stateWritePhase = "before-directory-sync"
)

type stateWriteHooks struct{ Fail func(stateWritePhase) error }

func (hooks *stateWriteHooks) check(phase stateWritePhase) error {
	if hooks == nil || hooks.Fail == nil {
		return nil
	}
	return hooks.Fail(phase)
}

func saveStateWithHooks(dataDir string, master []byte, state persistedState, hooks *stateWriteHooks) error {
	if err := validateState(state, master); err != nil {
		return err
	}
	payload, err := encodeCanonical(state)
	if err != nil {
		return ErrStateCorrupt
	}
	if len(payload) > maxStateBytes {
		return ErrCapacityExhausted
	}
	envelope := stateEnvelope{Version: stateVersionV2, Payload: payload, MAC: stateMACV2(master, payload)}
	encoded, err := encodeCanonical(envelope)
	if err != nil {
		return ErrStateCorrupt
	}
	if len(encoded) > maxStateBytes {
		return ErrCapacityExhausted
	}
	if err := hooks.check(stateWriteBeforeTemporary); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dataDir, ".state-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	reference := filepath.Join(dataDir, stateFileName)
	if _, err := os.Stat(reference); errors.Is(err, os.ErrNotExist) {
		reference = dataDir
	} else if err != nil {
		temporary.Close()
		return err
	}
	if err := preserveOwnership(temporaryPath, reference); err != nil {
		temporary.Close()
		return err
	}
	if hooks != nil && hooks.Fail != nil {
		middle := len(encoded) / 2
		if _, err := temporary.Write(encoded[:middle]); err != nil {
			temporary.Close()
			return err
		}
		if err := hooks.check(stateWriteDuringTemporary); err != nil {
			temporary.Close()
			return err
		}
		if _, err := temporary.Write(encoded[middle:]); err != nil {
			temporary.Close()
			return err
		}
	} else if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := hooks.check(stateWriteBeforeSync); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := hooks.check(stateWriteBeforeRename); err != nil {
		return err
	}
	destination := filepath.Join(dataDir, stateFileName)
	if runtime.GOOS == "windows" {
		backup := destination + ".previous"
		_ = os.Remove(backup)
		if _, err := os.Stat(destination); err == nil {
			if err := os.Rename(destination, backup); err != nil {
				return err
			}
		}
		if err := os.Rename(temporaryPath, destination); err != nil {
			_ = os.Rename(backup, destination)
			return err
		}
		if err := hooks.check(stateWriteAfterRename); err != nil {
			return errors.Join(ErrCommitUncertain, err)
		}
		_ = os.Remove(backup)
		if err := hooks.check(stateWriteBeforeDirSync); err != nil {
			return errors.Join(ErrCommitUncertain, err)
		}
		if err := syncDirectory(dataDir); err != nil {
			return errors.Join(ErrCommitUncertain, err)
		}
		return nil
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	if err := hooks.check(stateWriteAfterRename); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	if err := hooks.check(stateWriteBeforeDirSync); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	if err := syncDirectory(dataDir); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if runtime.GOOS == "windows" {
		return nil
	}
	return directory.Sync()
}

func withStateTransaction(dataDir string, action, subject string, at int64, update func(*persistedState, []byte) error) error {
	return withStateTransactionClock(dataDir, action, subject, at, false, update)
}

func withStateTransactionClock(dataDir string, action, subject string, at int64, allowClockRepair bool, update func(*persistedState, []byte) error) error {
	if dataDir == "" || at <= 0 || update == nil {
		return ErrInvalidInput
	}
	lockPath := filepath.Join(dataDir, lockDirectoryName)
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrBusy
		}
		return err
	}
	defer os.Remove(lockPath)
	state, master, err := loadState(dataDir)
	if err != nil {
		return err
	}
	defer zero(master)
	if err := validateClockTransition(state.LastObservedAt, at); err != nil && !allowClockRepair {
		return err
	}
	if err := update(&state, master); err != nil {
		return err
	}
	compactRevokedProfiles(&state)
	if at > state.LastObservedAt {
		state.LastObservedAt = at
	}
	state.Revision++
	if err := appendAudit(&state, at, action, subject); err != nil {
		return err
	}
	state.PublicationOutbox = []publicationOutboxEntry{{Revision: state.Revision, CreatedAt: at, Action: action}}
	return saveState(dataDir, master, state)
}

func validateState(state persistedState, master []byte) error {
	if state.Schema != stateSchemaV2 || state.Version != stateVersionV2 || state.MigrationEpoch == 0 || state.RelayEpoch == 0 || state.Revision == 0 || !validName(state.DeploymentName) || !validID(state.DeploymentID) ||
		!validEndpoint(state.Endpoint) || state.Generation > 1<<53 || state.LastObservedAt <= 0 || state.RootFingerprint != fingerprint(state.RootPublicDER) ||
		len(state.Profiles) > maxProfiles || len(state.Audit) == 0 || len(state.Audit) > maxProfiles*8 || len(state.PublicationOutbox) != 1 ||
		state.PublicationOutbox[0].Revision != state.Revision || state.PublicationOutbox[0].CreatedAt <= 0 || !validName(state.PublicationOutbox[0].Action) {
		return ErrStateCorrupt
	}
	rootPublic, err := parseP256Public(state.RootPublicDER)
	if err != nil || state.Root.Keys == nil || len(state.Root.Keys) != 1 || state.Root.Keys[0].KeyID != keyID("root", state.RootPublicDER) {
		return ErrStateCorrupt
	}
	issuerPublic, err := parseP256Public(state.IssuerPublicDER)
	if err != nil || state.IssuerKey.KeyID != keyID("issuer", state.IssuerPublicDER) {
		return ErrStateCorrupt
	}
	if requireDistinctKeys(state.Root.Keys[0].KeyID, state.IssuerKey.KeyID, state.RelayKeyID) != nil ||
		state.RelayKeyID != keyID("relay", state.RelayPublic) || len(state.RelayPublic) != 32 {
		return ErrStateCorrupt
	}
	if validateTLSIdentity(master, state.DeploymentID, state.TLS, state.RelayPublic) != nil || validateAddressPool(state.IPv4Pool) != nil || validateAddressPool(state.IPv6Pool) != nil || validateAssignments(state) != nil || validateRecipientUseLedger(state.RecipientUses) != nil {
		return ErrStateCorrupt
	}
	verifier := p256Verifier{keys: map[string]*ecdsa.PublicKey{
		state.Root.Keys[0].KeyID: rootPublic,
		state.IssuerKey.KeyID:    issuerPublic,
	}}
	if verifier.Verify(state.Root.Keys[0], state.DelegationPayload, state.DelegationSig) != nil ||
		verifier.Verify(state.Root.Keys[0], state.RevocationPayload, state.RevocationSig) != nil {
		return ErrStateCorrupt
	}
	delegationPayload, err := profile.EncodeIssuerDelegationV1(state.Delegation)
	if err != nil || !bytes.Equal(delegationPayload, state.DelegationPayload) {
		return ErrStateCorrupt
	}
	revocationPayload, err := profile.EncodeRevocationSetV1(state.Revocations)
	if err != nil || !bytes.Equal(revocationPayload, state.RevocationPayload) {
		return ErrStateCorrupt
	}
	seenProfiles := make(map[string]struct{}, len(state.Profiles))
	for _, record := range state.Profiles {
		if !validName(record.Name) || !validID(record.ProfileID) || !validID(record.ContentID) || record.Generation == 0 ||
			len(record.Artifact) == 0 && !isRevokedProfileTombstone(record) || record.CreatedAt <= 0 || record.ValidUntil <= record.CreatedAt {
			return ErrStateCorrupt
		}
		if err := validateProfileRecordV2(state, record); err != nil {
			return ErrStateCorrupt
		}
		if _, duplicate := seenProfiles[record.ProfileID]; duplicate {
			return ErrStateCorrupt
		}
		seenProfiles[record.ProfileID] = struct{}{}
	}
	previous := ""
	for index, entry := range state.Audit {
		if entry.Sequence != uint64(index+1) || entry.PreviousDigest != previous || entry.At <= 0 || !validName(entry.Action) || !validID(entry.Subject) {
			return ErrStateCorrupt
		}
		expected := auditDigest(entry.Sequence, entry.At, entry.Action, entry.Subject, entry.PreviousDigest)
		if entry.Digest != expected {
			return ErrStateCorrupt
		}
		previous = entry.Digest
	}
	return nil
}

func validateStateV1(state persistedStateV1) error {
	if state.Schema != stateSchemaV1 || state.Revision == 0 || !validName(state.DeploymentName) || !validID(state.DeploymentID) ||
		!validEndpoint(state.Endpoint) || state.Generation > 1<<53 || state.LastObservedAt <= 0 || state.RootFingerprint != fingerprint(state.RootPublicDER) ||
		len(state.Profiles) > maxProfiles || len(state.Audit) == 0 || len(state.Audit) > maxProfiles*8 || len(state.PublicationOutbox) != 1 ||
		state.PublicationOutbox[0].Revision != state.Revision || state.PublicationOutbox[0].CreatedAt <= 0 || !validName(state.PublicationOutbox[0].Action) {
		return ErrStateCorrupt
	}
	rootPublic, err := parseP256Public(state.RootPublicDER)
	if err != nil || state.Root.Keys == nil || len(state.Root.Keys) != 1 || state.Root.Keys[0].KeyID != keyID("root", state.RootPublicDER) {
		return ErrStateCorrupt
	}
	issuerPublic, err := parseP256Public(state.IssuerPublicDER)
	if err != nil || state.IssuerKey.KeyID != keyID("issuer", state.IssuerPublicDER) || requireDistinctKeys(state.Root.Keys[0].KeyID, state.IssuerKey.KeyID, state.RelayKeyID) != nil ||
		state.RelayKeyID != keyID("relay", state.RelayPublic) || len(state.RelayPublic) != 32 {
		return ErrStateCorrupt
	}
	verifier := p256Verifier{keys: map[string]*ecdsa.PublicKey{state.Root.Keys[0].KeyID: rootPublic, state.IssuerKey.KeyID: issuerPublic}}
	if verifier.Verify(state.Root.Keys[0], state.DelegationPayload, state.DelegationSig) != nil || verifier.Verify(state.Root.Keys[0], state.RevocationPayload, state.RevocationSig) != nil {
		return ErrStateCorrupt
	}
	delegationPayload, err := profile.EncodeIssuerDelegationV1(state.Delegation)
	if err != nil || !bytes.Equal(delegationPayload, state.DelegationPayload) {
		return ErrStateCorrupt
	}
	revocationPayload, err := profile.EncodeRevocationSetV1(state.Revocations)
	if err != nil || !bytes.Equal(revocationPayload, state.RevocationPayload) {
		return ErrStateCorrupt
	}
	seenProfiles := make(map[string]struct{}, len(state.Profiles))
	for _, record := range state.Profiles {
		if !validName(record.Name) || !validID(record.ProfileID) || !validID(record.ContentID) || record.Generation == 0 || len(record.Artifact) == 0 || record.CreatedAt <= 0 || record.ValidUntil <= record.CreatedAt {
			return ErrStateCorrupt
		}
		if _, duplicate := seenProfiles[record.ProfileID]; duplicate {
			return ErrStateCorrupt
		}
		seenProfiles[record.ProfileID] = struct{}{}
	}
	previous := ""
	for index, entry := range state.Audit {
		if entry.Sequence != uint64(index+1) || entry.PreviousDigest != previous || entry.At <= 0 || !validName(entry.Action) || !validID(entry.Subject) || entry.Digest != auditDigest(entry.Sequence, entry.At, entry.Action, entry.Subject, entry.PreviousDigest) {
			return ErrStateCorrupt
		}
		previous = entry.Digest
	}
	return nil
}

func validateClockTransition(previous, current int64) error {
	const rollbackTolerance = int64(5 * 60)
	const forwardLimit = int64(90 * 24 * 60 * 60)
	if previous <= 0 || current <= 0 || current < previous-rollbackTolerance || current > previous+forwardLimit {
		return ErrClockUnhealthy
	}
	return nil
}

func appendAudit(state *persistedState, at int64, action, subject string) error {
	if state == nil || at <= 0 || !validName(action) || !validID(subject) {
		return ErrInvalidInput
	}
	previous := ""
	if len(state.Audit) != 0 {
		previous = state.Audit[len(state.Audit)-1].Digest
	}
	sequence := uint64(len(state.Audit) + 1)
	state.Audit = append(state.Audit, auditEntry{
		Sequence: sequence, At: at, Action: action, Subject: subject,
		PreviousDigest: previous, Digest: auditDigest(sequence, at, action, subject, previous),
	})
	return nil
}

func auditDigest(sequence uint64, at int64, action, subject, previous string) string {
	material := fmt.Sprintf("kurd-selfhost-audit-v1\nsequence=%d\nat=%d\naction=%s\nsubject=%s\nprevious=%s\n", sequence, at, action, subject, previous)
	digest := sha256.Sum256([]byte(material))
	return hex.EncodeToString(digest[:])
}

func validName(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character == '.' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func validID(value string) bool { return validName(value) && strings.Contains(value, ".") }

func sortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
