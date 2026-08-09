// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	migrationMarkerFileV2 = "migration-v2.marker"
	migrationBackupFileV1 = "pre-migration-v1.kurd-state"
	migrationMarkerSchema = "kurd-selfhost-migration-marker-v2"
)

type migrationMarkerV2 struct {
	_                                 struct{} `cbor:",toarray"`
	Schema, Phase, DeploymentID       string
	SourceSchema, TargetSchema        string
	MigrationEpoch                    uint64
	SourceRevision, SourceGeneration  uint64
	SourceStateSHA256, BackupBasename string
	CreatedAt                         int64
}

type migrationMarkerEnvelopeV2 struct {
	_       struct{} `cbor:",toarray"`
	Version uint64
	Payload []byte
	MAC     []byte
}

// MigrateToV2 converts one authenticated Phase 16 v1 state exactly once.
func MigrateToV2(dataDir string, now time.Time) error {
	now = now.UTC()
	if dataDir == "" || now.IsZero() {
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
	master, err := loadMasterKey(dataDir)
	if err != nil {
		return err
	}
	defer zero(master)
	raw, err := os.ReadFile(filepath.Join(dataDir, stateFileName))
	if err != nil || len(raw) == 0 || len(raw) > maxStateBytes {
		return ErrStateCorrupt
	}
	if state, err := decodeStateFile(raw, master); err == nil {
		marker, markerErr := readMigrationMarker(dataDir, master)
		if markerErr == nil && marker.Phase == "prepared" && marker.DeploymentID == state.DeploymentID && marker.SourceRevision == state.Revision {
			marker.Phase = "committed"
			if err := writeMigrationMarker(dataDir, master, marker); err != nil {
				return err
			}
			return expandLegacyIPv4Pool(dataDir, master, state, now)
		}
		if markerErr == nil && marker.Phase == "committed" {
			return expandLegacyIPv4Pool(dataDir, master, state, now)
		}
		if errors.Is(markerErr, os.ErrNotExist) {
			return expandLegacyIPv4Pool(dataDir, master, state, now)
		}
		return ErrMigration
	}
	v1, err := decodeStateFileV1(raw, master)
	if err != nil {
		return err
	}
	existingMarker, markerErr := readMigrationMarker(dataDir, master)
	if markerErr == nil {
		if existingMarker.Phase == "committed" {
			return ErrRollback
		}
		if existingMarker.Phase != "prepared" || existingMarker.DeploymentID != v1.DeploymentID || existingMarker.SourceRevision != v1.Revision || existingMarker.SourceGeneration != v1.Generation {
			return ErrMigration
		}
	} else if !errors.Is(markerErr, os.ErrNotExist) {
		return ErrMigration
	}
	if err := validateClockTransition(v1.LastObservedAt, now.Unix()); err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	marker := migrationMarkerV2{
		Schema: migrationMarkerSchema, Phase: "prepared", DeploymentID: v1.DeploymentID,
		SourceSchema: stateSchemaV1, TargetSchema: stateSchemaV2, MigrationEpoch: migrationEpochV2,
		SourceRevision: v1.Revision, SourceGeneration: v1.Generation, SourceStateSHA256: hexSHA256(digest),
		BackupBasename: migrationBackupFileV1, CreatedAt: now.Unix(),
	}
	if markerErr == nil && (existingMarker.SourceStateSHA256 != marker.SourceStateSHA256 || existingMarker.BackupBasename != marker.BackupBasename || existingMarker.MigrationEpoch != marker.MigrationEpoch) {
		return ErrMigration
	}
	backupPath := filepath.Join(dataDir, migrationBackupFileV1)
	if existing, readErr := os.ReadFile(backupPath); readErr == nil {
		if !bytes.Equal(existing, raw) {
			return ErrMigration
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	} else {
		if err := writeExclusive(backupPath, raw, 0o600); err != nil {
			return err
		}
		if err := syncDirectory(dataDir); err != nil {
			return err
		}
	}
	if err := writeMigrationMarker(dataDir, master, marker); err != nil {
		return err
	}
	v2, err := migrateStateV1(v1, master, now)
	if err != nil {
		return err
	}
	if err := saveState(dataDir, master, v2); err != nil {
		return err
	}
	marker.Phase = "committed"
	return writeMigrationMarker(dataDir, master, marker)
}

func expandLegacyIPv4Pool(dataDir string, master []byte, state persistedState, now time.Time) error {
	if state.IPv4Pool.PrefixLength == 16 {
		return nil
	}
	if state.IPv4Pool.PrefixLength != 24 || !bytes.Equal(state.IPv4Pool.Network, []byte{10, 77, 0, 0}) || !bytes.Equal(state.IPv4Pool.ServerDNS, []byte{10, 77, 0, 1}) {
		return ErrMigration
	}
	if err := validateClockTransition(state.LastObservedAt, now.Unix()); err != nil {
		return err
	}
	state.IPv4Pool.PrefixLength = 16
	if state.IPv4Pool.NextHostOffset < 2 {
		state.IPv4Pool.NextHostOffset = 2
	}
	state.LastObservedAt = now.Unix()
	state.Revision++
	if err := appendAudit(&state, now.Unix(), "expand-ipv4-pool", "deployment.network.ipv4"); err != nil {
		return err
	}
	state.PublicationOutbox = []publicationOutboxEntry{{Revision: state.Revision, CreatedAt: now.Unix(), Action: "expand-ipv4-pool"}}
	return saveState(dataDir, master, state)
}

// RollbackMigrationV2 restores only the authenticated exact v1 backup before
// any v2 transaction advances the source revision.
func RollbackMigrationV2(dataDir string) error {
	if dataDir == "" {
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
	master, err := loadMasterKey(dataDir)
	if err != nil {
		return err
	}
	defer zero(master)
	marker, err := readMigrationMarker(dataDir, master)
	if err != nil || marker.Phase != "committed" {
		return ErrRollback
	}
	backup, err := os.ReadFile(filepath.Join(dataDir, marker.BackupBasename))
	if err != nil {
		return ErrRollback
	}
	digest := sha256.Sum256(backup)
	if hexSHA256(digest) != marker.SourceStateSHA256 {
		return ErrRollback
	}
	v1, err := decodeStateFileV1(backup, master)
	if err != nil || v1.DeploymentID != marker.DeploymentID || v1.Revision != marker.SourceRevision || v1.Generation != marker.SourceGeneration {
		return ErrRollback
	}
	current, err := os.ReadFile(filepath.Join(dataDir, stateFileName))
	if err != nil {
		return ErrRollback
	}
	if bytes.Equal(current, backup) {
		if err := os.Remove(filepath.Join(dataDir, migrationMarkerFileV2)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(dataDir)
	}
	state, err := loadStateWithKey(dataDir, master)
	if err != nil || state.Revision != marker.SourceRevision || state.Generation != marker.SourceGeneration || state.MigrationEpoch != marker.MigrationEpoch {
		return ErrRollback
	}
	if err := atomicWriteFile(filepath.Join(dataDir, stateFileName), backup, 0o600); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dataDir, migrationMarkerFileV2)); err != nil {
		return err
	}
	return syncDirectory(dataDir)
}

func migrateStateV1(v1 persistedStateV1, master []byte, now time.Time) (persistedState, error) {
	host, _, err := netSplitHostPort(v1.Endpoint)
	if err != nil {
		return persistedState{}, err
	}
	tlsIdentity, err := newTLSIdentity(master, v1.DeploymentID, host, 1, now)
	if err != nil {
		return persistedState{}, err
	}
	ipv4Pool, ipv6Pool := defaultAddressPools()
	profiles := make([]profileRecord, len(v1.Profiles))
	for index := range v1.Profiles {
		record := v1.Profiles[index]
		profiles[index] = profileRecord{
			Name: record.Name, ProfileID: record.ProfileID, ContentID: record.ContentID, Generation: record.Generation,
			Artifact: append([]byte(nil), record.Artifact...), CreatedAt: record.CreatedAt, ValidUntil: record.ValidUntil,
			Revoked: record.Revoked, Mode: profileModeAuthorityOnly,
		}
	}
	state := persistedState{
		Schema: stateSchemaV2, Version: stateVersionV2, MigrationEpoch: migrationEpochV2,
		Revision: v1.Revision, Generation: v1.Generation, LastObservedAt: v1.LastObservedAt,
		DeploymentID: v1.DeploymentID, DeploymentName: v1.DeploymentName, Endpoint: v1.Endpoint,
		Root: v1.Root, RootPublicDER: append([]byte(nil), v1.RootPublicDER...), RootFingerprint: v1.RootFingerprint,
		IssuerKey: v1.IssuerKey, IssuerPublicDER: append([]byte(nil), v1.IssuerPublicDER...), IssuerSecret: cloneSealed(v1.IssuerSecret),
		RelayEpoch: 1, RelayKeyID: v1.RelayKeyID, RelayPublic: append([]byte(nil), v1.RelayPublic...), RelaySecret: cloneSealed(v1.RelaySecret), TLS: tlsIdentity,
		Delegation: v1.Delegation, DelegationPayload: append([]byte(nil), v1.DelegationPayload...), DelegationSig: append([]byte(nil), v1.DelegationSig...),
		Revocations: v1.Revocations, RevocationPayload: append([]byte(nil), v1.RevocationPayload...), RevocationSig: append([]byte(nil), v1.RevocationSig...),
		RecoveryConfirmed: v1.RecoveryConfirmed, Drained: v1.Drained, IPv4Pool: ipv4Pool, IPv6Pool: ipv6Pool,
		Profiles: profiles, Assignments: []addressAssignmentV1{}, RecipientUses: recipientUseLedgerV1{}, Audit: append([]auditEntry(nil), v1.Audit...), PublicationOutbox: append([]publicationOutboxEntry(nil), v1.PublicationOutbox...),
	}
	if err := validateState(state, master); err != nil {
		return persistedState{}, err
	}
	return state, nil
}

func writeMigrationMarker(dataDir string, master []byte, marker migrationMarkerV2) error {
	if err := validateMigrationMarker(marker); err != nil {
		return err
	}
	payload, err := encodeCanonical(marker)
	if err != nil {
		return err
	}
	envelope := migrationMarkerEnvelopeV2{Version: stateVersionV2, Payload: payload, MAC: migrationMarkerMAC(master, payload)}
	encoded, err := encodeCanonical(envelope)
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dataDir, migrationMarkerFileV2), encoded, 0o600)
}

func readMigrationMarker(dataDir string, master []byte) (migrationMarkerV2, error) {
	raw, err := os.ReadFile(filepath.Join(dataDir, migrationMarkerFileV2))
	if err != nil {
		return migrationMarkerV2{}, err
	}
	var envelope migrationMarkerEnvelopeV2
	if decodeCanonical(raw, &envelope, 4096) != nil || envelope.Version != stateVersionV2 || subtle.ConstantTimeCompare(envelope.MAC, migrationMarkerMAC(master, envelope.Payload)) != 1 {
		return migrationMarkerV2{}, ErrMigration
	}
	var marker migrationMarkerV2
	if decodeCanonical(envelope.Payload, &marker, 4096) != nil || validateMigrationMarker(marker) != nil {
		return migrationMarkerV2{}, ErrMigration
	}
	return marker, nil
}

func validateMigrationMarker(marker migrationMarkerV2) error {
	if marker.Schema != migrationMarkerSchema || marker.Phase != "prepared" && marker.Phase != "committed" || !validID(marker.DeploymentID) ||
		marker.SourceSchema != stateSchemaV1 || marker.TargetSchema != stateSchemaV2 || marker.MigrationEpoch != migrationEpochV2 || marker.SourceRevision == 0 ||
		marker.SourceStateSHA256 == "" || marker.BackupBasename != migrationBackupFileV1 || marker.CreatedAt <= 0 {
		return ErrMigration
	}
	return nil
}

func migrationMarkerMAC(master, payload []byte) []byte {
	mac := hmac.New(sha256.New, master)
	_, _ = mac.Write([]byte("kurd-selfhost/migration-marker/v2\x00"))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func cloneSealed(value sealedSecret) sealedSecret {
	return sealedSecret{Version: value.Version, Nonce: append([]byte(nil), value.Nonce...), Ciphertext: append([]byte(nil), value.Ciphertext...)}
}

func hexSHA256(value [32]byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, 64)
	for index, part := range value {
		encoded[index*2] = digits[part>>4]
		encoded[index*2+1] = digits[part&15]
	}
	return string(encoded)
}

func netSplitHostPort(endpoint string) (string, string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", "", ErrInvalidInput
	}
	return strings.ToLower(host), port, nil
}
