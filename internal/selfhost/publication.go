// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"kurdistan/internal/product/profile"
)

func PublishSnapshot(dataDir, destination string, now time.Time) (PublicationSummary, error) {
	if dataDir == "" || destination == "" || now.IsZero() {
		return PublicationSummary{}, ErrInvalidInput
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		return PublicationSummary{}, err
	}
	defer zero(master)
	if err := validateClockTransition(state.LastObservedAt, now.UTC().Unix()); err != nil {
		return PublicationSummary{}, err
	}
	records := append([]profileRecord(nil), state.Profiles...)
	sort.Slice(records, func(left, right int) bool { return records[left].ProfileID < records[right].ProfileID })
	profiles := make([][]byte, 0, len(records))
	if !state.Revocations.EmergencyDenied {
		for _, record := range records {
			if !record.Revoked {
				profiles = append(profiles, append([]byte(nil), record.Artifact...))
			}
		}
	}
	snapshot := publicationSnapshot{
		Version: 1, Revision: state.Revision, GeneratedAt: now.UTC().Unix(), DeploymentID: state.DeploymentID,
		RootFingerprint: state.RootFingerprint, Root: state.Root, RootPublicDER: state.RootPublicDER,
		Revocations: state.Revocations, RevocationPayload: state.RevocationPayload, RevocationSignature: state.RevocationSig,
		Profiles: profiles,
	}
	encoded, err := encodeCanonical(snapshot)
	if err != nil || len(encoded) == 0 || len(encoded) > maxStateBytes {
		return PublicationSummary{}, ErrInvalidInput
	}
	verified, err := VerifyPublicationSnapshot(encoded, now.UTC())
	if err != nil {
		return PublicationSummary{}, err
	}
	if err := atomicWriteFile(destination, encoded, 0o644); err != nil {
		return PublicationSummary{}, err
	}
	cursorPayload := publicationCursorPayload{Version: 1, DeploymentID: state.DeploymentID, Revision: state.Revision, Digest: verified.Digest}
	payload, err := encodeCanonical(cursorPayload)
	if err != nil {
		return PublicationSummary{}, err
	}
	cursor, err := encodeCanonical(publicationCursorEnvelope{Payload: payload, MAC: stateMACV1(master, payload)})
	if err != nil {
		return PublicationSummary{}, err
	}
	if err := atomicWriteFile(filepath.Join(dataDir, publicationCursorFileName), cursor, 0o600); err != nil {
		return PublicationSummary{}, err
	}
	return verified, nil
}

func PublicationDeliveryStatus(dataDir string) (PublicationDelivery, error) {
	state, master, err := loadState(dataDir)
	if err != nil {
		return PublicationDelivery{}, err
	}
	defer zero(master)
	result := PublicationDelivery{Schema: "kurd-selfhost-publication-delivery-v1", RequiredRevision: state.PublicationOutbox[0].Revision, Pending: true}
	raw, err := os.ReadFile(filepath.Join(dataDir, publicationCursorFileName))
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return PublicationDelivery{}, ErrStateCorrupt
	}
	var envelope publicationCursorEnvelope
	if decodeCanonical(raw, &envelope, 4096) != nil || !verifyStateMAC(stateMACV1(master, envelope.Payload), envelope.MAC) {
		return PublicationDelivery{}, ErrStateCorrupt
	}
	var cursor publicationCursorPayload
	if decodeCanonical(envelope.Payload, &cursor, 2048) != nil || cursor.Version != 1 || cursor.DeploymentID != state.DeploymentID ||
		cursor.Revision == 0 || cursor.Revision > state.Revision || len(cursor.Digest) != 64 {
		return PublicationDelivery{}, ErrStateCorrupt
	}
	if _, err := hex.DecodeString(cursor.Digest); err != nil {
		return PublicationDelivery{}, ErrStateCorrupt
	}
	result.DeliveredRevision, result.Digest = cursor.Revision, cursor.Digest
	result.Pending = cursor.Revision < result.RequiredRevision
	return result, nil
}

func VerifyPublicationSnapshot(encoded []byte, now time.Time) (PublicationSummary, error) {
	if now.IsZero() {
		return PublicationSummary{}, ErrInvalidInput
	}
	var snapshot publicationSnapshot
	if decodeCanonical(encoded, &snapshot, maxStateBytes) != nil || snapshot.Version != 1 || snapshot.Revision == 0 || snapshot.GeneratedAt <= 0 ||
		!validID(snapshot.DeploymentID) || snapshot.RootFingerprint != fingerprint(snapshot.RootPublicDER) || len(snapshot.Profiles) > maxProfiles ||
		snapshot.GeneratedAt > now.UTC().Unix()+300 {
		return PublicationSummary{}, ErrInvalidInput
	}
	rootPublic, err := parseP256Public(snapshot.RootPublicDER)
	if err != nil || len(snapshot.Root.Keys) != 1 || snapshot.Root.Keys[0].KeyID != keyID("root", snapshot.RootPublicDER) {
		return PublicationSummary{}, ErrInvalidInput
	}
	revocationPayload, err := profile.EncodeRevocationSetV1(snapshot.Revocations)
	verifier := p256Verifier{keys: map[string]*ecdsa.PublicKey{snapshot.Root.Keys[0].KeyID: rootPublic}}
	if err != nil || !bytes.Equal(revocationPayload, snapshot.RevocationPayload) ||
		verifier.Verify(snapshot.Root.Keys[0], snapshot.RevocationPayload, snapshot.RevocationSignature) != nil ||
		snapshot.Revocations.RootEpoch != snapshot.Root.Epoch || now.UTC().Unix() < snapshot.Revocations.IssuedAt || now.UTC().Unix() >= snapshot.Revocations.ExpiresAt {
		return PublicationSummary{}, ErrInvalidInput
	}
	if snapshot.Revocations.EmergencyDenied && len(snapshot.Profiles) != 0 {
		return PublicationSummary{}, ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(snapshot.Profiles))
	for _, artifact := range snapshot.Profiles {
		verified, err := VerifyBundle(artifact, now.UTC(), 1)
		if err != nil || verified.DeploymentID != snapshot.DeploymentID || verified.RootFingerprint != snapshot.RootFingerprint ||
			verified.RootEpoch != snapshot.Root.Epoch || verified.RevocationEpoch > snapshot.Revocations.Epoch ||
			contains(snapshot.Revocations.RevokedContentIDs, verified.ContentID) {
			return PublicationSummary{}, ErrInvalidInput
		}
		if _, duplicate := seen[verified.ProfileID]; duplicate {
			return PublicationSummary{}, ErrInvalidInput
		}
		seen[verified.ProfileID] = struct{}{}
	}
	return PublicationSummary{
		Schema: "kurd-selfhost-publication-v1", DeploymentID: snapshot.DeploymentID, RootFingerprint: snapshot.RootFingerprint,
		Digest: artifactDigest(encoded), Revision: snapshot.Revision, RevocationEpoch: snapshot.Revocations.Epoch,
		GeneratedAt: snapshot.GeneratedAt, ProfileCount: len(snapshot.Profiles),
	}, nil
}

func atomicWriteFile(destination string, value []byte, mode os.FileMode) error {
	if destination == "" || len(value) == 0 {
		return ErrInvalidInput
	}
	directory := filepath.Dir(destination)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".publish-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	reference := destination
	if _, err := os.Stat(reference); errors.Is(err, os.ErrNotExist) {
		reference = directory
	} else if err != nil {
		file.Close()
		return err
	}
	if err := preserveOwnership(temporary, reference); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(value); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		backup := destination + ".previous"
		_ = os.Remove(backup)
		if _, err := os.Stat(destination); err == nil {
			if err := os.Rename(destination, backup); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(temporary, destination); err != nil {
			_ = os.Rename(backup, destination)
			return err
		}
		_ = os.Remove(backup)
		return syncDirectory(directory)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	return syncDirectory(directory)
}
