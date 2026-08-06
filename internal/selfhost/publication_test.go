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

func TestPublicationSnapshotTracksRevocationAndDeploymentDisable(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	publication := filepath.Join(base, "published", "snapshot.kurd-publication")
	passphrase := []byte("correct horse battery staple")
	now := time.Unix(1_800_000_000, 0).UTC()
	if _, err := Initialize(InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(dataDir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	issued, err := CreateProfile(dataDir, CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	first, err := PublishSnapshot(dataDir, publication, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.ProfileCount != 1 {
		t.Fatalf("published profile count = %d", first.ProfileCount)
	}
	raw, err := os.ReadFile(publication)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPublicationSnapshot(raw, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := RevokeProfile(dataDir, RevokeProfileOptions{ProfileID: issued.ProfileID, RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now.Add(3 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	second, err := PublishSnapshot(dataDir, publication, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if second.ProfileCount != 0 || second.RevocationEpoch <= first.RevocationEpoch {
		t.Fatalf("revocation publication mismatch: first=%+v second=%+v", first, second)
	}
	raw, err = os.ReadFile(publication)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if _, err := VerifyPublicationSnapshot(raw, now.Add(4*time.Minute)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("tampered publication error = %v", err)
	}
}

func TestPublicationOutboxIsAtomicAndCursorIsAuthenticated(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	publication := filepath.Join(base, "published", "snapshot.kurd-publication")
	passphrase := []byte("correct horse battery staple")
	now := time.Unix(1_800_100_000, 0).UTC()
	if _, err := Initialize(InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	zero(master)
	if len(state.PublicationOutbox) != 1 || state.PublicationOutbox[0].Revision != state.Revision || state.PublicationOutbox[0].Action != "initialize" {
		t.Fatalf("initial publication outbox mismatch: %+v", state.PublicationOutbox)
	}
	first, err := PublishSnapshot(dataDir, publication, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	status, err := PublicationDeliveryStatus(dataDir)
	if err != nil || status.Pending || status.DeliveredRevision != first.Revision || status.Digest != first.Digest {
		t.Fatalf("publication delivery status mismatch: status=%+v err=%v", status, err)
	}
	if err := SetDrained(dataDir, true, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	status, err = PublicationDeliveryStatus(dataDir)
	if err != nil || !status.Pending || status.RequiredRevision <= status.DeliveredRevision {
		t.Fatalf("new state did not produce a pending publication: status=%+v err=%v", status, err)
	}
	cursorPath := filepath.Join(dataDir, publicationCursorFileName)
	if err := os.WriteFile(cursorPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PublicationDeliveryStatus(dataDir); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("tampered publication cursor error = %v", err)
	}
}
