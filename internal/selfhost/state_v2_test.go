// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveStateReportsCapacityInsteadOfCorruption(t *testing.T) {
	dataDir, recovery, passphrase := initializedV2TestState(t)
	now := time.Unix(1_760_000_000, 0).UTC()
	if err := ConfirmRecovery(dataDir, recovery, passphrase, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	issued, err := CreateProfile(dataDir, CreateProfileOptions{Name: "capacity", ValidFor: time.Hour, Now: now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	index := profileIndex(state.Profiles, issued.ProfileID)
	if index < 0 {
		t.Fatal("created profile missing from state")
	}
	state.Profiles[index].Artifact = bytes.Repeat([]byte{0x42}, maxStateBytes)
	if err := saveState(dataDir, master, state); !errors.Is(err, ErrCapacityExhausted) {
		t.Fatalf("oversized valid state error = %v, want capacity exhausted", err)
	}
}

func TestStateV2RoundTripDoesNotAliasMutableData(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	masterBeforeLoad, err := loadMasterKey(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, stateFileName))
	if err != nil {
		zero(masterBeforeLoad)
		t.Fatal(err)
	}
	var envelope stateEnvelope
	if err := decodeCanonical(raw, &envelope, maxStateBytes); err != nil {
		zero(masterBeforeLoad)
		t.Fatalf("state envelope is not canonical: %v", err)
	}
	var decoded persistedState
	if err := decodeCanonical(envelope.Payload, &decoded, maxStateBytes); err != nil {
		zero(masterBeforeLoad)
		t.Fatalf("state v2 payload is not canonical: %v", err)
	}
	if err := validateRecipientUseLedger(decoded.RecipientUses); err != nil {
		zero(masterBeforeLoad)
		t.Fatalf("empty recipient-use ledger did not survive state v2 round trip: %v", err)
	}
	zero(masterBeforeLoad)
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	originalRoot := append([]byte(nil), state.RootPublicDER...)
	state.RootPublicDER[0] ^= 0xff
	state.TLS.LeafDER[0] ^= 0xff
	state.IPv4Pool.Network[0] ^= 0xff
	zero(master)
	reloaded, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	if string(reloaded.RootPublicDER) != string(originalRoot) {
		t.Fatal("decoded state aliases a prior caller mutation")
	}
	if reloaded.Schema != stateSchemaV2 || reloaded.Version != stateVersionV2 || reloaded.MigrationEpoch != migrationEpochV2 || reloaded.RelayEpoch != 1 {
		t.Fatalf("unexpected v2 authority: %+v", reloaded)
	}
}

func TestStateV2RoundTripSurvivesAuditBeyondLegacyDecoderLimit(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	for len(state.Audit) < maxProfiles+65 {
		at := state.LastObservedAt + int64(len(state.Audit)) + 1
		if err := appendAudit(&state, at, "stress-rotation", "profile.fixture"); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveState(dataDir, master, state); err != nil {
		t.Fatalf("writer rejected its validated audit state: %v", err)
	}
	reloaded, reloadedMaster, err := loadState(dataDir)
	if err != nil {
		t.Fatalf("reader rejected writer-accepted audit state: %v", err)
	}
	defer zero(reloadedMaster)
	if len(reloaded.Audit) != maxProfiles+65 {
		t.Fatalf("reloaded audit entries = %d, want %d", len(reloaded.Audit), maxProfiles+65)
	}
}

func TestCanonicalDecoderAcceptsValidatedAuditCapacity(t *testing.T) {
	encoded, err := encodeCanonical(make([]uint64, maxAuditEntries))
	if err != nil {
		t.Fatal(err)
	}
	var decoded []uint64
	if err := decodeCanonical(encoded, &decoded, maxStateBytes); err != nil {
		t.Fatalf("decoder rejected the writer's validated audit capacity: %v", err)
	}
	if len(decoded) != maxAuditEntries {
		t.Fatalf("decoded entries = %d, want %d", len(decoded), maxAuditEntries)
	}
}

func TestCanonicalDecoderRejectsArrayBeyondSharedCapacity(t *testing.T) {
	encoded, err := encodeCanonical(make([]uint64, maxStateArrayElements+1))
	if err != nil {
		t.Fatal(err)
	}
	var decoded []uint64
	if err := decodeCanonical(encoded, &decoded, maxStateBytes); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("decoder overflow error = %v, want invalid input", err)
	}
}

func TestAppendAuditRejectsBeyondValidatedCapacity(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	for len(state.Audit) < maxAuditEntries {
		at := state.LastObservedAt + int64(len(state.Audit)) + 1
		if err := appendAudit(&state, at, "stress-rotation", "profile.fixture"); err != nil {
			t.Fatal(err)
		}
	}
	at := state.LastObservedAt + int64(len(state.Audit)) + 1
	if err := appendAudit(&state, at, "stress-rotation", "profile.fixture"); !errors.Is(err, ErrCapacityExhausted) {
		t.Fatalf("audit append overflow error = %v, want capacity exhausted", err)
	}
	if len(state.Audit) != maxAuditEntries {
		t.Fatalf("audit overflow mutated state: entries = %d, want %d", len(state.Audit), maxAuditEntries)
	}
}

func TestStateEnvelopeRejectsFutureAndCrossVersionPayloads(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	master, err := loadMasterKey(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(master)
	raw, err := os.ReadFile(filepath.Join(dataDir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	var envelope stateEnvelope
	if err := decodeCanonical(raw, &envelope, maxStateBytes); err != nil {
		t.Fatal(err)
	}
	future := envelope
	future.Version = stateVersionV2 + 1
	futureRaw, _ := encodeCanonical(future)
	if _, err := decodeStateFile(futureRaw, master); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("future version error=%v", err)
	}
	cross := envelope
	cross.Version = stateVersionV1
	cross.MAC = stateMACV1(master, cross.Payload)
	crossRaw, _ := encodeCanonical(cross)
	if _, err := decodeStateFileV1(crossRaw, master); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("v2 payload accepted under v1 envelope: %v", err)
	}
}

func initializedV2TestState(t *testing.T) (string, string, []byte) {
	t.Helper()
	directory := t.TempDir()
	dataDir := filepath.Join(directory, "state")
	recovery := filepath.Join(directory, "recovery.kurd-recovery")
	passphrase := []byte("state v2 test recovery passphrase")
	if _, err := Initialize(InitOptions{
		DataDir: dataDir, DeploymentName: "state-v2", Endpoint: "203.0.113.7:443",
		RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: time.Unix(1_760_000_000, 0),
	}); err != nil {
		t.Fatal(err)
	}
	return dataDir, recovery, passphrase
}
