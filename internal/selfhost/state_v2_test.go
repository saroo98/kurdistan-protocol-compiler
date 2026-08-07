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
