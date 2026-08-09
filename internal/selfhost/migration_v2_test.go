// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

const frozenPhase16StateSHA256 = "b0106fef213cabeeed1dc04c05f97e56758a719c66fe691c32b0e014c3e4fb36"

func TestFrozenPhase16StateMigratesExactlyOnceAndCanRollbackBeforeMutation(t *testing.T) {
	dataDir, raw, master := copyPhase16Fixture(t)
	if digest := sha256File(t, filepath.Join(dataDir, stateFileName)); digest != frozenPhase16StateSHA256 {
		t.Fatalf("legacy fixture drift=%s", digest)
	}
	v1, err := decodeStateFileV1(raw, master)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(v1.LastObservedAt+60, 0)
	if err := MigrateToV2(dataDir, now); err != nil {
		t.Fatal(err)
	}
	v2, loadedMaster, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	zero(loadedMaster)
	if v2.DeploymentID != v1.DeploymentID || v2.RootFingerprint != v1.RootFingerprint || v2.IssuerKey != v1.IssuerKey || v2.RelayKeyID != v1.RelayKeyID ||
		v2.Revision != v1.Revision || v2.Generation != v1.Generation || len(v2.Profiles) != len(v1.Profiles) || len(v2.Audit) != len(v1.Audit) || v2.Profiles[0].Mode != profileModeAuthorityOnly {
		t.Fatalf("migration did not preserve authority: v1=%+v v2=%+v", v1, v2)
	}
	if !reflect.DeepEqual(v2.Root, v1.Root) || !bytes.Equal(v2.RootPublicDER, v1.RootPublicDER) ||
		!bytes.Equal(v2.IssuerPublicDER, v1.IssuerPublicDER) || !reflect.DeepEqual(v2.IssuerSecret, v1.IssuerSecret) ||
		!bytes.Equal(v2.RelayPublic, v1.RelayPublic) || !reflect.DeepEqual(v2.RelaySecret, v1.RelaySecret) ||
		!reflect.DeepEqual(v2.Delegation, v1.Delegation) || !bytes.Equal(v2.DelegationPayload, v1.DelegationPayload) || !bytes.Equal(v2.DelegationSig, v1.DelegationSig) ||
		!reflect.DeepEqual(v2.Revocations, v1.Revocations) || !bytes.Equal(v2.RevocationPayload, v1.RevocationPayload) || !bytes.Equal(v2.RevocationSig, v1.RevocationSig) ||
		!reflect.DeepEqual(v2.Audit, v1.Audit) || !reflect.DeepEqual(v2.PublicationOutbox, v1.PublicationOutbox) {
		t.Fatal("migration changed frozen Phase 16 authority, revocation, audit, or outbox data")
	}
	for index, legacy := range v1.Profiles {
		migrated := v2.Profiles[index]
		if migrated.Name != legacy.Name || migrated.ProfileID != legacy.ProfileID || migrated.ContentID != legacy.ContentID || migrated.Generation != legacy.Generation ||
			!bytes.Equal(migrated.Artifact, legacy.Artifact) || migrated.CreatedAt != legacy.CreatedAt || migrated.ValidUntil != legacy.ValidUntil || migrated.Revoked != legacy.Revoked {
			t.Fatalf("profile %d changed during migration", index)
		}
	}
	backup, err := os.ReadFile(filepath.Join(dataDir, migrationBackupFileV1))
	if err != nil || !bytes.Equal(backup, raw) {
		t.Fatal("migration backup is not the exact v1 state")
	}
	marker, err := readMigrationMarker(dataDir, master)
	if err != nil || marker.Phase != "committed" || marker.SourceRevision != v1.Revision {
		t.Fatalf("marker=%+v err=%v", marker, err)
	}
	if err := MigrateToV2(dataDir, now.Add(time.Minute)); err != nil {
		t.Fatalf("migration not idempotent: %v", err)
	}
	if err := RollbackMigrationV2(dataDir); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(filepath.Join(dataDir, stateFileName))
	if err != nil || !bytes.Equal(restored, raw) {
		t.Fatal("rollback did not restore exact v1 bytes")
	}
}

func TestMigrationRollbackClosesAfterFirstV2Transaction(t *testing.T) {
	dataDir, raw, master := copyPhase16Fixture(t)
	v1, err := decodeStateFileV1(raw, master)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(v1.LastObservedAt+60, 0)
	if err := MigrateToV2(dataDir, now); err != nil {
		t.Fatal(err)
	}
	if err := SetDrained(dataDir, true, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := RollbackMigrationV2(dataDir); !errors.Is(err, ErrRollback) {
		t.Fatalf("post-mutation rollback error=%v", err)
	}
}

func TestMigrationApplyExpandsLegacyIPv4PoolExactlyOnce(t *testing.T) {
	dataDir, _, _ := initializedV2TestState(t)
	state, master, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	state.IPv4Pool.PrefixLength = 24
	state.IPv4Pool.NextHostOffset = 254
	if err := saveState(dataDir, master, state); err != nil {
		zero(master)
		t.Fatal(err)
	}
	zero(master)

	now := time.Unix(state.LastObservedAt+60, 0).UTC()
	if err := MigrateToV2(dataDir, now); err != nil {
		t.Fatal(err)
	}
	expanded, loadedMaster, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	zero(loadedMaster)
	if expanded.IPv4Pool.PrefixLength != 16 || expanded.Revision != state.Revision+1 || expanded.Audit[len(expanded.Audit)-1].Action != "expand-ipv4-pool" {
		t.Fatalf("expanded state=%+v", expanded.IPv4Pool)
	}
	if err := MigrateToV2(dataDir, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	idempotent, loadedMaster, err := loadState(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	zero(loadedMaster)
	if idempotent.Revision != expanded.Revision {
		t.Fatalf("idempotent revision=%d want=%d", idempotent.Revision, expanded.Revision)
	}
}

func TestMigrationRollbackResumesAfterStateRestoreBeforeMarkerRemoval(t *testing.T) {
	dataDir, raw, master := copyPhase16Fixture(t)
	v1, err := decodeStateFileV1(raw, master)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(v1.LastObservedAt+60, 0)
	if err := MigrateToV2(dataDir, now); err != nil {
		t.Fatal(err)
	}
	// Reproduce a process failure after the exact v1 state replacement but
	// before the authenticated migration marker is removed.
	if err := atomicWriteFile(filepath.Join(dataDir, stateFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RollbackMigrationV2(dataDir); err != nil {
		t.Fatalf("resume interrupted rollback: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, migrationMarkerFileV2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("migration marker still present: %v", err)
	}
	restored, err := os.ReadFile(filepath.Join(dataDir, stateFileName))
	if err != nil || !bytes.Equal(restored, raw) {
		t.Fatal("resumed rollback did not preserve exact v1 state")
	}
}

func TestCommittedMigrationRejectsSubstitutedV1AndMarkerTamper(t *testing.T) {
	dataDir, raw, master := copyPhase16Fixture(t)
	v1, err := decodeStateFileV1(raw, master)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(v1.LastObservedAt+60, 0)
	if err := MigrateToV2(dataDir, now); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(dataDir, migrationMarkerFileV2)
	markerRaw, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(filepath.Join(dataDir, stateFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MigrateToV2(dataDir, now.Add(time.Minute)); !errors.Is(err, ErrRollback) {
		t.Fatalf("substituted v1 state error=%v", err)
	}
	if err := atomicWriteFile(filepath.Join(dataDir, stateFileName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	markerRaw[len(markerRaw)-1] ^= 1
	if err := atomicWriteFile(markerPath, markerRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MigrateToV2(dataDir, now.Add(2*time.Minute)); !errors.Is(err, ErrMigration) {
		t.Fatalf("tampered marker error=%v", err)
	}
}

func TestStateReplacementFaultsReopenOnlyCompleteOldOrNewState(t *testing.T) {
	for _, phase := range []stateWritePhase{
		stateWriteBeforeTemporary, stateWriteDuringTemporary, stateWriteBeforeSync,
		stateWriteBeforeRename, stateWriteAfterRename, stateWriteBeforeDirSync,
	} {
		t.Run(string(phase), func(t *testing.T) {
			dataDir, _, _ := initializedV2TestState(t)
			state, master, err := loadState(dataDir)
			if err != nil {
				t.Fatal(err)
			}
			defer zero(master)
			oldRevision := state.Revision
			state.Drained = true
			state.Revision++
			if err := appendAudit(&state, state.LastObservedAt+1, "drain-node", "node.runtime"); err != nil {
				t.Fatal(err)
			}
			state.LastObservedAt++
			state.PublicationOutbox = []publicationOutboxEntry{{Revision: state.Revision, CreatedAt: state.LastObservedAt, Action: "drain-node"}}
			injected := errors.New("injected write fault")
			err = saveStateWithHooks(dataDir, master, state, &stateWriteHooks{Fail: func(observed stateWritePhase) error {
				if observed == phase {
					return injected
				}
				return nil
			}})
			if err == nil {
				t.Fatal("injected write succeeded")
			}
			if phase == stateWriteAfterRename || phase == stateWriteBeforeDirSync {
				if !errors.Is(err, ErrCommitUncertain) {
					t.Fatalf("post-rename error is not uncertain: %v", err)
				}
			}
			reopened, err := loadStateWithKey(dataDir, master)
			if err != nil {
				t.Fatalf("reopen partial state: %v", err)
			}
			if reopened.Revision != oldRevision && reopened.Revision != oldRevision+1 {
				t.Fatalf("reopened revision=%d old=%d", reopened.Revision, oldRevision)
			}
			if reopened.Revision == oldRevision && reopened.Drained || reopened.Revision == oldRevision+1 && !reopened.Drained {
				t.Fatalf("mixed state revision=%d drained=%v", reopened.Revision, reopened.Drained)
			}
		})
	}
}

func copyPhase16Fixture(t *testing.T) (string, []byte, []byte) {
	t.Helper()
	destination := t.TempDir()
	var state, master []byte
	for _, name := range []string{stateFileName, masterKeyFileName} {
		value, err := os.ReadFile(filepath.Join("testdata", "phase16-v1", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, name), value, 0o600); err != nil {
			t.Fatal(err)
		}
		if name == stateFileName {
			state = value
		} else {
			master = value
		}
	}
	return destination, state, master
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return artifactDigest(value)
}
