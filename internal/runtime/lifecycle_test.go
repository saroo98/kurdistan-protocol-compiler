// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"reflect"
	gort "runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

func newAuthenticatingFirstRecordPairV1(t *testing.T, seed int64, rotation string, maxSession, maxKey int) (*HandshakeRuntime, *ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1) {
	t.Helper()
	fixture := newLifecycleFixtureV1(t, seed, rotation, maxSession, maxKey)
	owner := lifecycleRuntimeV1(t, fixture)
	client, relay, err := owner.NewAuthenticatedChannelPair(lifecyclePairInputV1(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return owner, client, relay
}

func TestFirstRecordCommitServerEstablishOrderingV1(t *testing.T) {
	_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7601, "message_lifetime_bound", 8, 8)
	if relay.State() != auth.StateAuthenticating {
		t.Fatalf("initial relay state=%s", relay.State())
	}
	operation, err := client.state.life.beginOperationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	var replayCalls atomic.Int32
	ack, err := relay.state.life.commitFirstAuthenticatedOperationV1(operation, func() error {
		replayCalls.Add(1)
		if relay.state.life.state != auth.StateAuthenticating || relay.state.life.receiveCompleted != 0 ||
			len(relay.state.life.completed) != 0 || relay.state.life.inKeyAttempts != 0 {
			return errors.New("lifecycle mutated before replay commit")
		}
		return nil
	})
	if err != nil || replayCalls.Load() != 1 || ack.OperationID != operation.operationID || ack.CompletedCount != 1 {
		t.Fatalf("first transaction ack=%+v calls=%d err=%v", ack, replayCalls.Load(), err)
	}
	if relay.State() != auth.StateEstablished || relay.state.life.receiveCompleted != 1 ||
		len(relay.state.life.completed) != 1 || relay.state.life.inKeyAttempts != 1 || relay.state.life.inOperationSequence != 1 {
		t.Fatalf("first commit state=%s receive=%d completed=%d attempts=%d sequence=%d", relay.State(), relay.state.life.receiveCompleted, len(relay.state.life.completed), relay.state.life.inKeyAttempts, relay.state.life.inOperationSequence)
	}
	second, err := client.state.life.beginOperationV1(2)
	if err != nil {
		t.Fatal(err)
	}
	if secondAck, err := relay.state.life.commitFirstAuthenticatedOperationV1(second, func() error { return nil }); err != nil || secondAck.CompletedCount != 2 || relay.State() != auth.StateEstablished {
		t.Fatalf("established transaction ack=%+v state=%s err=%v", secondAck, relay.State(), err)
	}
}

func TestFirstRecordCommitReplayCommitOrderingFailureV1(t *testing.T) {
	_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7602, "message_lifetime_bound", 8, 8)
	operation, err := client.state.life.beginOperationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("prepared replay rejected")
	if ack, err := relay.state.life.commitFirstAuthenticatedOperationV1(operation, func() error { return sentinel }); !errors.Is(err, sentinel) || ack != (OperationAckV1{}) {
		t.Fatalf("replay failure ack=%+v err=%v", ack, err)
	}
	if relay.State() != auth.StateAuthenticating || relay.state.life.receiveCompleted != 0 || len(relay.state.life.completed) != 0 || relay.state.life.inKeyAttempts != 0 || relay.state.life.inOperationSequence != 0 {
		t.Fatalf("replay failure mutated receiver state=%s receive=%d completed=%d attempts=%d sequence=%d", relay.State(), relay.state.life.receiveCompleted, len(relay.state.life.completed), relay.state.life.inKeyAttempts, relay.state.life.inOperationSequence)
	}
	if _, err := relay.state.life.commitFirstAuthenticatedOperationV1(operation, func() error { return nil }); err != nil || relay.State() != auth.StateEstablished {
		t.Fatalf("valid retry after replay failure state=%s err=%v", relay.State(), err)
	}
}

func TestFirstRecordCommitRatchetInstallV1(t *testing.T) {
	_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7603, "message_lifetime_bound", 8, 1)
	operation, err := client.state.life.beginOperationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.state.life.commitFirstAuthenticatedOperationV1(operation, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	retry, err := client.state.life.retryOperationV1(operation.operationID)
	if err != nil || retry.recordEpoch != 1 {
		t.Fatalf("ratcheted retry=%+v err=%v", retry, err)
	}
	if ack, err := relay.state.life.commitFirstAuthenticatedOperationV1(retry, func() error { return nil }); err != nil || ack.CompletedCount != 1 {
		t.Fatalf("ratcheted receive ack=%+v err=%v", ack, err)
	}
	if relay.state.life.keyEpoch != 1 || relay.state.life.inKeyAttempts != 1 || relay.state.life.receiveCompleted != 1 || relay.State() != auth.StateEstablished {
		t.Fatalf("ratchet install epoch=%d attempts=%d receive=%d state=%s", relay.state.life.keyEpoch, relay.state.life.inKeyAttempts, relay.state.life.receiveCompleted, relay.State())
	}
}

func TestFirstRecordCommitInvalidMatrixV1(t *testing.T) {
	for name, mutate := range map[string]func(operationTransmissionV1) operationTransmissionV1{
		"wrong-owner":        func(value operationTransmissionV1) operationTransmissionV1 { value.owner = nil; return value },
		"wrong-id":           func(value operationTransmissionV1) operationTransmissionV1 { value.operationID[0] ^= 1; return value },
		"zero-slot":          func(value operationTransmissionV1) operationTransmissionV1 { value.streamSlot = 0; return value },
		"wrong-sequence":     func(value operationTransmissionV1) operationTransmissionV1 { value.operationSequence++; return value },
		"wrong-record-epoch": func(value operationTransmissionV1) operationTransmissionV1 { value.recordEpoch++; return value },
	} {
		t.Run(name, func(t *testing.T) {
			_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7610+int64(len(name)), "message_lifetime_bound", 8, 8)
			operation, err := client.state.life.beginOperationV1(1)
			if err != nil {
				t.Fatal(err)
			}
			var replayCalls atomic.Int32
			if _, err := relay.state.life.commitFirstAuthenticatedOperationV1(mutate(operation), func() error { replayCalls.Add(1); return nil }); err == nil {
				t.Fatal("invalid operation committed")
			}
			if replayCalls.Load() != 0 || relay.State() != auth.StateAuthenticating || relay.state.life.receiveCompleted != 0 || len(relay.state.life.completed) != 0 || relay.state.life.inKeyAttempts != 0 {
				t.Fatalf("invalid operation calls=%d state=%s receive=%d completed=%d attempts=%d", replayCalls.Load(), relay.State(), relay.state.life.receiveCompleted, len(relay.state.life.completed), relay.state.life.inKeyAttempts)
			}
		})
	}
}

type strictFirstRecordStateSnapshotV1 struct {
	state                                     auth.State
	role                                      lifecycleRoleV1
	keyEpoch, inKeyAttempts, receiveCompleted uint64
	inOperationSequence, outSequence          uint64
	outKeyAttempts, sendCompleted             uint64
	inOperationSequenceEnd, outSequenceEnd    bool
	completed, acknowledged, issuedAcks       int
	schedule                                  [32]byte
}

func snapshotStrictFirstRecordStateV1(life *endpointLifecycleV1) strictFirstRecordStateSnapshotV1 {
	var digest [32]byte
	if life.schedule != nil {
		h := sha256.New()
		for _, material := range [][]byte{life.schedule.ClientWriteKey, life.schedule.ServerWriteKey, life.schedule.ClientNonceBase, life.schedule.ServerNonceBase, life.schedule.ExporterSecret} {
			_, _ = h.Write(material)
		}
		var encoded [8]byte
		for i := uint(0); i < 8; i++ {
			encoded[i] = byte(life.schedule.Epoch >> (8 * i))
		}
		_, _ = h.Write(encoded[:])
		copy(digest[:], h.Sum(nil))
	}
	return strictFirstRecordStateSnapshotV1{
		state: life.state, role: life.role, keyEpoch: life.keyEpoch, inKeyAttempts: life.inKeyAttempts,
		receiveCompleted: life.receiveCompleted, inOperationSequence: life.inOperationSequence,
		outSequence: life.outSequence, outKeyAttempts: life.outKeyAttempts, sendCompleted: life.sendCompleted,
		inOperationSequenceEnd: life.inOperationSequenceEnd, outSequenceEnd: life.outSequenceEnd,
		completed: len(life.completed), acknowledged: len(life.acknowledged), issuedAcks: len(life.issuedAcks), schedule: digest,
	}
}

func TestFirstRecordCommitAdditionalInvalidCandidatesV1(t *testing.T) {
	type testCase struct {
		prepare func(*testing.T, *ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, operationTransmissionV1) (operationTransmissionV1, func() error)
	}
	cases := map[string]testCase{
		"wrong-coordinator": {prepare: func(t *testing.T, _ *ClientAuthenticatedEndpointV1, _ *RelayAuthenticatedEndpointV1, operation operationTransmissionV1) (operationTransmissionV1, func() error) {
			_, _, otherRelay := newAuthenticatingFirstRecordPairV1(t, 7641, "message_lifetime_bound", 8, 8)
			operation.coordinator = otherRelay.state.life.coordinator
			return operation, func() error { t.Fatal("replay callback called"); return nil }
		}},
		"wrong-role": {prepare: func(t *testing.T, _ *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, operation operationTransmissionV1) (operationTransmissionV1, func() error) {
			relay.state.life.role = lifecycleRoleClientV1
			return operation, func() error { t.Fatal("replay callback called"); return nil }
		}},
		"forged-issued-attempt": {prepare: func(t *testing.T, _ *ClientAuthenticatedEndpointV1, _ *RelayAuthenticatedEndpointV1, operation operationTransmissionV1) (operationTransmissionV1, func() error) {
			operation.attempt++
			return operation, func() error { t.Fatal("replay callback called"); return nil }
		}},
		"nil-closure": {prepare: func(_ *testing.T, _ *ClientAuthenticatedEndpointV1, _ *RelayAuthenticatedEndpointV1, operation operationTransmissionV1) (operationTransmissionV1, func() error) {
			return operation, nil
		}},
		"session-limit": {prepare: func(t *testing.T, _ *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, operation operationTransmissionV1) (operationTransmissionV1, func() error) {
			relay.state.life.receiveCompleted = relay.state.life.config.MaxSessionMessages
			return operation, func() error { t.Fatal("replay callback called"); return nil }
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7640+int64(len(name)), "message_lifetime_bound", 8, 8)
			operation, err := client.state.life.beginOperationV1(1)
			if err != nil {
				t.Fatal(err)
			}
			operation, callback := tc.prepare(t, client, relay, operation)
			before := snapshotStrictFirstRecordStateV1(relay.state.life)
			if ack, err := relay.state.life.commitFirstAuthenticatedOperationV1(operation, callback); err == nil || ack != (OperationAckV1{}) {
				t.Fatalf("invalid candidate ack=%+v err=%v", ack, err)
			}
			if after := snapshotStrictFirstRecordStateV1(relay.state.life); after != before {
				t.Fatalf("invalid candidate mutated lifecycle before=%+v after=%+v", before, after)
			}
		})
	}

	t.Run("terminal-closed-pair", func(t *testing.T) {
		_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7650, "message_lifetime_bound", 8, 8)
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		life := relay.state.life
		client.Close()
		before := snapshotStrictFirstRecordStateV1(life)
		var calls atomic.Int32
		if ack, err := life.commitFirstAuthenticatedOperationV1(operation, func() error { calls.Add(1); return nil }); err == nil || ack != (OperationAckV1{}) {
			t.Fatalf("closed pair ack=%+v err=%v", ack, err)
		}
		if calls.Load() != 0 || snapshotStrictFirstRecordStateV1(life) != before {
			t.Fatalf("closed pair callback=%d or lifecycle mutation", calls.Load())
		}
	})
}

func TestFirstRecordCommitRatchetScheduleDestructionV1(t *testing.T) {
	t.Run("replay-failure-destroys-pending-once", func(t *testing.T) {
		_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7660, "message_lifetime_bound", 8, 1)
		first, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitFirstAuthenticatedOperationV1(first, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		retry, err := client.state.life.retryOperationV1(first.operationID)
		if err != nil || retry.recordEpoch != 1 {
			t.Fatalf("retry=%+v err=%v", retry, err)
		}
		before := snapshotStrictFirstRecordStateV1(relay.state.life)
		var destroys atomic.Int32
		var sawMaterial atomic.Bool
		relay.state.life.destroySchedule = func(schedule *security.KeySchedule) {
			destroys.Add(1)
			sawMaterial.Store(scheduleMaterialPresentV1(schedule))
			schedule.Destroy()
			if scheduleMaterialPresentV1(schedule) {
				t.Error("pending schedule retained material after destroy")
			}
		}
		sentinel := errors.New("replay rejected after ratchet preparation")
		if ack, err := relay.state.life.commitFirstAuthenticatedOperationV1(retry, func() error { return sentinel }); !errors.Is(err, sentinel) || ack != (OperationAckV1{}) {
			t.Fatalf("ratchet replay failure ack=%+v err=%v", ack, err)
		}
		if destroys.Load() != 1 || !sawMaterial.Load() || snapshotStrictFirstRecordStateV1(relay.state.life) != before {
			t.Fatalf("pending destroy count=%d material=%v state changed=%v", destroys.Load(), sawMaterial.Load(), snapshotStrictFirstRecordStateV1(relay.state.life) != before)
		}
	})

	t.Run("success-destroys-old-once", func(t *testing.T) {
		_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7661, "message_lifetime_bound", 8, 1)
		first, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitFirstAuthenticatedOperationV1(first, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		retry, err := client.state.life.retryOperationV1(first.operationID)
		if err != nil {
			t.Fatal(err)
		}
		oldExporterAlias := relay.state.life.schedule.ExporterSecret
		var destroys atomic.Int32
		relay.state.life.destroySchedule = func(schedule *security.KeySchedule) {
			destroys.Add(1)
			schedule.Destroy()
		}
		if _, err := relay.state.life.commitFirstAuthenticatedOperationV1(retry, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		if destroys.Load() != 1 || !bytes.Equal(oldExporterAlias, make([]byte, len(oldExporterAlias))) || relay.state.life.keyEpoch != 1 || !scheduleMaterialPresentV1(relay.state.life.schedule) {
			t.Fatalf("old destroy=%d oldWiped=%v epoch=%d newMaterial=%v", destroys.Load(), bytes.Equal(oldExporterAlias, make([]byte, len(oldExporterAlias))), relay.state.life.keyEpoch, scheduleMaterialPresentV1(relay.state.life.schedule))
		}
	})
}

func TestFirstRecordCommitDuplicateCallbackFailureNoAdvanceV1(t *testing.T) {
	_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7670, "message_lifetime_bound", 8, 8)
	operation, err := client.state.life.beginOperationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.state.life.commitFirstAuthenticatedOperationV1(operation, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	before := snapshotStrictFirstRecordStateV1(relay.state.life)
	var calls atomic.Int32
	sentinel := errors.New("duplicate replay rejected")
	if ack, err := relay.state.life.commitFirstAuthenticatedOperationV1(operation, func() error { calls.Add(1); return sentinel }); !errors.Is(err, sentinel) || ack != (OperationAckV1{}) {
		t.Fatalf("duplicate failure ack=%+v err=%v", ack, err)
	}
	if calls.Load() != 1 || snapshotStrictFirstRecordStateV1(relay.state.life) != before {
		t.Fatalf("duplicate failure calls=%d state changed=%v", calls.Load(), snapshotStrictFirstRecordStateV1(relay.state.life) != before)
	}
}

func TestFirstRecordCommitProfileAdvanceLinearizationV1(t *testing.T) {
	owner, client, relay := newAuthenticatingFirstRecordPairV1(t, 7680, "profile_lifetime_bound", 8, 8)
	operation, err := client.state.life.beginOperationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	observerEntered := make(chan struct{})
	releaseObserver := make(chan struct{})
	relay.state.life.beforeProfileCommitObserver = func() {
		close(observerEntered)
		<-releaseObserver
	}
	before := snapshotStrictFirstRecordStateV1(relay.state.life)
	result := make(chan error, 1)
	var replayCalls atomic.Int32
	go func() {
		_, err := relay.state.life.commitFirstAuthenticatedOperationV1(operation, func() error { replayCalls.Add(1); return nil })
		result <- err
	}()
	select {
	case <-observerEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("strict transaction did not reach profile observer")
	}
	owner.profileMu.Lock()
	owner.profileGeneration++
	owner.profileMu.Unlock()
	close(releaseObserver)
	select {
	case err := <-result:
		if !errors.Is(err, ErrProfileRotationRequired) {
			t.Fatalf("profile advance err=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("strict transaction did not finish")
	}
	relay.state.life.beforeProfileCommitObserver = nil
	if replayCalls.Load() != 0 || snapshotStrictFirstRecordStateV1(relay.state.life) != before {
		t.Fatalf("profile advance replay calls=%d state changed=%v", replayCalls.Load(), snapshotStrictFirstRecordStateV1(relay.state.life) != before)
	}
}

func TestFirstRecordCommitProfileGenerationAndRatchetPrepareFailureV1(t *testing.T) {
	t.Run("stale-profile", func(t *testing.T) {
		owner, client, relay := newAuthenticatingFirstRecordPairV1(t, 7620, "profile_lifetime_bound", 8, 8)
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		owner.profileMu.Lock()
		owner.profileGeneration++
		owner.profileMu.Unlock()
		var calls atomic.Int32
		if _, err := relay.state.life.commitFirstAuthenticatedOperationV1(operation, func() error { calls.Add(1); return nil }); !errors.Is(err, ErrProfileRotationRequired) {
			t.Fatalf("stale profile err=%v", err)
		}
		if calls.Load() != 0 || relay.State() != auth.StateAuthenticating || relay.state.life.receiveCompleted != 0 {
			t.Fatalf("stale profile calls=%d state=%s receive=%d", calls.Load(), relay.State(), relay.state.life.receiveCompleted)
		}
	})
	t.Run("ratchet-prepare", func(t *testing.T) {
		_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7621, "message_lifetime_bound", 8, 1)
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		retry, err := client.state.life.retryOperationV1(operation.operationID)
		if err != nil || retry.recordEpoch != 1 {
			t.Fatalf("retry=%+v err=%v", retry, err)
		}
		clear(relay.state.life.schedule.ExporterSecret)
		var calls atomic.Int32
		if _, err := relay.state.life.commitFirstAuthenticatedOperationV1(retry, func() error { calls.Add(1); return nil }); !errors.Is(err, ErrRekeyFailed) {
			t.Fatalf("ratchet prepare err=%v", err)
		}
		if calls.Load() != 0 || relay.State() != auth.StateAuthenticating || relay.state.life.keyEpoch != 0 || relay.state.life.inKeyAttempts != 0 || relay.state.life.receiveCompleted != 0 {
			t.Fatalf("ratchet failure calls=%d state=%s epoch=%d attempts=%d receive=%d", calls.Load(), relay.State(), relay.state.life.keyEpoch, relay.state.life.inKeyAttempts, relay.state.life.receiveCompleted)
		}
	})
}

func TestFirstRecordCommitConcurrentCopiesEstablishOnceV1(t *testing.T) {
	_, client, relay := newAuthenticatingFirstRecordPairV1(t, 7630, "message_lifetime_bound", 8, 8)
	operation, err := client.state.life.beginOperationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	var replayDecision atomic.Bool
	var successes atomic.Int32
	var replaySuccesses atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(copyTransmission operationTransmissionV1) {
			defer wg.Done()
			<-start
			_, err := relay.state.life.commitFirstAuthenticatedOperationV1(copyTransmission, func() error {
				if replayDecision.CompareAndSwap(false, true) {
					replaySuccesses.Add(1)
					return nil
				}
				return security.ErrReplayDuplicate
			})
			if err == nil {
				successes.Add(1)
			}
		}(operation)
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent first-record transaction timed out")
	}
	if successes.Load() != 1 || replaySuccesses.Load() != 1 || relay.State() != auth.StateEstablished || relay.state.life.receiveCompleted != 1 || len(relay.state.life.completed) != 1 || relay.state.life.inKeyAttempts != 1 {
		t.Fatalf("concurrent success=%d replay=%d state=%s receive=%d completed=%d attempts=%d", successes.Load(), replaySuccesses.Load(), relay.State(), relay.state.life.receiveCompleted, len(relay.state.life.completed), relay.state.life.inKeyAttempts)
	}
}

func TestFirstRecordCommitCandidateCallPathV1(t *testing.T) {
	_, filename, _, _ := gort.Caller(0)
	filename = strings.Replace(filename, "lifecycle_test.go", "lifecycle.go", 1)
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "func (life *endpointLifecycleV1) commitFirstAuthenticatedOperationV1")
	if start < 0 {
		t.Fatal("strict transaction missing")
	}
	end := strings.Index(source[start+1:], "\nfunc ")
	if end < 0 {
		t.Fatal("strict transaction boundary missing")
	}
	body := source[start : start+1+end]
	for _, forbidden := range []string{"postAuthenticationCommitV1", "validLockedV1", "validOperationOwnerLockedV1", "prepareReceiveEpochLockedV1", "commitReceiveEpochLockedV1", "commitReplay", "CommitAuthenticated", "ReplayMetadataV1", "NewReplayWindowV1"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("strict transaction calls forbidden compatibility replay/establishment path %s", forbidden)
		}
	}
	replayIndex := strings.Index(body, "replayCommit()")
	receiveIndex := strings.Index(body, "life.receiveCompleted++")
	establishIndex := strings.Index(body, "life.state = auth.StateEstablished")
	if replayIndex < 0 || receiveIndex < replayIndex || establishIndex < receiveIndex {
		t.Fatalf("transaction ordering replay=%d receive=%d establish=%d", replayIndex, receiveIndex, establishIndex)
	}
	applyIndex := strings.Index(body, "oldSchedule := life.applyStrictReceiveEpochLockedV1")
	if applyIndex < replayIndex || strings.Contains(body[applyIndex:establishIndex], "return ") || strings.Contains(body[applyIndex:establishIndex], ", err :=") {
		t.Fatal("fallible operation remains after successful replay commit before establishment publication")
	}
}

func newStrictAckTransactionV1(t *testing.T, seed int64, rotation string, maxSession, maxKey int) (*HandshakeRuntime, *ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, operationTransmissionV1, acknowledgementTransmissionV1) {
	t.Helper()
	owner, client, relay := newAuthenticatingFirstRecordPairV1(t, seed, rotation, maxSession, maxKey)
	operation, err := client.state.life.beginOperationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.state.life.commitFirstAuthenticatedOperationV1(operation, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	ack, err := relay.state.life.beginOperationAckV1(operation.operationID)
	if err != nil {
		t.Fatal(err)
	}
	return owner, client, relay, operation, ack
}

type strictAckStateSnapshotV1 struct {
	state                                                    auth.State
	keyEpoch, inKeyAttempts, sendCompleted, receiveCompleted uint64
	outstanding, acknowledged, completed                     int
	schedule                                                 [32]byte
}

func snapshotStrictAckStateV1(life *endpointLifecycleV1) strictAckStateSnapshotV1 {
	base := snapshotStrictFirstRecordStateV1(life)
	return strictAckStateSnapshotV1{
		state: life.state, keyEpoch: life.keyEpoch, inKeyAttempts: life.inKeyAttempts,
		sendCompleted: life.sendCompleted, receiveCompleted: life.receiveCompleted,
		outstanding: len(life.outstanding), acknowledged: len(life.acknowledged), completed: len(life.completed), schedule: base.schedule,
	}
}

func TestAuthenticatedOperationAckStrictReplayCommitOrderingV1(t *testing.T) {
	_, client, relay, _, ack := newStrictAckTransactionV1(t, 7690, "message_lifetime_bound", 8, 8)
	before := snapshotStrictAckStateV1(client.state.life)
	var calls atomic.Int32
	err := client.state.life.commitStrictAuthenticatedOperationAckV1(relay.state.life, controlDirectionRelayV1, ack.recordEpoch, ack.recordSequence, ack.ack, func() error {
		calls.Add(1)
		if snapshotStrictAckStateV1(client.state.life) != before {
			return errors.New("Ack lifecycle mutated before replay commit")
		}
		return nil
	})
	if err != nil || calls.Load() != 1 {
		t.Fatalf("strict Ack commit calls=%d err=%v", calls.Load(), err)
	}
	after := snapshotStrictAckStateV1(client.state.life)
	if after.outstanding != 0 || after.acknowledged != 1 || after.sendCompleted != before.sendCompleted+1 || after.inKeyAttempts != before.inKeyAttempts+1 {
		t.Fatalf("strict Ack state before=%+v after=%+v", before, after)
	}
}

func TestAuthenticatedOperationAckStrictInvalidMatrixV1(t *testing.T) {
	type mutation func(*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, acknowledgementTransmissionV1) (*endpointLifecycleV1, uint16, uint64, uint64, OperationAckV1)
	cases := map[string]mutation{
		"wrong-owner": func(client *ClientAuthenticatedEndpointV1, _ *RelayAuthenticatedEndpointV1, ack acknowledgementTransmissionV1) (*endpointLifecycleV1, uint16, uint64, uint64, OperationAckV1) {
			return client.state.life, controlDirectionClientV1, ack.recordEpoch, ack.recordSequence, ack.ack
		},
		"wrong-direction": func(_ *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, ack acknowledgementTransmissionV1) (*endpointLifecycleV1, uint16, uint64, uint64, OperationAckV1) {
			return relay.state.life, controlDirectionClientV1, ack.recordEpoch, ack.recordSequence, ack.ack
		},
		"unknown-operation": func(_ *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, ack acknowledgementTransmissionV1) (*endpointLifecycleV1, uint16, uint64, uint64, OperationAckV1) {
			ack.ack.OperationID[0] ^= 1
			return relay.state.life, controlDirectionRelayV1, ack.recordEpoch, ack.recordSequence, ack.ack
		},
		"count-mismatch": func(_ *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, ack acknowledgementTransmissionV1) (*endpointLifecycleV1, uint16, uint64, uint64, OperationAckV1) {
			ack.ack.CompletedCount++
			return relay.state.life, controlDirectionRelayV1, ack.recordEpoch, ack.recordSequence, ack.ack
		},
		"invalid-epoch": func(_ *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, ack acknowledgementTransmissionV1) (*endpointLifecycleV1, uint16, uint64, uint64, OperationAckV1) {
			return relay.state.life, controlDirectionRelayV1, ack.recordEpoch + 2, ack.recordSequence, ack.ack
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, client, relay, _, ack := newStrictAckTransactionV1(t, 7700+int64(len(name)), "message_lifetime_bound", 8, 8)
			sender, direction, epoch, sequence, decoded := mutate(client, relay, ack)
			before := snapshotStrictAckStateV1(client.state.life)
			var calls atomic.Int32
			err := client.state.life.commitStrictAuthenticatedOperationAckV1(sender, direction, epoch, sequence, decoded, func() error { calls.Add(1); return nil })
			if !errors.Is(err, ErrOperationAckInvalid) || calls.Load() != 0 || snapshotStrictAckStateV1(client.state.life) != before {
				t.Fatalf("invalid Ack err=%v calls=%d changed=%v", err, calls.Load(), snapshotStrictAckStateV1(client.state.life) != before)
			}
		})
	}

	t.Run("already-completed", func(t *testing.T) {
		_, client, relay, _, ack := newStrictAckTransactionV1(t, 7710, "message_lifetime_bound", 8, 8)
		invoke := func() error {
			return client.state.life.commitStrictAuthenticatedOperationAckV1(relay.state.life, controlDirectionRelayV1, ack.recordEpoch, ack.recordSequence, ack.ack, func() error { return nil })
		}
		if err := invoke(); err != nil {
			t.Fatal(err)
		}
		before := snapshotStrictAckStateV1(client.state.life)
		var calls atomic.Int32
		if err := client.state.life.commitStrictAuthenticatedOperationAckV1(relay.state.life, controlDirectionRelayV1, ack.recordEpoch, ack.recordSequence, ack.ack, func() error { calls.Add(1); return nil }); !errors.Is(err, ErrOperationAckInvalid) || calls.Load() != 0 || snapshotStrictAckStateV1(client.state.life) != before {
			t.Fatalf("completed Ack err=%v calls=%d", err, calls.Load())
		}
	})

	t.Run("terminal", func(t *testing.T) {
		_, client, relay, _, ack := newStrictAckTransactionV1(t, 7711, "message_lifetime_bound", 8, 8)
		life, sender := client.state.life, relay.state.life
		client.Close()
		before := snapshotStrictAckStateV1(life)
		var calls atomic.Int32
		if err := life.commitStrictAuthenticatedOperationAckV1(sender, controlDirectionRelayV1, ack.recordEpoch, ack.recordSequence, ack.ack, func() error { calls.Add(1); return nil }); !errors.Is(err, ErrOperationAckInvalid) || calls.Load() != 0 || snapshotStrictAckStateV1(life) != before {
			t.Fatalf("terminal Ack err=%v calls=%d", err, calls.Load())
		}
	})

	t.Run("stale-profile", func(t *testing.T) {
		owner, client, relay, _, ack := newStrictAckTransactionV1(t, 7712, "profile_lifetime_bound", 8, 8)
		owner.profileMu.Lock()
		owner.profileGeneration++
		owner.profileMu.Unlock()
		before := snapshotStrictAckStateV1(client.state.life)
		var calls atomic.Int32
		err := client.state.life.commitStrictAuthenticatedOperationAckV1(relay.state.life, controlDirectionRelayV1, ack.recordEpoch, ack.recordSequence, ack.ack, func() error { calls.Add(1); return nil })
		if !errors.Is(err, ErrProfileRotationRequired) || calls.Load() != 0 || snapshotStrictAckStateV1(client.state.life) != before {
			t.Fatalf("stale Ack err=%v calls=%d", err, calls.Load())
		}
	})

	t.Run("key-attempt-limit", func(t *testing.T) {
		_, client, relay, _, ack := newStrictAckTransactionV1(t, 7713, "session_only", 8, 1)
		client.state.life.inKeyAttempts = client.state.life.config.MaxKeyLifetimeMessages
		before := snapshotStrictAckStateV1(client.state.life)
		var calls atomic.Int32
		err := client.state.life.commitStrictAuthenticatedOperationAckV1(relay.state.life, controlDirectionRelayV1, ack.recordEpoch, ack.recordSequence, ack.ack, func() error { calls.Add(1); return nil })
		if !errors.Is(err, ErrOperationAckInvalid) || calls.Load() != 0 || snapshotStrictAckStateV1(client.state.life) != before {
			t.Fatalf("key limit Ack err=%v calls=%d", err, calls.Load())
		}
	})

	t.Run("ratchet-prepare-failure", func(t *testing.T) {
		_, client, relay, _, first := newStrictAckTransactionV1(t, 7714, "message_lifetime_bound", 8, 1)
		retry, err := relay.state.life.retryOperationAckV1(first.ack.OperationID)
		if err != nil || retry.recordEpoch != 1 {
			t.Fatalf("Ack retry=%+v err=%v", retry, err)
		}
		clear(client.state.life.schedule.ExporterSecret)
		before := snapshotStrictAckStateV1(client.state.life)
		var calls atomic.Int32
		err = client.state.life.commitStrictAuthenticatedOperationAckV1(relay.state.life, controlDirectionRelayV1, retry.recordEpoch, retry.recordSequence, retry.ack, func() error { calls.Add(1); return nil })
		if !errors.Is(err, ErrOperationAckInvalid) || calls.Load() != 0 || snapshotStrictAckStateV1(client.state.life) != before {
			t.Fatalf("ratchet prepare Ack err=%v calls=%d changed=%v", err, calls.Load(), snapshotStrictAckStateV1(client.state.life) != before)
		}
	})
}

func TestAuthenticatedOperationAckStrictRatchetAndReplayFailureV1(t *testing.T) {
	_, client, relay, _, first := newStrictAckTransactionV1(t, 7720, "message_lifetime_bound", 8, 1)
	retry, err := relay.state.life.retryOperationAckV1(first.ack.OperationID)
	if err != nil || retry.recordEpoch != 1 {
		t.Fatalf("Ack retry=%+v err=%v", retry, err)
	}
	before := snapshotStrictAckStateV1(client.state.life)
	var destroys atomic.Int32
	client.state.life.destroySchedule = func(schedule *security.KeySchedule) {
		destroys.Add(1)
		schedule.Destroy()
	}
	sentinel := errors.New("Ack replay commit failed")
	err = client.state.life.commitStrictAuthenticatedOperationAckV1(relay.state.life, controlDirectionRelayV1, retry.recordEpoch, retry.recordSequence, retry.ack, func() error { return sentinel })
	if !errors.Is(err, sentinel) || destroys.Load() != 1 || snapshotStrictAckStateV1(client.state.life) != before {
		t.Fatalf("Ack replay failure err=%v destroys=%d changed=%v", err, destroys.Load(), snapshotStrictAckStateV1(client.state.life) != before)
	}
	oldExporter := client.state.life.schedule.ExporterSecret
	if err := client.state.life.commitStrictAuthenticatedOperationAckV1(relay.state.life, controlDirectionRelayV1, retry.recordEpoch, retry.recordSequence, retry.ack, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if destroys.Load() != 2 || !bytes.Equal(oldExporter, make([]byte, len(oldExporter))) || client.state.life.keyEpoch != 1 || client.state.life.sendCompleted != 1 {
		t.Fatalf("Ack ratchet destroys=%d wiped=%v epoch=%d sends=%d", destroys.Load(), bytes.Equal(oldExporter, make([]byte, len(oldExporter))), client.state.life.keyEpoch, client.state.life.sendCompleted)
	}
}

func TestAuthenticatedOperationAckStrictConcurrentConvergesOnceV1(t *testing.T) {
	_, client, relay, _, ack := newStrictAckTransactionV1(t, 7730, "message_lifetime_bound", 8, 8)
	var calls, successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := client.state.life.commitStrictAuthenticatedOperationAckV1(relay.state.life, controlDirectionRelayV1, ack.recordEpoch, ack.recordSequence, ack.ack, func() error { calls.Add(1); return nil })
			if err == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 || successes.Load() != 1 || client.state.life.sendCompleted != 1 || len(client.state.life.outstanding) != 0 || len(client.state.life.acknowledged) != 1 {
		t.Fatalf("concurrent Ack calls=%d successes=%d sends=%d outstanding=%d acknowledged=%d", calls.Load(), successes.Load(), client.state.life.sendCompleted, len(client.state.life.outstanding), len(client.state.life.acknowledged))
	}
}

func TestAuthenticatedOperationAckStrictCallPathV1(t *testing.T) {
	_, filename, _, _ := gort.Caller(0)
	raw, err := os.ReadFile(strings.Replace(filename, "lifecycle_test.go", "lifecycle.go", 1))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "func (life *endpointLifecycleV1) commitStrictAuthenticatedOperationAckV1")
	if start < 0 {
		t.Fatal("strict Ack transaction missing")
	}
	end := strings.Index(source[start+1:], "\nfunc ")
	if end < 0 {
		t.Fatal("strict Ack transaction boundary missing")
	}
	body := source[start : start+1+end]
	for _, forbidden := range []string{"prepareReceiveEpochLockedV1", "commitReceiveEpochLockedV1", "commitReplay", "CommitAuthenticated", "ReplayMetadataV1"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("strict Ack transaction calls forbidden replay path %s", forbidden)
		}
	}
	replayIndex := strings.Index(body, "replayCommit()")
	applyIndex := strings.Index(body, "oldSchedule := life.applyStrictReceiveEpochLockedV1")
	if replayIndex < 0 || applyIndex < replayIndex || strings.Contains(body[applyIndex:], ", err :=") || strings.Contains(body[applyIndex:], "return Err") {
		t.Fatal("strict Ack transaction retains a fallible operation after replay commit")
	}
}

func newLifecycleFixtureV1(t *testing.T, seed int64, rotation string, maxSession, maxKey int) strictSupportFixtureV1 {
	return newLifecycleFixtureConfiguredV1(t, seed, "", rotation, security.NonceModeCounterXORBaseV1, maxSession, maxKey)
}

func newLifecycleFixtureConfiguredV1(t *testing.T, seed int64, profileID, rotation, nonceMode string, maxSession, maxKey int) strictSupportFixtureV1 {
	t.Helper()
	p, err := compiler.Generate(6201)
	if err != nil {
		t.Fatal(err)
	}
	if profileID == "" {
		profileID = fmt.Sprintf("kp_lifecycle_%d", seed)
	}
	p.ID = profileID
	p.Seed = seed
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:2]...)
	p.Security.TranscriptMode = security.TranscriptCanonicalV1
	p.Security.NonceMode = nonceMode
	p.Security.ReplayPolicy = security.ReplayPolicyOrderedOnlyV1
	p.Security.DowngradePolicy = "strict_suite_and_capabilities"
	p.Security.CapabilityNegotiationPolicy = "strict_required"
	p.Security.ProfileCompatibilityPolicy = "strict_schema"
	p.Security.KeyRotationPolicy = rotation
	p.Security.ConfigValidationPolicy = "strict_required"
	p.Security.SecureEnvelopeMode = "metadata_authenticated"
	p.Security.MaxSessionMessages = maxSession
	p.Security.MaxKeyLifetimeMessages = maxKey
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	client, err := auth.NewPeerParameters("runtime-client", p, policy, policy, known, floor)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := auth.NewPeerParameters("runtime-server", p, policy, policy, known, floor)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := runtimeDependenciesFixture(t)
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	input := auth.FirstContactInput{
		Client: client, Server: relay, SelectedPolicy: policy, SelectedCapabilities: append([]string(nil), floor...),
		ClientDependencies: dependencies.client, ServerDependencies: dependencies.server, Replay: replay,
	}
	snapshot, view, err := auth.SnapshotFirstContactInputV1(input)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, err := security.EffectivePolicyHashV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	clientEntry := clientAuthorizationEntryV1(snapshot.Client.ProfileHash, policyHash, policy, view.ClientModeBinding)
	relayEntry := relayAuthorizationEntryV1(snapshot.Server.ProfileHash, policyHash, policy, view.ServerModeBinding)
	clientRegistry := strictSupportFixtureV1{}.clientRegistry
	clientRegistry.entries = append(clientRegistry.entries, profileAuthorizationEntryV1{
		profileHash: clientEntry.ProfileHash, effectivePolicyHash: clientEntry.EffectivePolicyHash,
		replayWindowSize: clientEntry.ReplayWindowSize, maxConcurrentStreams: clientEntry.MaxConcurrentStreams,
		maxFrameBytes: clientEntry.MaxFrameBytes, maxEnvelopeBytes: clientEntry.MaxEnvelopeBytes,
		framingPolicyHash: clientEntry.FramingPolicyHash, stateMachinePolicyHash: clientEntry.StateMachinePolicyHash,
		schedulerPolicyHash: clientEntry.SchedulerPolicyHash, paddingPolicyHash: clientEntry.PaddingPolicyHash,
		streamPolicyHash: clientEntry.StreamPolicyHash, proxyPolicyHash: clientEntry.ProxyPolicyHash,
		carrierContextPolicyHash: clientEntry.CarrierContextPolicyHash,
	})
	relayRegistry := strictSupportFixtureV1{}.relayRegistry
	relayRegistry.entries = append(relayRegistry.entries, profileAuthorizationEntryV1{
		profileHash: relayEntry.ProfileHash, effectivePolicyHash: relayEntry.EffectivePolicyHash,
		replayWindowSize: relayEntry.ReplayWindowSize, maxConcurrentStreams: relayEntry.MaxConcurrentStreams,
		maxFrameBytes: relayEntry.MaxFrameBytes, maxEnvelopeBytes: relayEntry.MaxEnvelopeBytes,
		framingPolicyHash: relayEntry.FramingPolicyHash, stateMachinePolicyHash: relayEntry.StateMachinePolicyHash,
		schedulerPolicyHash: relayEntry.SchedulerPolicyHash, paddingPolicyHash: relayEntry.PaddingPolicyHash,
		streamPolicyHash: relayEntry.StreamPolicyHash, proxyPolicyHash: relayEntry.ProxyPolicyHash,
		carrierContextPolicyHash: relayEntry.CarrierContextPolicyHash,
	})
	return strictSupportFixtureV1{
		input: input, snapshot: snapshot, view: view, dependencies: dependencies,
		clientEntry: clientEntry, relayEntry: relayEntry,
		clientRegistry: clientRegistry, relayRegistry: relayRegistry,
	}
}

func lifecycleRuntimeV1(t *testing.T, primary strictSupportFixtureV1, extras ...strictSupportFixtureV1) *HandshakeRuntime {
	t.Helper()
	clientRegistry := primary.clientRegistry.clone()
	relayRegistry := primary.relayRegistry.clone()
	for _, fixture := range extras {
		clientRegistry.entries = append(clientRegistry.entries, fixture.clientRegistry.entries...)
		relayRegistry.entries = append(relayRegistry.entries, fixture.relayRegistry.entries...)
	}
	sort.Slice(clientRegistry.entries, func(i, j int) bool {
		return bytes.Compare(clientRegistry.entries[i].profileHash[:], clientRegistry.entries[j].profileHash[:]) < 0
	})
	sort.Slice(relayRegistry.entries, func(i, j int) bool {
		return bytes.Compare(relayRegistry.entries[i].profileHash[:], relayRegistry.entries[j].profileHash[:]) < 0
	})
	if !clientRegistry.valid() || !relayRegistry.valid() {
		t.Fatal("combined lifecycle owner registries are invalid")
	}
	runtime, err := NewStrictHandshakeRuntimeV1(
		primary.dependencies.client, primary.dependencies.server,
		clientRegistry, relayRegistry,
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime.clientSupport.rotationPolicies = []string{"message_lifetime_bound", "profile_lifetime_bound", "session_only"}
	runtime.relaySupport.rotationPolicies = append([]string(nil), runtime.clientSupport.rotationPolicies...)
	runtime.clientSupport.nonceModes = sortedStringsV1([]string{
		security.NonceModeCounterXORBaseV1,
		security.NonceModeCounterAppendBaseV1,
		security.NonceModeDirectionalCounterV1,
		security.NonceModeStreamPartitionedCounterV1,
	})
	runtime.relaySupport.nonceModes = append([]string(nil), runtime.clientSupport.nonceModes...)
	return runtime
}

func copyHandshakeRuntimeStateWithoutLocksV1(source *HandshakeRuntime) *HandshakeRuntime {
	if source == nil {
		return nil
	}
	source.epochMu.Lock()
	epoch, entropy, entropyFailed := source.epoch, source.strictEntropy, source.strictEntropyFailed
	source.epochMu.Unlock()
	source.pairMu.Lock()
	pending := source.pendingPairMaterials
	source.pairMu.Unlock()
	source.profileMu.Lock()
	generation, seen, id, hash, overflow := source.profileGeneration, source.profileSeen, source.profileID, source.profileHash, source.profileOverflow
	source.profileMu.Unlock()
	return &HandshakeRuntime{
		self: source.self, instanceTag: source.instanceTag, replay: source.replay, epoch: epoch,
		clientDependencies: source.clientDependencies, serverDependencies: source.serverDependencies,
		strict: source.strict, strictEntropy: entropy, strictEntropyFailed: entropyFailed,
		clientSupport: source.clientSupport, relaySupport: source.relaySupport,
		clientRegistry: source.clientRegistry, relayRegistry: source.relayRegistry,
		pendingPairMaterials: pending, pairDeriveScheduleV1: source.pairDeriveScheduleV1,
		pairConstructV1:   source.pairConstructV1,
		profileGeneration: generation, profileSeen: seen, profileID: id, profileHash: hash, profileOverflow: overflow,
	}
}

type failingRestartEntropyReaderV1 struct{}

func (failingRestartEntropyReaderV1) Read([]byte) (int, error) {
	return 0, errors.New("injected restart entropy failure")
}

type observingRestartEntropyReaderV1 struct {
	client         *ClientAuthenticatedEndpointV1
	relay          *RelayAuthenticatedEndpointV1
	clientDestroy  *atomic.Int32
	relayDestroy   *atomic.Int32
	data           []byte
	err            error
	reads          atomic.Int32
	observedClosed atomic.Bool
}

func (reader *observingRestartEntropyReaderV1) Read(destination []byte) (int, error) {
	reader.reads.Add(1)
	if reader.client.State() == auth.StateClosed && reader.relay.State() == auth.StateClosed &&
		reader.clientDestroy.Load() == 1 && reader.relayDestroy.Load() == 1 {
		reader.observedClosed.Store(true)
	}
	if reader.err != nil {
		return 0, reader.err
	}
	return copy(destination, reader.data), nil
}

type blockingRestartEntropyReaderV1 struct {
	data    []byte
	entered chan struct{}
	release chan struct{}
	reads   atomic.Int32
	once    sync.Once
}

func (reader *blockingRestartEntropyReaderV1) Read(destination []byte) (int, error) {
	reader.reads.Add(1)
	reader.once.Do(func() { close(reader.entered) })
	<-reader.release
	return copy(destination, reader.data), nil
}

type mutatingRestartEntropyReaderV1 struct {
	data   []byte
	mutate func()
	reads  atomic.Int32
}

func (reader *mutatingRestartEntropyReaderV1) Read(destination []byte) (int, error) {
	reader.reads.Add(1)
	reader.mutate()
	return copy(destination, reader.data), nil
}

func restartEntropyBytesV1(seed int64) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("kurdistan/restart-test/v1/%d", seed)))
	return append([]byte(nil), sum[:]...)
}

func handshakeReplaySeenLengthV1(t *testing.T, replay *auth.HandshakeReplayCache) int {
	t.Helper()
	if replay == nil {
		t.Fatal("nil handshake replay cache")
	}
	seen := reflect.ValueOf(replay).Elem().FieldByName("seen")
	if !seen.IsValid() || seen.Kind() != reflect.Map {
		t.Fatal("handshake replay cache seen map unavailable")
	}
	return seen.Len()
}

func (runtime *HandshakeRuntime) pendingPairMaterialCountV1() int {
	if runtime == nil {
		return 0
	}
	runtime.pairMu.Lock()
	defer runtime.pairMu.Unlock()
	return len(runtime.pendingPairMaterials)
}

func lifecyclePairInputV1(t *testing.T, fixture strictSupportFixtureV1) PairInputV1 {
	t.Helper()
	probe := lifecycleRuntimeV1(t, fixture)
	result, context, err := probe.strictFirstContactWithContextV1(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	wipeRuntimeBytesV1(result.ChannelSecret)
	clientValue, err := strictConfigFromContextV1(context, true)
	if err != nil {
		t.Fatal(err)
	}
	relayValue, err := strictConfigFromContextV1(context, false)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := NewClientStrictSessionConfigV1(clientValue)
	if err != nil {
		t.Fatal(err)
	}
	relayConfig, err := NewRelayStrictSessionConfigV1(relayValue)
	if err != nil {
		t.Fatal(err)
	}
	return PairInputV1{
		FirstContactInput: fixture.input,
		ClientConfig:      clientConfig,
		RelayConfig:       relayConfig,
		ClientControls:    ClientLocalRuntimeControlsV1{RuntimeID: "client-runtime", EventCapacity: 128, QueueCeiling: 1},
		RelayControls:     RelayLocalRuntimeControlsV1{RuntimeID: "relay-runtime", EventCapacity: 128, QueueCeiling: 1},
	}
}

func newEstablishedLifecyclePairV1(t *testing.T, runtime *HandshakeRuntime, input PairInputV1) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1) {
	t.Helper()
	client, relay, err := runtime.NewAuthenticatedChannelPair(input)
	if err != nil {
		snapshot, view, snapshotErr := auth.SnapshotFirstContactInputV1(input.FirstContactInput)
		preflightErr := runtime.verifySupportAndAuthorizationPreflightV1(snapshot, view)
		universalErr := verifyUniversalSupportV1(runtime.clientSupport, view.SelectedPolicy, view.SelectedCapabilities, view.ClientModeBinding, view.ServerModeBinding)
		t.Fatalf("pair: %v snapshot=%v preflight=%v universal=%v rotation=%q limits=%d/%d", err, snapshotErr, preflightErr, universalErr, view.SelectedPolicy.KeyRotationPolicy, view.SelectedPolicy.MaxSessionMessages, view.SelectedPolicy.MaxKeyLifetimeMessages)
	}
	if err := relay.state.life.postAuthenticationCommitV1(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, relay
}

func assertOperationAckInvalidExactV1(t *testing.T, err error) {
	t.Helper()
	if err != ErrOperationAckInvalid || err.Error() != "operation_ack_invalid" {
		t.Fatalf("operation acknowledgement error=%#v", err)
	}
}

func TestLifecyclePostAuthCommitAndStaticReachabilityV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7301, "session_only", 8, 8)
	runtime := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	client, relay, err := runtime.NewAuthenticatedChannelPair(input)
	if err != nil {
		t.Fatal(err)
	}
	if client.State() != auth.StateEstablished || relay.State() != auth.StateAuthenticating {
		t.Fatalf("initial states=%s/%s", client.State(), relay.State())
	}
	if err := relay.state.life.postAuthenticationCommitV1(); err != nil || relay.State() != auth.StateEstablished {
		t.Fatalf("post-auth commit state=%s err=%v", relay.State(), err)
	}
	if err := relay.state.life.postAuthenticationCommitV1(); !errors.Is(err, ErrLifecycle) || client.State() != auth.StateClosed {
		t.Fatalf("duplicate post-auth state=%s err=%v", client.State(), err)
	}

	runtime = lifecycleRuntimeV1(t, fixture)
	client, relay, err = runtime.NewAuthenticatedChannelPair(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.state.life.postAuthenticationCommitV1(); !errors.Is(err, ErrLifecycle) || relay.State() != auth.StateClosed {
		t.Fatalf("wrong-role post-auth state=%s err=%v", relay.State(), err)
	}

	runtime = lifecycleRuntimeV1(t, fixture)
	client, relay, err = runtime.NewAuthenticatedChannelPair(input)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err := relay.state.life.postAuthenticationCommitV1(); err != ErrLifecycle || client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
		t.Fatalf("post-auth after local close states=%s/%s err=%#v", client.State(), relay.State(), err)
	}

	_, thisFile, _, ok := gort.Caller(0)
	if !ok {
		t.Fatal("caller unavailable")
	}
	dir := filepath.Dir(thisFile)
	production := []string{"handshake.go", "lifecycle.go", "authenticated_pair.go", "errors.go"}
	occurrences := 0
	for _, name := range production {
		raw, readErr := os.ReadFile(filepath.Join(dir, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		occurrences += strings.Count(string(raw), "postAuthenticationCommitV1(")
	}
	if occurrences != 1 {
		t.Fatalf("production post-auth occurrences=%d want declaration only", occurrences)
	}
}

func TestLifecyclePrivateSurfaceAndControlBoundaryV1(t *testing.T) {
	if reflect.TypeOf(PairInputV1{}).NumField() != 5 {
		t.Fatal("PairInputV1 surface changed")
	}
	_, thisFile, _, ok := gort.Caller(0)
	if !ok {
		t.Fatal("caller unavailable")
	}
	dir := filepath.Dir(thisFile)
	production := []string{"authenticated_pair.go", "errors.go", "handshake.go", "lifecycle.go"}
	rawByFile := make(map[string][]byte, len(production))
	var combined []byte
	for _, name := range production {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		rawByFile[name] = raw
		combined = append(combined, raw...)
	}
	for _, forbidden := range []string{
		"SealOperationAckV1", "OpenOperationAckV1", "parseOperationAckBodyV1", "encodeOperationAckBodyV1",
		"ciphertext", "decrypt", "deriveNonce", "nonceDerivation", "wireClose", "CloseV1{",
		"restoreLifecycle", "resumeLifecycle", "profileGenerationInput",
	} {
		if bytes.Contains(combined, []byte(forbidden)) {
			t.Fatalf("changed production owns forbidden lifecycle concern %q", forbidden)
		}
	}
	allowedExports := map[string]bool{
		"NewRuntimeLabEndpointPairV1":   true,
		"RuntimeLabFaultObservationV1":  true,
		"ExecuteRuntimeLabFaultV1":      true,
		"ClientAuthenticatedEndpointV1": true, "ClientLocalRuntimeControlsV1": true,
		"Close": true, "ErrCompatibility": true, "ErrConfigInvalid": true, "ErrInvalidConfig": true,
		"ErrInvalidRole": true, "ErrKeyLifetimeExhausted": true, "ErrLifecycle": true,
		"ErrLinkClosed": true, "ErrLinkFailure": true, "ErrLinkQueueFull": true,
		"ErrNegotiation": true, "ErrOperationAckInvalid": true, "ErrProfileLoad": true,
		"ErrProfileRotationRequired": true, "ErrRecordInvalid": true, "ErrRekeyFailed": true,
		"ErrSecureChannel": true, "ErrSessionLimit": true, "ErrSessionMessageLimit": true,
		"ErrStreamLimit": true, "ErrTraceHygiene": true, "FirstContact": true,
		"HandshakeRuntime": true, "NewAuthenticatedChannelPair": true, "NewHandshakeRuntime": true,
		"NewAuthenticatedChannelPairWithAuthLabFaultV1": true,
		"NewStrictHandshakeRuntimeV1":                   true, "PairInputV1": true,
		"RelayAuthenticatedEndpointV1": true, "RelayLocalRuntimeControlsV1": true, "State": true,
	}
	for _, name := range production {
		file, err := parser.ParseFile(token.NewFileSet(), name, rawByFile[name], 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			switch typed := decl.(type) {
			case *ast.FuncDecl:
				privateProfileLoadErrorMethod := false
				if name == "errors.go" && (typed.Name.Name == "Error" || typed.Name.Name == "Unwrap") && typed.Recv != nil && len(typed.Recv.List) == 1 {
					receiver, ok := typed.Recv.List[0].Type.(*ast.Ident)
					privateProfileLoadErrorMethod = ok && receiver.Name == "profileLoadFailureV1"
				}
				if ast.IsExported(typed.Name.Name) && !allowedExports[typed.Name.Name] && !privateProfileLoadErrorMethod {
					t.Fatalf("%s added exported function or method %s", name, typed.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range typed.Specs {
					switch value := spec.(type) {
					case *ast.TypeSpec:
						if ast.IsExported(value.Name.Name) && !allowedExports[value.Name.Name] {
							t.Fatalf("%s added exported type %s", name, value.Name.Name)
						}
					case *ast.ValueSpec:
						for _, identifier := range value.Names {
							if ast.IsExported(identifier.Name) && !allowedExports[identifier.Name] {
								t.Fatalf("%s added exported value %s", name, identifier.Name)
							}
						}
					}
				}
			}
		}
	}
	record, err := hex.DecodeString(operationAckRecordV1)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(record)
	if got := hex.EncodeToString(digest[:]); got != "3a1ebb8246fc3d1c013017b11e28b29d4363001884496fc6e3c1a7f823acd194" {
		t.Fatalf("WO-032 acknowledgement recurrence=%s", got)
	}
}

func TestLifecycleStateMissingOrCorruptLifeFailsClosedV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7308, "session_only", 8, 8)
	input := lifecyclePairInputV1(t, fixture)
	for _, test := range []struct {
		name    string
		corrupt func(*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1)
		state   func(*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1) auth.State
	}{
		{
			name: "client_nil_life",
			corrupt: func(client *ClientAuthenticatedEndpointV1, _ *RelayAuthenticatedEndpointV1) {
				client.state.life = nil
			},
			state: func(client *ClientAuthenticatedEndpointV1, _ *RelayAuthenticatedEndpointV1) auth.State {
				return client.State()
			},
		},
		{
			name: "relay_nil_life",
			corrupt: func(_ *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) {
				relay.state.life = nil
			},
			state: func(_ *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) auth.State {
				return relay.State()
			},
		},
		{
			name: "client_corrupt_life",
			corrupt: func(client *ClientAuthenticatedEndpointV1, _ *RelayAuthenticatedEndpointV1) {
				client.state.life.self = nil
			},
			state: func(client *ClientAuthenticatedEndpointV1, _ *RelayAuthenticatedEndpointV1) auth.State {
				return client.State()
			},
		},
		{
			name: "relay_corrupt_life",
			corrupt: func(_ *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) {
				relay.state.life.self = nil
			},
			state: func(_ *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) auth.State {
				return relay.State()
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
			clientLife, relayLife := client.state.life, relay.state.life
			clientAliases := publicScheduleAliasesV1(client.state.schedule)
			relayAliases := publicScheduleAliasesV1(relay.state.schedule)
			var clientDestroy, relayDestroy atomic.Int32
			installScheduleDestroyCounterV1(clientLife, &clientDestroy)
			installScheduleDestroyCounterV1(relayLife, &relayDestroy)
			coordinator := client.state.coordinator
			test.corrupt(client, relay)
			if state := test.state(client, relay); state != auth.StateClosed {
				t.Fatalf("corrupt lifecycle state=%s", state)
			}
			if client.State() != auth.StateClosed || relay.State() != auth.StateClosed || !coordinator.closed || coordinator.destroy != nil ||
				clientDestroy.Load() != 1 || relayDestroy.Load() != 1 || !allRuntimeSlicesZeroV1(clientAliases) || !allRuntimeSlicesZeroV1(relayAliases) ||
				clientLife.schedule != nil || relayLife.schedule != nil {
				t.Fatalf("corrupt lifecycle close states=%s/%s closed=%v destroy_present=%v calls=%d/%d zero=%v/%v schedules=%v/%v",
					client.State(), relay.State(), coordinator.closed, coordinator.destroy != nil, clientDestroy.Load(), relayDestroy.Load(),
					allRuntimeSlicesZeroV1(clientAliases), allRuntimeSlicesZeroV1(relayAliases), clientLife.schedule, relayLife.schedule)
			}
			_ = test.state(client, relay)
			client.Close()
			relay.Close()
			if clientDestroy.Load() != 1 || relayDestroy.Load() != 1 {
				t.Fatalf("corrupt lifecycle double destroy=%d/%d", clientDestroy.Load(), relayDestroy.Load())
			}
		})
	}
}

func TestLifecycleLocalCloseConcurrentAndIdempotentV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7302, "session_only", 8, 8)
	owner := lifecycleRuntimeV1(t, fixture)
	client, relay := newEstablishedLifecyclePairV1(t, owner, lifecyclePairInputV1(t, fixture))
	clientAliases := publicScheduleAliasesV1(client.state.schedule)
	relayAliases := publicScheduleAliasesV1(relay.state.schedule)
	coordinator := client.state.coordinator
	profile := coordinator.retiredProfile
	clientRoleTag, relayRoleTag := coordinator.clientTag, coordinator.relayTag
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				client.Close()
			} else {
				relay.Close()
			}
			_ = client.State()
			_ = relay.State()
		}(i)
	}
	wg.Wait()
	client.Close()
	relay.Close()
	if client.State() != auth.StateClosed || relay.State() != auth.StateClosed ||
		!allRuntimeSlicesZeroV1(clientAliases) || !allRuntimeSlicesZeroV1(relayAliases) ||
		coordinator.destroy != nil || !coordinator.closed || coordinator.owner != owner || coordinator.ownerTag != owner.instanceTag ||
		coordinator.runtimeEpoch != owner.epoch || coordinator.retiredProfile != profile || !validPairProfileBindingV1(profile) ||
		coordinator.clientTag != clientRoleTag || coordinator.relayTag != relayRoleTag ||
		client.state.restartTag != clientRoleTag || relay.state.restartTag != relayRoleTag ||
		coordinator.restartInProgress || coordinator.restartSucceeded || !reflect.DeepEqual(coordinator.context, auth.AuthenticatedContextSnapshotV1{}) ||
		client.state.config != (StrictSessionConfigV1{}) || relay.state.config != (StrictSessionConfigV1{}) ||
		client.state.controls != (ClientLocalRuntimeControlsV1{}) || relay.state.controls != (RelayLocalRuntimeControlsV1{}) ||
		client.state.life.config != (StrictSessionConfigV1{}) || relay.state.life.config != (StrictSessionConfigV1{}) ||
		client.state.life.role != 0 || relay.state.life.role != 0 || client.state.life.rotation != "" || relay.state.life.rotation != "" ||
		client.state.life.nonceMode != "" || relay.state.life.nonceMode != "" || client.state.life.replayPolicy != "" || relay.state.life.replayPolicy != "" ||
		client.state.life.generation != 0 || relay.state.life.generation != 0 || client.state.life.keyEpoch != 0 || relay.state.life.keyEpoch != 0 ||
		client.state.life.outSequence != 0 || relay.state.life.outSequence != 0 || client.state.life.operationSequence != 0 || relay.state.life.operationSequence != 0 ||
		client.state.life.inOperationSequence != 0 || relay.state.life.inOperationSequence != 0 || client.state.life.outKeyAttempts != 0 || relay.state.life.outKeyAttempts != 0 ||
		client.state.life.inKeyAttempts != 0 || relay.state.life.inKeyAttempts != 0 || client.state.life.sendCompleted != 0 || relay.state.life.sendCompleted != 0 ||
		client.state.life.receiveCompleted != 0 || relay.state.life.receiveCompleted != 0 {
		t.Fatal("local close did not converge and destroy exactly once")
	}
}

func TestLifecycleOperationAckRetryConvergenceV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7310, "session_only", 16, 16)
	client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
	operation, err := client.state.life.beginOperationV1(7)
	if err != nil {
		t.Fatal(err)
	}
	if operation.recordEpoch != 0 || operation.recordSequence != 0 || operation.attempt != 1 || operation.operationSequence != 0 {
		t.Fatalf("initial operation=%+v", operation)
	}
	ack, err := relay.state.life.commitAuthenticatedOperationV1(operation)
	if err != nil || ack.OperationID != operation.operationID || ack.CompletedCount != 1 {
		t.Fatalf("operation completion ack=%+v err=%v", ack, err)
	}
	retry, err := client.state.life.retryOperationV1(operation.operationID)
	if err != nil {
		t.Fatal(err)
	}
	if retry.operationID != operation.operationID || retry.recordSequence == operation.recordSequence || retry.attempt != 2 {
		t.Fatalf("operation retry=%+v", retry)
	}
	duplicateAck, err := relay.state.life.commitAuthenticatedOperationV1(retry)
	if err != nil || duplicateAck != ack || relay.state.life.receiveCompleted != 1 {
		t.Fatalf("duplicate operation ack=%+v err=%v completed=%d", duplicateAck, err, relay.state.life.receiveCompleted)
	}
	ackTransmission, err := relay.state.life.beginOperationAckV1(operation.operationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.state.life.commitAuthenticatedOperationAckV1(ackTransmission); err != nil {
		t.Fatal(err)
	}
	ackRetry, err := relay.state.life.retryOperationAckV1(operation.operationID)
	if err != nil {
		t.Fatal(err)
	}
	if ackRetry.ack != ackTransmission.ack || ackRetry.recordSequence == ackTransmission.recordSequence || ackRetry.attempt != 2 {
		t.Fatalf("ack retry=%+v", ackRetry)
	}
	if err := client.state.life.commitAuthenticatedOperationAckV1(ackRetry); err != nil {
		t.Fatalf("fresh-sequence duplicate ack failed: %v", err)
	}
	if client.state.life.sendCompleted != 1 || len(client.state.life.outstanding) != 0 || relay.state.life.receiveCompleted != 1 {
		t.Fatalf("convergence send=%d outstanding=%d receive=%d", client.state.life.sendCompleted, len(client.state.life.outstanding), relay.state.life.receiveCompleted)
	}
}

func TestLifecycleOperationIDVectorV1(t *testing.T) {
	var th4 [32]byte
	for i := range th4 {
		th4[i] = byte(i)
	}
	for _, vector := range []struct {
		sequence uint64
		want     string
	}{
		{sequence: 0, want: "233d89aa83d6c6158340dbb59b5900410b0b7c992436c4c87ff70dfb722e22d5"},
		{sequence: 9, want: "cde482ac3912a60bdba0c2a0ecebc0335cf2850833d7f2e9d502e2fe798ffd34"},
	} {
		id := operationIDV1(th4, controlDirectionClientV1, 7, 3, vector.sequence)
		if got := hex.EncodeToString(id[:]); got != vector.want {
			t.Fatalf("operation sequence %d id=%s", vector.sequence, got)
		}
	}
}

func TestOperationAckAndLocalCloseWO032VectorRecurrenceV1(t *testing.T) {
	mustHex := func(encoded string) []byte {
		value, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	assertBytes := func(name string, got []byte, want string) {
		t.Helper()
		expected := mustHex(want)
		if !bytes.Equal(got, expected) {
			t.Fatalf("%s=%x want=%x", name, got, expected)
		}
	}
	var context ControlContextV1
	for index := range context.EffectivePolicyHash {
		context.EffectivePolicyHash[index] = byte(0x20 + index)
		context.TH4[index] = byte(index)
	}
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("operation_ack", func(t *testing.T) {
		var operationID [32]byte
		copy(operationID[:], mustHex("cde482ac3912a60bdba0c2a0ecebc0335cf2850833d7f2e9d502e2fe798ffd34"))
		ack := OperationAckV1{OperationID: operationID, CompletedCount: 5}
		body, err := encodeOperationAckBodyV1(ack)
		if err != nil {
			t.Fatal(err)
		}
		assertBytes("ack body", body[:], "00010002cde482ac3912a60bdba0c2a0ecebc0335cf2850833d7f2e9d502e2fe798ffd340000000000000005")
		header := ControlHeaderV1{Version: 1, Type: 2, Epoch: 7, Direction: 2, Sequence: 11, SealedLength: 60}
		headerBytes := encodeControlHeaderV1(header)
		assertBytes("ack header", headerBytes[:], "0001000200000000000000070002000000000000000b0000003c")
		aad := encodeControlAADV1(header, context)
		assertBytes("ack aad", aad[:], "00010002202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000000070002000000000000000b0000003c")
		record, err := (RelayControlCodecV1{}).SealOperationAckV1(context, 7, 11, ack, func(epoch, sequence uint64, plaintext, callbackAAD []byte) ([]byte, error) {
			if epoch != 7 || sequence != 11 {
				t.Fatalf("ack metadata=%d/%d", epoch, sequence)
			}
			assertBytes("ack callback body", plaintext, "00010002cde482ac3912a60bdba0c2a0ecebc0335cf2850833d7f2e9d502e2fe798ffd340000000000000005")
			assertBytes("ack callback aad", callbackAAD, "00010002202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000000070002000000000000000b0000003c")
			nonce := mustHex("a0a1a2a3000000000000000b")
			return aead.Seal(nil, nonce, plaintext, callbackAAD), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		assertBytes("ack record", record, "0001000200000000000000070002000000000000000b0000003ce8de59be63e5cffed77e6dd10286b57dc47c83ff6e7dafec088247653f2fcc44105a354c243ed2b636fc5159f8ce0e52c04e8a34694eb042c535e105")
	})

	t.Run("local_close", func(t *testing.T) {
		closeValue := CloseV1{Code: 1}
		body, err := encodeCloseBodyV1(closeValue)
		if err != nil {
			t.Fatal(err)
		}
		assertBytes("close body", body[:], "000100030001")
		header := ControlHeaderV1{Version: 1, Type: 3, Epoch: 7, Direction: 2, Sequence: 12, SealedLength: 22}
		headerBytes := encodeControlHeaderV1(header)
		assertBytes("close header", headerBytes[:], "0001000300000000000000070002000000000000000c00000016")
		aad := encodeControlAADV1(header, context)
		assertBytes("close aad", aad[:], "00010003202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000000070002000000000000000c00000016")
		record, err := (RelayControlCodecV1{}).SealCloseV1(context, 7, 12, closeValue, func(epoch, sequence uint64, plaintext, callbackAAD []byte) ([]byte, error) {
			if epoch != 7 || sequence != 12 {
				t.Fatalf("close metadata=%d/%d", epoch, sequence)
			}
			assertBytes("close callback body", plaintext, "000100030001")
			assertBytes("close callback aad", callbackAAD, "00010003202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000000070002000000000000000c00000016")
			nonce := mustHex("a0a1a2a3000000000000000c")
			return aead.Seal(nil, nonce, plaintext, callbackAAD), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		assertBytes("close record", record, "0001000300000000000000070002000000000000000c0000001617b3e1818ec76c1ff72c25b291cb249742d5b93bc97d")
	})
}

func TestLifecycleConcurrentOperationAdmissionAndReplayCommitV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7314, "session_only", 128, 128)
	client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
	transmissions := make(chan operationTransmissionV1, 64)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(slot uint16) {
			defer wg.Done()
			transmission, err := client.state.life.beginOperationV1(slot)
			if err == nil {
				transmissions <- transmission
			}
		}(uint16(i + 1))
	}
	wg.Wait()
	close(transmissions)
	seenID := make(map[[32]byte]struct{})
	seenSequence := make(map[uint64]struct{})
	var first operationTransmissionV1
	for transmission := range transmissions {
		if transmission.operationSequence == 0 {
			first = transmission
		}
		seenID[transmission.operationID] = struct{}{}
		seenSequence[transmission.recordSequence] = struct{}{}
	}
	if len(seenID) != 64 || len(seenSequence) != 64 || len(client.state.life.outstanding) != 64 {
		t.Fatalf("concurrent admission ids=%d sequences=%d outstanding=%d", len(seenID), len(seenSequence), len(client.state.life.outstanding))
	}
	replayAlias := relay.state.life.replay
	completedAlias := relay.state.life.completed
	var successes atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := relay.state.life.commitAuthenticatedOperationV1(first); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || len(completedAlias) != 1 || replayAlias.MetadataV1().SeenCount != 1 || relay.State() != auth.StateClosed {
		t.Fatalf("concurrent replay successes=%d completed=%d replay=%+v state=%s", successes.Load(), len(completedAlias), replayAlias.MetadataV1(), relay.State())
	}
}

func TestLifecycleOperationAndAckIndependentTransmissionLimitsV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7311, "session_only", 32, 32)
	input := lifecyclePairInputV1(t, fixture)

	t.Run("operation", func(t *testing.T) {
		client, _ := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
		first, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		second, err := client.state.life.retryOperationV1(first.operationID)
		if err != nil {
			t.Fatal(err)
		}
		third, err := client.state.life.retryOperationV1(first.operationID)
		if err != nil {
			t.Fatal(err)
		}
		if first.attempt != 1 || second.attempt != 2 || third.attempt != 3 ||
			first.recordSequence == second.recordSequence || second.recordSequence == third.recordSequence {
			t.Fatalf("operation attempts=%+v %+v %+v", first, second, third)
		}
		if _, err := client.state.life.retryOperationV1(first.operationID); !errors.Is(err, ErrLifecycle) || client.State() != auth.StateClosed {
			t.Fatalf("fourth operation transmission err=%v state=%s", err, client.State())
		}
	})

	t.Run("acknowledgement", func(t *testing.T) {
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
			t.Fatal(err)
		}
		first, err := relay.state.life.beginOperationAckV1(operation.operationID)
		if err != nil {
			t.Fatal(err)
		}
		second, err := relay.state.life.retryOperationAckV1(operation.operationID)
		if err != nil {
			t.Fatal(err)
		}
		third, err := relay.state.life.retryOperationAckV1(operation.operationID)
		if err != nil {
			t.Fatal(err)
		}
		if first.attempt != 1 || second.attempt != 2 || third.attempt != 3 || first.ack != second.ack || second.ack != third.ack {
			t.Fatalf("ack attempts=%+v %+v %+v", first, second, third)
		}
		if _, err := relay.state.life.retryOperationAckV1(operation.operationID); !errors.Is(err, ErrOperationAckInvalid) || relay.State() != auth.StateClosed {
			t.Fatalf("fourth ack transmission err=%v state=%s", err, relay.State())
		}
	})
}

func TestOperationAckInvalidSemanticInputsDoNotCommitV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7312, "session_only", 32, 32)
	input := lifecyclePairInputV1(t, fixture)
	tests := []struct {
		name   string
		mutate func(*acknowledgementTransmissionV1, *endpointLifecycleV1)
	}{
		{"wrong_id", func(tx *acknowledgementTransmissionV1, _ *endpointLifecycleV1) { tx.ack.OperationID[0] ^= 0x80 }},
		{"wrong_count", func(tx *acknowledgementTransmissionV1, _ *endpointLifecycleV1) { tx.ack.CompletedCount++ }},
		{"wrong_owner", func(tx *acknowledgementTransmissionV1, receiver *endpointLifecycleV1) { tx.owner = receiver }},
		{"wrong_coordinator", func(tx *acknowledgementTransmissionV1, _ *endpointLifecycleV1) {
			tx.coordinator = &pairTerminalCoordinatorV1{}
		}},
		{"wrong_state", func(_ *acknowledgementTransmissionV1, receiver *endpointLifecycleV1) {
			receiver.state = auth.StateAuthenticating
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
			operation, err := client.state.life.beginOperationV1(1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
				t.Fatal(err)
			}
			ack, err := relay.state.life.beginOperationAckV1(operation.operationID)
			if err != nil {
				t.Fatal(err)
			}
			outstandingAlias := client.state.life.outstanding
			replayAlias := client.state.life.replay
			beforeReplay := replayAlias.MetadataV1()
			test.mutate(&ack, client.state.life)
			beforeSendCompleted, beforeInKeyAttempts := client.state.life.sendCompleted, client.state.life.inKeyAttempts
			assertOperationAckInvalidExactV1(t, client.state.life.commitAuthenticatedOperationAckV1(ack))
			if _, ok := outstandingAlias[operation.operationID]; !ok || replayAlias.MetadataV1() != beforeReplay ||
				client.state.life.sendCompleted != beforeSendCompleted || client.state.life.inKeyAttempts != beforeInKeyAttempts ||
				client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
				t.Fatal("semantic invalid input committed state or remained open")
			}
		})
	}

	t.Run("ack_before_operation", func(t *testing.T) {
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
		var unknown [32]byte
		unknown[0] = 1
		tx := acknowledgementTransmissionV1{
			owner: relay.state.life, coordinator: client.state.life.coordinator,
			ack: OperationAckV1{OperationID: unknown, CompletedCount: 1}, recordEpoch: 0, recordSequence: 0, attempt: 1,
		}
		replayAlias := client.state.life.replay
		before := replayAlias.MetadataV1()
		beforeSendCompleted, beforeInKeyAttempts := client.state.life.sendCompleted, client.state.life.inKeyAttempts
		err := client.state.life.commitAuthenticatedOperationAckV1(tx)
		assertOperationAckInvalidExactV1(t, err)
		if replayAlias.MetadataV1() != before || client.state.life.sendCompleted != beforeSendCompleted || client.state.life.inKeyAttempts != beforeInKeyAttempts {
			t.Fatalf("ack-before-operation committed state err=%v", err)
		}
	})

	t.Run("wrong_order", func(t *testing.T) {
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
		first, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		second, err := client.state.life.beginOperationV1(2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(first); err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(second); err != nil {
			t.Fatal(err)
		}
		secondAck, err := relay.state.life.beginOperationAckV1(second.operationID)
		if err != nil {
			t.Fatal(err)
		}
		replay := client.state.life.replay
		beforeReplay := replay.MetadataV1()
		outstanding := client.state.life.outstanding
		beforeSendCompleted, beforeInKeyAttempts := client.state.life.sendCompleted, client.state.life.inKeyAttempts
		err = client.state.life.commitAuthenticatedOperationAckV1(secondAck)
		assertOperationAckInvalidExactV1(t, err)
		if replay.MetadataV1() != beforeReplay || len(outstanding) != 2 || client.state.life.sendCompleted != beforeSendCompleted || client.state.life.inKeyAttempts != beforeInKeyAttempts {
			t.Fatal("out-of-order acknowledgement committed state")
		}
	})
}

func TestOperationAckExactRecordReplayRejectsV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7313, "session_only", 16, 16)
	client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
	operation, err := client.state.life.beginOperationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
		t.Fatal(err)
	}
	ack, err := relay.state.life.beginOperationAckV1(operation.operationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.state.life.commitAuthenticatedOperationAckV1(ack); err != nil {
		t.Fatal(err)
	}
	replay := client.state.life.replay
	beforeReplay := replay.MetadataV1()
	acknowledged := client.state.life.acknowledged
	beforeAcknowledged := acknowledged[operation.operationID]
	outstanding := client.state.life.outstanding
	issuedOperations := client.state.life.issuedOperations
	err = client.state.life.commitAuthenticatedOperationAckV1(ack)
	assertOperationAckInvalidExactV1(t, err)
	if client.State() != auth.StateClosed || relay.State() != auth.StateClosed || replay.MetadataV1() != beforeReplay ||
		len(acknowledged) != 1 || acknowledged[operation.operationID] != beforeAcknowledged || beforeAcknowledged != 1 ||
		len(outstanding) != 0 || len(issuedOperations) != 1 || client.state.life.sendCompleted != 0 || client.state.life.inKeyAttempts != 0 {
		t.Fatalf("exact ack replay mutated semantic state err=%#v states=%s/%s replay=%+v acknowledged=%v outstanding=%d issued=%d",
			err, client.State(), relay.State(), replay.MetadataV1(), acknowledged, len(outstanding), len(issuedOperations))
	}
}

func TestOperationAckIssuedStaleAndGappedEpochsInvalidV1(t *testing.T) {
	assertInvalidWithoutCommit := func(t *testing.T, client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, operation operationTransmissionV1, ack acknowledgementTransmissionV1) {
		t.Helper()
		life := client.state.life
		outstanding := life.outstanding
		acknowledged := life.acknowledged
		issuedOperations := life.issuedOperations
		issuedAcks := relay.state.life.issuedAcks
		replay := life.replay
		if replay == nil || len(outstanding) != 1 || outstanding[operation.operationID] == nil || len(acknowledged) != 0 ||
			issuedAcks[ackReservationKeyV1(ack)] != ack {
			t.Fatal("invalid issued-ack epoch setup")
		}
		beforeReplay := replay.MetadataV1()
		beforeSendCompleted := life.sendCompleted
		assertOperationAckInvalidExactV1(t, life.commitAuthenticatedOperationAckV1(ack))
		if client.State() != auth.StateClosed || relay.State() != auth.StateClosed || replay.MetadataV1() != beforeReplay ||
			len(outstanding) != 1 || outstanding[operation.operationID] == nil || len(acknowledged) != 0 ||
			len(issuedOperations) != 1 || issuedAcks[ackReservationKeyV1(ack)] != ack || beforeSendCompleted != 0 || life.sendCompleted != 0 {
			t.Fatalf("invalid issued-ack epoch committed semantic state states=%s/%s replay=%+v/%+v outstanding=%d acknowledged=%d issued_operations=%d send=%d/%d",
				client.State(), relay.State(), replay.MetadataV1(), beforeReplay, len(outstanding), len(acknowledged), len(issuedOperations), life.sendCompleted, beforeSendCompleted)
		}
	}

	t.Run("stale_epoch", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7402, "message_lifetime_bound", 8, 1)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
			t.Fatal(err)
		}
		ack, err := relay.state.life.beginOperationAckV1(operation.operationID)
		if err != nil {
			t.Fatal(err)
		}
		advance, err := relay.state.life.beginOperationV1(2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.state.life.commitAuthenticatedOperationV1(advance); err != nil {
			t.Fatal(err)
		}
		if ack.recordEpoch != 0 || client.state.life.keyEpoch != 1 {
			t.Fatalf("stale issued-ack epochs ack=%d receiver=%d", ack.recordEpoch, client.state.life.keyEpoch)
		}
		assertInvalidWithoutCommit(t, client, relay, operation, ack)
	})

	t.Run("epoch_gap", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7403, "message_lifetime_bound", 8, 1)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.beginOperationV1(2); err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.beginOperationV1(3); err != nil {
			t.Fatal(err)
		}
		ack, err := relay.state.life.beginOperationAckV1(operation.operationID)
		if err != nil {
			t.Fatal(err)
		}
		if ack.recordEpoch != 2 || client.state.life.keyEpoch != 0 {
			t.Fatalf("gapped issued-ack epochs ack=%d receiver=%d", ack.recordEpoch, client.state.life.keyEpoch)
		}
		assertInvalidWithoutCommit(t, client, relay, operation, ack)
	})
}

func TestOperationAckDelayedReservedOperationRetryAfterCompletionV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7315, "session_only", 16, 16)
	client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
	first, err := client.state.life.beginOperationV1(3)
	if err != nil {
		t.Fatal(err)
	}
	delayedRetry, err := client.state.life.retryOperationV1(first.operationID)
	if err != nil {
		t.Fatal(err)
	}
	firstAck, err := relay.state.life.commitAuthenticatedOperationV1(first)
	if err != nil {
		t.Fatal(err)
	}
	ackTransmission, err := relay.state.life.beginOperationAckV1(first.operationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.state.life.commitAuthenticatedOperationAckV1(ackTransmission); err != nil {
		t.Fatal(err)
	}
	relayReplay := relay.state.life.replay
	beforeReplay := relayReplay.MetadataV1()
	beforeInboundAttempts := relay.state.life.inKeyAttempts
	delayedAck, err := relay.state.life.commitAuthenticatedOperationV1(delayedRetry)
	if err != nil || delayedAck != firstAck {
		t.Fatalf("delayed retry ack=%+v first=%+v err=%v", delayedAck, firstAck, err)
	}
	afterReplay := relayReplay.MetadataV1()
	if relay.state.life.receiveCompleted != 1 || client.state.life.sendCompleted != 1 || len(client.state.life.outstanding) != 0 ||
		afterReplay.SeenCount != beforeReplay.SeenCount+1 || relay.state.life.inKeyAttempts != beforeInboundAttempts+1 {
		t.Fatalf("delayed retry semantic/replay state receive=%d send=%d outstanding=%d replay=%+v->%+v attempts=%d->%d",
			relay.state.life.receiveCompleted, client.state.life.sendCompleted, len(client.state.life.outstanding),
			beforeReplay, afterReplay, beforeInboundAttempts, relay.state.life.inKeyAttempts)
	}
}

func TestOperationAckReservationInvalidStateOrderAndBudgetExactV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7316, "session_only", 32, 32)
	input := lifecyclePairInputV1(t, fixture)
	type reservationMethodV1 struct {
		name string
		call func(*endpointLifecycleV1, [32]byte) (acknowledgementTransmissionV1, error)
	}
	methods := []reservationMethodV1{
		{name: "begin", call: func(life *endpointLifecycleV1, id [32]byte) (acknowledgementTransmissionV1, error) {
			return life.beginOperationAckV1(id)
		}},
		{name: "retry", call: func(life *endpointLifecycleV1, id [32]byte) (acknowledgementTransmissionV1, error) {
			return life.retryOperationAckV1(id)
		}},
	}
	completedPair := func(t *testing.T) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, [32]byte) {
		t.Helper()
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
			t.Fatal(err)
		}
		return client, relay, operation.operationID
	}
	assertNoReservation := func(t *testing.T, life *endpointLifecycleV1, id [32]byte, call func() error) {
		t.Helper()
		issued := life.issuedAcks
		beforeIssued := len(issued)
		completed := life.completed[id]
		var beforeAckAttempts uint8
		if completed != nil {
			beforeAckAttempts = completed.ackAttempts
		}
		err := call()
		assertOperationAckInvalidExactV1(t, err)
		if len(issued) != beforeIssued || life.outKeyAttempts != 0 || life.keyEpoch != 0 ||
			(completed != nil && completed.ackAttempts != beforeAckAttempts) {
			t.Fatalf("invalid reservation committed issued=%d/%d scrubbed_attempts=%d scrubbed_epoch=%d ack_attempts=%d/%d",
				len(issued), beforeIssued, life.outKeyAttempts, life.keyEpoch,
				func() uint8 {
					if completed == nil {
						return 0
					}
					return completed.ackAttempts
				}(), beforeAckAttempts)
		}
	}
	assertPredicateOnlyInvalid := func(t *testing.T, client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, id [32]byte, method reservationMethodV1, predicate string) {
		t.Helper()
		life := relay.state.life
		if method.name == "retry" {
			if _, err := life.beginOperationAckV1(id); err != nil {
				t.Fatal(err)
			}
		}
		issued := life.issuedAcks
		issuedBefore := make(map[recordReservationKeyV1]acknowledgementTransmissionV1, len(issued))
		for key, value := range issued {
			issuedBefore[key] = value
		}
		outStreams := life.outStreams
		outStreamsBefore := make(map[uint16]outboundSequenceStateV1, len(outStreams))
		for key, value := range outStreams {
			outStreamsBefore[key] = value
		}
		completed := life.completed
		completedEntry := completed[id]
		if completedEntry == nil {
			t.Fatal("predicate-isolation setup has no completed operation")
		}
		beforeAckAttempts := completedEntry.ackAttempts
		beforeOutAttempts, beforeKeyEpoch := life.outKeyAttempts, life.keyEpoch
		switch predicate {
		case "wrong_state":
			life.state = auth.StateAuthenticating
		case "terminal":
			life.coordinator.mu.Lock()
			life.coordinator.closed = true
			life.coordinator.mu.Unlock()
		default:
			t.Fatalf("unknown predicate %q", predicate)
		}
		transmission, err := method.call(life, id)
		assertOperationAckInvalidExactV1(t, err)
		if transmission != (acknowledgementTransmissionV1{}) || !reflect.DeepEqual(issued, issuedBefore) ||
			!reflect.DeepEqual(outStreams, outStreamsBefore) || len(completed) != 1 || completed[id] != completedEntry ||
			completedEntry.ackAttempts != beforeAckAttempts || client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
			t.Fatalf("%s %s predicate committed transmission=%+v issued=%v/%v streams=%v/%v completed=%d ack_attempts=%d/%d states=%s/%s",
				method.name, predicate, transmission, issued, issuedBefore, outStreams, outStreamsBefore,
				len(completed), completedEntry.ackAttempts, beforeAckAttempts, client.State(), relay.State())
		}
		if predicate == "wrong_state" {
			if life.outKeyAttempts != 0 || life.keyEpoch != 0 {
				t.Fatalf("wrong-state terminal scrub attempts=%d epoch=%d", life.outKeyAttempts, life.keyEpoch)
			}
			return
		}
		if life.outKeyAttempts != beforeOutAttempts || life.keyEpoch != beforeKeyEpoch {
			t.Fatalf("closed-predicate counters changed attempts=%d/%d epoch=%d/%d", life.outKeyAttempts, beforeOutAttempts, life.keyEpoch, beforeKeyEpoch)
		}
		life.coordinator.mu.Lock()
		life.coordinator.closed = false
		life.coordinator.mu.Unlock()
		client.Close()
	}

	for _, method := range methods {
		t.Run(method.name+"_wrong_state", func(t *testing.T) {
			client, relay, id := completedPair(t)
			assertPredicateOnlyInvalid(t, client, relay, id, method, "wrong_state")
		})

		t.Run(method.name+"_terminal", func(t *testing.T) {
			client, relay, id := completedPair(t)
			assertPredicateOnlyInvalid(t, client, relay, id, method, "terminal")
		})

		t.Run(method.name+"_unknown", func(t *testing.T) {
			_, relay, _ := completedPair(t)
			var unknown [32]byte
			unknown[0] = 0x80
			assertNoReservation(t, relay.state.life, unknown, func() error {
				_, err := method.call(relay.state.life, unknown)
				return err
			})
		})

		t.Run(method.name+"_order", func(t *testing.T) {
			_, relay, id := completedPair(t)
			if method.name == "begin" {
				if _, err := relay.state.life.beginOperationAckV1(id); err != nil {
					t.Fatal(err)
				}
			}
			assertNoReservation(t, relay.state.life, id, func() error {
				_, err := method.call(relay.state.life, id)
				return err
			})
		})

		t.Run(method.name+"_budget", func(t *testing.T) {
			_, relay, id := completedPair(t)
			if _, err := relay.state.life.beginOperationAckV1(id); err != nil {
				t.Fatal(err)
			}
			for index := 1; index < lifecycleTransmissionLimitV1; index++ {
				if _, err := relay.state.life.retryOperationAckV1(id); err != nil {
					t.Fatal(err)
				}
			}
			assertNoReservation(t, relay.state.life, id, func() error {
				_, err := method.call(relay.state.life, id)
				return err
			})
		})
	}
}

func TestOperationAckReservationPreservesLifetimeRekeyAndProfileGenerationErrorsV1(t *testing.T) {
	t.Run("profile_rotation", func(t *testing.T) {
		profileA := newLifecycleFixtureV1(t, 7317, "profile_lifetime_bound", 8, 8)
		profileB := newLifecycleFixtureV1(t, 7318, "profile_lifetime_bound", 8, 8)
		runtime := lifecycleRuntimeV1(t, profileA, profileB)
		client, relay := newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileA))
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
			t.Fatal(err)
		}
		newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileB))
		if _, err := relay.state.life.beginOperationAckV1(operation.operationID); err != ErrProfileRotationRequired || err.Error() != "profile_rotation_required" {
			t.Fatalf("profile acknowledgement reservation err=%#v", err)
		}
	})

	t.Run("session_key_exhaustion", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7319, "session_only", 8, 1)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.beginOperationAckV1(operation.operationID); err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.retryOperationAckV1(operation.operationID); err != ErrKeyLifetimeExhausted || err.Error() != "key_lifetime_exhausted" {
			t.Fatalf("session acknowledgement retry err=%#v", err)
		}
	})

	t.Run("rekey_failure", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7325, "message_lifetime_bound", 8, 1)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.beginOperationAckV1(operation.operationID); err != nil {
			t.Fatal(err)
		}
		relay.state.schedule.ExporterSecret = nil
		if _, err := relay.state.life.retryOperationAckV1(operation.operationID); err != ErrRekeyFailed || err.Error() != "rekey_failed" {
			t.Fatalf("rekey acknowledgement retry err=%#v", err)
		}
	})
}

func TestRekeyLifetimeBoundaryAndPendingReceiveCommitV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7320, "message_lifetime_bound", 8, 2)
	client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
	oldClientAliases := publicScheduleAliasesV1(client.state.schedule)
	oldRelayAliases := publicScheduleAliasesV1(relay.state.schedule)
	oldClientKey := append([]byte(nil), client.state.schedule.ClientWriteKey...)
	first, err := client.state.life.beginOperationV1(3)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.state.life.retryOperationV1(first.operationID)
	if err != nil {
		t.Fatal(err)
	}
	if first.recordEpoch != 0 || first.recordSequence != 0 || second.recordEpoch != 0 || second.recordSequence != 1 {
		t.Fatalf("last allowed attempts=%+v %+v", first, second)
	}
	if _, err := relay.state.life.commitAuthenticatedOperationV1(first); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.state.life.commitAuthenticatedOperationV1(second); err != nil {
		t.Fatal(err)
	}
	third, err := client.state.life.retryOperationV1(first.operationID)
	if err != nil {
		t.Fatal(err)
	}
	if third.recordEpoch != 1 || third.recordSequence != 0 || third.operationID != first.operationID || client.state.life.keyEpoch != 1 ||
		bytes.Equal(oldClientKey, client.state.schedule.ClientWriteKey) || !allRuntimeSlicesZeroV1(oldClientAliases) {
		t.Fatalf("sender ratchet did not atomically install epoch one: %+v", third)
	}
	ack, err := relay.state.life.commitAuthenticatedOperationV1(third)
	if err != nil {
		t.Fatal(err)
	}
	if relay.state.life.keyEpoch != 1 || relay.state.life.receiveCompleted != 1 || !allRuntimeSlicesZeroV1(oldRelayAliases) ||
		!bytes.Equal(client.state.schedule.ClientWriteKey, relay.state.schedule.ClientWriteKey) {
		t.Fatal("receiver did not commit the authenticated pending epoch exactly once")
	}
	ackTransmission, err := relay.state.life.beginOperationAckV1(first.operationID)
	if err != nil {
		t.Fatal(err)
	}
	if ackTransmission.ack != ack || ackTransmission.recordEpoch != 1 || ackTransmission.recordSequence != 0 {
		t.Fatalf("post-ratchet ack=%+v", ackTransmission)
	}
	if err := client.state.life.commitAuthenticatedOperationAckV1(ackTransmission); err != nil {
		t.Fatal(err)
	}
}

func TestRekeyFailureAndEpochDivergenceAreTerminalV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7321, "message_lifetime_bound", 4, 1)
	input := lifecyclePairInputV1(t, fixture)
	t.Run("ratchet_failure", func(t *testing.T) {
		client, _ := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
		first, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		client.state.schedule.ExporterSecret = nil
		if _, err := client.state.life.retryOperationV1(first.operationID); !errors.Is(err, ErrRekeyFailed) || client.State() != auth.StateClosed {
			t.Fatalf("ratchet failure err=%v state=%s", err, client.State())
		}
	})
	t.Run("epoch_gap", func(t *testing.T) {
		_, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
		life := relay.state.life
		life.coordinator.mu.Lock()
		_, err := life.prepareReceiveEpochLockedV1(1, 2, 0)
		if err != nil {
			life.failLockedV1(err)
		}
		life.coordinator.mu.Unlock()
		if !errors.Is(err, ErrRekeyFailed) || relay.State() != auth.StateClosed {
			t.Fatalf("epoch gap err=%v state=%s", err, relay.State())
		}
	})
	t.Run("old_epoch_after_ratchet", func(t *testing.T) {
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
		first, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(first); err != nil {
			t.Fatal(err)
		}
		next, err := client.state.life.retryOperationV1(first.operationID)
		if err != nil || next.recordEpoch != 1 {
			t.Fatalf("next epoch operation=%+v err=%v", next, err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(next); err != nil {
			t.Fatal(err)
		}
		life := relay.state.life
		life.coordinator.mu.Lock()
		_, err = life.prepareReceiveEpochLockedV1(next.streamSlot, 0, 1)
		if err != nil {
			life.failLockedV1(err)
		}
		life.coordinator.mu.Unlock()
		if !errors.Is(err, ErrRekeyFailed) {
			t.Fatalf("old epoch err=%v", err)
		}
	})
}

func TestLifetimeSessionOnlyAndSessionMessageLimitV1(t *testing.T) {
	t.Run("key_lifetime", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7322, "session_only", 4, 1)
		client, _ := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil || operation.recordSequence != 0 {
			t.Fatalf("last key attempt=%+v err=%v", operation, err)
		}
		if _, err := client.state.life.retryOperationV1(operation.operationID); !errors.Is(err, ErrKeyLifetimeExhausted) || client.State() != auth.StateClosed {
			t.Fatalf("key limit err=%v state=%s", err, client.State())
		}
	})
	t.Run("session_message_limit", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7323, "message_lifetime_bound", 1, 1)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
			t.Fatal(err)
		}
		ack, err := relay.state.life.beginOperationAckV1(operation.operationID)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.state.life.commitAuthenticatedOperationAckV1(ack); err != nil {
			t.Fatal(err)
		}
		if _, err := client.state.life.beginOperationV1(2); !errors.Is(err, ErrSessionMessageLimit) || client.State() != auth.StateClosed {
			t.Fatalf("session limit err=%v state=%s", err, client.State())
		}
	})
}

func TestLifecycleCounterLimitNoWrapV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7324, "message_lifetime_bound", 8, 8)
	client, _ := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
	client.state.life.outSequence = math.MaxUint64
	operation, err := client.state.life.beginOperationV1(1)
	if err != nil || operation.recordSequence != math.MaxUint64 || !client.state.life.outSequenceEnd {
		t.Fatalf("max record sequence=%+v err=%v", operation, err)
	}
	client.state.life.operationSequence = math.MaxUint64
	client.state.life.operationSequenceEnd = false
	second, err := client.state.life.beginOperationV1(2)
	if err != nil || second.operationSequence != math.MaxUint64 || !client.state.life.operationSequenceEnd || second.recordEpoch != 1 || second.recordSequence != 0 {
		t.Fatalf("counter exhaustion ratchet=%+v err=%v", second, err)
	}
	if _, err := client.state.life.beginOperationV1(3); !errors.Is(err, ErrLifecycle) {
		t.Fatalf("operation counter wrap err=%v", err)
	}
}

func TestProfileGenerationSuccessfulPairsAndFailedAttemptV1(t *testing.T) {
	profileA := newLifecycleFixtureV1(t, 7330, "profile_lifetime_bound", 8, 2)
	profileB := newLifecycleFixtureV1(t, 7331, "profile_lifetime_bound", 8, 2)
	runtime := lifecycleRuntimeV1(t, profileA, profileB)
	inputA := lifecyclePairInputV1(t, profileA)
	inputB := lifecyclePairInputV1(t, profileB)
	firstA, relayA := newEstablishedLifecyclePairV1(t, runtime, inputA)
	if firstA.state.life.generation != 0 {
		t.Fatalf("first generation=%d", firstA.state.life.generation)
	}
	secondA, _ := newEstablishedLifecyclePairV1(t, runtime, inputA)
	if secondA.state.life.generation != 0 {
		t.Fatalf("same-profile generation=%d", secondA.state.life.generation)
	}
	failedB := inputB
	failedB.ClientControls.RuntimeID = ""
	if client, relay, err := runtime.NewAuthenticatedChannelPair(failedB); client != nil || relay != nil || !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("partial different-profile pair=%v/%v err=%v", client, relay, err)
	}
	assertGeneration := func(stage string) {
		t.Helper()
		if generation, overflow := runtime.currentProfileGenerationV1(); generation != 0 || overflow {
			t.Fatalf("%s advanced generation=%d overflow=%v", stage, generation, overflow)
		}
	}
	assertGeneration("invalid config")
	preflightB := inputB
	preflightB.FirstContactInput.SelectedCapabilities = nil
	if client, relay, err := runtime.NewAuthenticatedChannelPair(preflightB); client != nil || relay != nil || err == nil {
		t.Fatalf("preflight different-profile pair=%v/%v err=%v", client, relay, err)
	}
	assertGeneration("failed preflight")
	originalDerive := runtime.pairDeriveScheduleV1
	runtime.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
		wipeRuntimeBytesV1(input.ApplicationSecret)
		return security.KeySchedule{}, errors.New("injected lifecycle KDF failure")
	}
	if client, relay, err := runtime.NewAuthenticatedChannelPair(inputB); client != nil || relay != nil || err == nil {
		t.Fatalf("KDF different-profile pair=%v/%v err=%v", client, relay, err)
	}
	runtime.pairDeriveScheduleV1 = originalDerive
	assertGeneration("failed KDF")
	originalConstruct := runtime.pairConstructV1
	runtime.pairConstructV1 = func(pairConstructionInputV1) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error) {
		return nil, nil, errors.New("injected lifecycle construction failure")
	}
	if client, relay, err := runtime.NewAuthenticatedChannelPair(inputB); client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) {
		t.Fatalf("construction different-profile pair=%v/%v err=%v", client, relay, err)
	}
	runtime.pairConstructV1 = originalConstruct
	assertGeneration("failed construction")
	firstB, _ := newEstablishedLifecyclePairV1(t, runtime, inputB)
	if firstB.state.life.generation != 1 {
		t.Fatalf("different-profile generation=%d", firstB.state.life.generation)
	}
	for name, endpoint := range map[string]*ClientAuthenticatedEndpointV1{"first": firstA, "same": secondA} {
		if _, err := endpoint.state.life.beginOperationV1(1); !errors.Is(err, ErrProfileRotationRequired) || endpoint.State() != auth.StateClosed {
			t.Fatalf("%s stale profile err=%v state=%s", name, err, endpoint.State())
		}
	}
	if relayA.State() != auth.StateClosed {
		t.Fatal("stale pair terminal coordination did not close relay")
	}
	if _, err := firstB.state.life.beginOperationV1(1); err != nil {
		t.Fatalf("current profile operation failed: %v", err)
	}
}

func TestProfileGenerationConcurrentDifferentSuccessTotalOrderV1(t *testing.T) {
	profileA := newLifecycleFixtureV1(t, 7332, "profile_lifetime_bound", 8, 2)
	profileB := newLifecycleFixtureV1(t, 7333, "profile_lifetime_bound", 8, 2)
	runtime := lifecycleRuntimeV1(t, profileA, profileB)
	inputs := []PairInputV1{lifecyclePairInputV1(t, profileA), lifecyclePairInputV1(t, profileB)}
	type result struct {
		client *ClientAuthenticatedEndpointV1
		relay  *RelayAuthenticatedEndpointV1
		err    error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, input := range inputs {
		input := input
		wg.Add(1)
		go func() {
			defer wg.Done()
			client, relay, err := runtime.NewAuthenticatedChannelPair(input)
			results <- result{client: client, relay: relay, err: err}
		}()
	}
	wg.Wait()
	close(results)
	var pairs []result
	for got := range results {
		if got.err != nil {
			t.Fatal(got.err)
		}
		pairs = append(pairs, got)
		t.Cleanup(got.client.Close)
	}
	if len(pairs) != 2 {
		t.Fatalf("pairs=%d", len(pairs))
	}
	generations := []uint64{pairs[0].client.state.life.generation, pairs[1].client.state.life.generation}
	if !((generations[0] == 0 && generations[1] == 1) || (generations[0] == 1 && generations[1] == 0)) {
		t.Fatalf("concurrent generations=%v", generations)
	}
	current, overflow := runtime.currentProfileGenerationV1()
	if current != 1 || overflow {
		t.Fatalf("final generation=%d overflow=%v", current, overflow)
	}
	for _, pair := range pairs {
		if pair.client.state.life.generation == current {
			if _, err := pair.client.state.life.beginOperationV1(1); err != nil {
				t.Fatalf("current pair failed: %v", err)
			}
		} else if _, err := pair.client.state.life.beginOperationV1(1); !errors.Is(err, ErrProfileRotationRequired) {
			t.Fatalf("older pair err=%v", err)
		}
	}
}

func TestProfileGenerationOverflowFailsClosedV1(t *testing.T) {
	profileA := newLifecycleFixtureV1(t, 7334, "profile_lifetime_bound", 8, 2)
	profileB := newLifecycleFixtureV1(t, 7335, "profile_lifetime_bound", 8, 2)
	runtime := lifecycleRuntimeV1(t, profileA, profileB)
	oldClient, _ := newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileA))
	runtime.profileMu.Lock()
	runtime.profileGeneration = math.MaxUint64
	runtime.profileSeen = true
	runtime.profileID = profileA.snapshot.Client.ProfileID
	runtime.profileHash = profileA.snapshot.Client.ProfileHash
	runtime.profileMu.Unlock()
	originalConstruct := runtime.pairConstructV1
	var candidateClient *ClientAuthenticatedEndpointV1
	var candidateRelay *RelayAuthenticatedEndpointV1
	var candidateClientGeneration, candidateRelayGeneration uint64
	runtime.pairConstructV1 = func(input pairConstructionInputV1) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error) {
		client, relay, err := originalConstruct(input)
		candidateClient, candidateRelay = client, relay
		if client != nil && relay != nil {
			candidateClientGeneration, candidateRelayGeneration = client.state.life.generation, relay.state.life.generation
		}
		return client, relay, err
	}
	client, relay, err := runtime.NewAuthenticatedChannelPair(lifecyclePairInputV1(t, profileB))
	if client != nil || relay != nil || err != ErrProfileRotationRequired || err.Error() != "profile_rotation_required" {
		t.Fatalf("overflow pair=%v/%v err=%v", client, relay, err)
	}
	runtime.profileMu.Lock()
	generation, overflow, profileID, profileHash := runtime.profileGeneration, runtime.profileOverflow, runtime.profileID, runtime.profileHash
	runtime.profileMu.Unlock()
	if generation != math.MaxUint64 || !overflow || profileID != profileA.snapshot.Client.ProfileID || profileHash != profileA.snapshot.Client.ProfileHash ||
		candidateClient == nil || candidateRelay == nil || candidateClientGeneration != math.MaxUint64 || candidateRelayGeneration != math.MaxUint64 ||
		candidateClient.State() != auth.StateClosed || candidateRelay.State() != auth.StateClosed {
		t.Fatalf("overflow atomic state generation=%d overflow=%v profile=%q/%x candidate=%v/%v", generation, overflow, profileID, profileHash, candidateClient, candidateRelay)
	}
	if _, err := oldClient.state.life.beginOperationV1(1); !errors.Is(err, ErrProfileRotationRequired) || oldClient.State() != auth.StateClosed {
		t.Fatalf("overflow old pair err=%v state=%s", err, oldClient.State())
	}

	t.Run("same_profile_at_max_captures_max", func(t *testing.T) {
		profile := newLifecycleFixtureV1(t, 7336, "profile_lifetime_bound", 8, 2)
		owner := lifecycleRuntimeV1(t, profile)
		newEstablishedLifecyclePairV1(t, owner, lifecyclePairInputV1(t, profile))
		owner.profileMu.Lock()
		owner.profileGeneration = math.MaxUint64
		owner.profileSeen = true
		owner.profileID = profile.snapshot.Client.ProfileID
		owner.profileHash = profile.snapshot.Client.ProfileHash
		owner.profileOverflow = false
		owner.profileMu.Unlock()
		client, relay, err := owner.NewAuthenticatedChannelPair(lifecyclePairInputV1(t, profile))
		if err != nil || client == nil || relay == nil {
			t.Fatalf("same-profile max pair=%v/%v err=%v", client, relay, err)
		}
		if client.state.life.generation != math.MaxUint64 || relay.state.life.generation != math.MaxUint64 {
			t.Fatalf("same-profile max generations=%d/%d", client.state.life.generation, relay.state.life.generation)
		}
		client.Close()
		if generation, overflow := owner.currentProfileGenerationV1(); generation != math.MaxUint64 || overflow {
			t.Fatalf("same-profile max generation=%d overflow=%v", generation, overflow)
		}
	})

	t.Run("concurrent_distinct_overflow_never_wraps", func(t *testing.T) {
		profileA := newLifecycleFixtureV1(t, 7337, "profile_lifetime_bound", 8, 2)
		profileB := newLifecycleFixtureV1(t, 7338, "profile_lifetime_bound", 8, 2)
		profileC := newLifecycleFixtureV1(t, 7339, "profile_lifetime_bound", 8, 2)
		owner := lifecycleRuntimeV1(t, profileA, profileB, profileC)
		newEstablishedLifecyclePairV1(t, owner, lifecyclePairInputV1(t, profileA))
		owner.profileMu.Lock()
		owner.profileGeneration = math.MaxUint64
		owner.profileSeen = true
		owner.profileID = profileA.snapshot.Client.ProfileID
		owner.profileHash = profileA.snapshot.Client.ProfileHash
		owner.profileOverflow = false
		owner.profileMu.Unlock()
		inputs := []PairInputV1{lifecyclePairInputV1(t, profileB), lifecyclePairInputV1(t, profileC)}
		errorsOut := make(chan error, len(inputs))
		var wait sync.WaitGroup
		for _, input := range inputs {
			input := input
			wait.Add(1)
			go func() {
				defer wait.Done()
				client, relay, err := owner.NewAuthenticatedChannelPair(input)
				if client != nil {
					client.Close()
				}
				if relay != nil {
					relay.Close()
				}
				errorsOut <- err
			}()
		}
		wait.Wait()
		close(errorsOut)
		rotationErrors := 0
		for err := range errorsOut {
			if err == ErrProfileRotationRequired {
				rotationErrors++
			} else if err != ErrProfileIncompatible {
				t.Fatalf("concurrent overflow err=%#v", err)
			}
		}
		owner.profileMu.Lock()
		generation, overflow, profileID, profileHash := owner.profileGeneration, owner.profileOverflow, owner.profileID, owner.profileHash
		owner.profileMu.Unlock()
		if rotationErrors == 0 || generation != math.MaxUint64 || !overflow || profileID != profileA.snapshot.Client.ProfileID || profileHash != profileA.snapshot.Client.ProfileHash {
			t.Fatalf("concurrent overflow generation=%d overflow=%v profile=%q/%x", generation, overflow, profileID, profileHash)
		}
	})
}

func TestRestartDestroysOldPairAndCreatesFreshRuntimeV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7340, "session_only", 8, 2)
	runtime := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	client, relay := newEstablishedLifecyclePairV1(t, runtime, input)
	oldEpoch := runtime.epoch
	oldTag := runtime.instanceTag
	oldReplay := runtime.replay
	oldReplayCount := handshakeReplaySeenLengthV1(t, oldReplay)
	oldCoordinator := client.state.life.coordinator
	oldTH4 := client.state.life.th4
	oldAliases := append(publicScheduleAliasesV1(client.state.schedule), publicScheduleAliasesV1(relay.state.schedule)...)
	oldScheduleValues := make([][]byte, len(oldAliases))
	for index := range oldAliases {
		oldScheduleValues[index] = append([]byte(nil), oldAliases[index]...)
	}
	if _, err := client.state.life.beginOperationV1(1); err != nil {
		t.Fatal(err)
	}
	oldCopy := *client.state.life
	freshRuntime, freshClient, freshRelay, err := runtime.restartAuthenticatedChannelPairV1(client, relay, input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(freshClient.Close)
	if client.State() != auth.StateClosed || relay.State() != auth.StateClosed || !allRuntimeSlicesZeroV1(oldAliases) {
		t.Fatal("restart retained old pair state or schedules")
	}
	if handshakeReplaySeenLengthV1(t, oldReplay) != oldReplayCount {
		t.Fatal("restart mutated the retired runtime replay cache")
	}
	if freshRuntime == runtime || zeroRuntimeEpoch(freshRuntime.epoch) || freshRuntime.epoch == oldEpoch ||
		freshRuntime.self != freshRuntime || freshRuntime.instanceTag == nil || freshRuntime.instanceTag == oldTag ||
		freshRuntime.replay == oldReplay || handshakeReplaySeenLengthV1(t, freshRuntime.replay) != 1 ||
		oldCoordinator.owner != nil || oldCoordinator.ownerTag != nil || oldCoordinator.retiredProfile != (pairProfileBindingV1{}) || !oldCoordinator.restartSucceeded || oldCoordinator.restartInProgress ||
		freshClient.state.coordinator.owner != freshRuntime || freshClient.state.coordinator.ownerTag != freshRuntime.instanceTag ||
		freshClient.state.life.coordinator == oldCoordinator || freshClient.state.life.th4 == oldTH4 ||
		zeroRuntimeBytesV1(freshClient.state.schedule.ClientWriteKey) || zeroRuntimeBytesV1(freshRelay.state.schedule.ServerWriteKey) ||
		freshClient.state.life.operationSequence != 0 || freshClient.state.life.sendCompleted != 0 || len(freshClient.state.life.outstanding) != 0 ||
		freshRelay.state.life.operationSequence != 0 || freshRelay.state.life.receiveCompleted != 0 || len(freshRelay.state.life.outstanding) != 0 ||
		freshClient.State() != auth.StateEstablished || freshRelay.State() != auth.StateAuthenticating ||
		freshRuntime.pendingPairMaterialCountV1() != 0 || client.state.config != (StrictSessionConfigV1{}) || relay.state.config != (StrictSessionConfigV1{}) ||
		client.state.controls != (ClientLocalRuntimeControlsV1{}) || relay.state.controls != (RelayLocalRuntimeControlsV1{}) ||
		client.state.life.config != (StrictSessionConfigV1{}) || relay.state.life.config != (StrictSessionConfigV1{}) {
		t.Fatal("restart did not create an independent fresh authenticated pair")
	}
	freshScheduleValues := append(publicScheduleAliasesV1(freshClient.state.schedule), publicScheduleAliasesV1(freshRelay.state.schedule)...)
	for index := range freshScheduleValues {
		if len(freshScheduleValues[index]) == 0 || bytes.Equal(freshScheduleValues[index], oldScheduleValues[index]) {
			t.Fatalf("fresh schedule material %d reused retired key/nonce/exporter bytes", index)
		}
	}
	if _, err := oldCopy.beginOperationV1(1); !errors.Is(err, ErrLifecycle) || freshClient.State() != auth.StateEstablished {
		t.Fatalf("old private state import err=%v fresh=%s", err, freshClient.State())
	}
	if err := freshRelay.state.life.postAuthenticationCommitV1(); err != nil {
		t.Fatal(err)
	}
	firstReplay := freshRuntime.replay
	firstReplayCount := handshakeReplaySeenLengthV1(t, firstReplay)
	secondRuntime, secondClient, secondRelay, err := freshRuntime.restartAuthenticatedChannelPairV1(freshClient, freshRelay, input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secondClient.Close)
	if secondRuntime == freshRuntime || secondRuntime.replay == firstReplay || secondRuntime.replay == oldReplay ||
		handshakeReplaySeenLengthV1(t, firstReplay) != firstReplayCount || handshakeReplaySeenLengthV1(t, secondRuntime.replay) != 1 ||
		secondClient.state.life.th4 == freshClient.state.life.th4 || secondRelay.state.coordinator == freshRelay.state.coordinator {
		t.Fatal("successive restart did not preserve independent replay and session ownership")
	}
}

func TestRestartProfileBindingExactIDAndHashV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7345, "session_only", 8, 2)
	input := lifecyclePairInputV1(t, fixture)
	contextProbe := lifecycleRuntimeV1(t, fixture)
	result, context, err := contextProbe.strictFirstContactWithContextV1(input.FirstContactInput)
	if err != nil {
		t.Fatal(err)
	}
	wipeRuntimeBytesV1(result.ChannelSecret)
	clientConfig := input.ClientConfig.value
	relayConfig := input.RelayConfig.value
	want, ok := authenticatedPairProfileBindingV1(context, clientConfig, relayConfig)
	if !ok {
		t.Fatal("valid authenticated profile binding was rejected")
	}
	for _, test := range []struct {
		name   string
		mutate func(*auth.AuthenticatedContextSnapshotV1, *StrictSessionConfigV1, *StrictSessionConfigV1)
	}{
		{name: "id_only", mutate: func(context *auth.AuthenticatedContextSnapshotV1, client, relay *StrictSessionConfigV1) {
			context.ServerConfigSourceBlock.ProfileID += "_other"
		}},
		{name: "hash_only", mutate: func(context *auth.AuthenticatedContextSnapshotV1, client, relay *StrictSessionConfigV1) {
			relay.ProfileHash[0] ^= 0x80
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutatedContext := context
			mutatedClient, mutatedRelay := clientConfig, relayConfig
			test.mutate(&mutatedContext, &mutatedClient, &mutatedRelay)
			if got, valid := authenticatedPairProfileBindingV1(mutatedContext, mutatedClient, mutatedRelay); valid || got != (pairProfileBindingV1{}) {
				t.Fatalf("mismatch accepted got=%+v valid=%v want=%+v", got, valid, want)
			}
		})
	}
}

func TestRestartCrossProfileRejectsAuthorizedCandidateAndRetriesSameProfileV1(t *testing.T) {
	for index, terminal := range []string{"live", "local_close", "fatal_close"} {
		t.Run(terminal, func(t *testing.T) {
			profileA := newLifecycleFixtureV1(t, int64(7346+index*2), "session_only", 8, 2)
			profileB := newLifecycleFixtureV1(t, int64(7347+index*2), "session_only", 8, 2)
			owner := lifecycleRuntimeV1(t, profileA, profileB)
			inputA := lifecyclePairInputV1(t, profileA)
			inputB := lifecyclePairInputV1(t, profileB)
			client, relay := newEstablishedLifecyclePairV1(t, owner, inputA)
			coordinator := client.state.coordinator
			profileABinding := pairProfileBindingV1{profileID: profileA.snapshot.Client.ProfileID, profileHash: profileA.snapshot.Client.ProfileHash}
			profileBBinding := pairProfileBindingV1{profileID: profileB.snapshot.Client.ProfileID, profileHash: profileB.snapshot.Client.ProfileHash}
			var clientDestroy, relayDestroy atomic.Int32
			installScheduleDestroyCounterV1(client.state.life, &clientDestroy)
			installScheduleDestroyCounterV1(relay.state.life, &relayDestroy)
			switch terminal {
			case "local_close":
				client.Close()
			case "fatal_close":
				if _, err := client.state.life.beginOperationV1(0); err != ErrLifecycle {
					t.Fatalf("fatal close err=%#v", err)
				}
			}
			coordinator.mu.Lock()
			bindingBefore := coordinator.retiredProfile
			coordinator.mu.Unlock()
			if bindingBefore != profileABinding {
				t.Fatalf("source binding before restart=%+v want=%+v", bindingBefore, profileABinding)
			}

			attempt := restartAttemptV1{entropy: bytes.NewReader(restartEntropyBytesV1(int64(7840 + index)))}
			fresh, freshClient, freshRelay, witness, err := attempt.restartAuthenticatedChannelPairWithEntropyV1(owner, client, relay, inputB)
			if fresh != nil || freshClient != nil || freshRelay != nil || err != ErrProfileIncompatible || err.Error() != "profile_incompatible" {
				t.Fatalf("cross-profile restart=%v/%v/%v err=%#v", fresh, freshClient, freshRelay, err)
			}
			assertRestartFailedWitnessCleanV1(t, witness, true)
			if witness.retiredProfile != profileBBinding || !witness.contextProfileValid || witness.contextProfile != profileBBinding ||
				witness.clientConfig.ProfileID != profileBBinding.profileID || witness.clientConfig.ProfileHash != profileBBinding.profileHash ||
				witness.relayConfig.ProfileID != profileBBinding.profileID || witness.relayConfig.ProfileHash != profileBBinding.profileHash {
				t.Fatalf("authorized B candidate provenance witness=%+v client=%+v relay=%+v", witness, witness.clientConfig, witness.relayConfig)
			}
			coordinator.mu.Lock()
			bindingAfterFailure, inProgress, succeeded := coordinator.retiredProfile, coordinator.restartInProgress, coordinator.restartSucceeded
			coordinator.mu.Unlock()
			if bindingAfterFailure != profileABinding || inProgress || succeeded || clientDestroy.Load() != 1 || relayDestroy.Load() != 1 {
				t.Fatalf("failed restart source binding=%+v flags=%v/%v destroy=%d/%d", bindingAfterFailure, inProgress, succeeded, clientDestroy.Load(), relayDestroy.Load())
			}

			fresh, freshClient, freshRelay, err = owner.restartAuthenticatedChannelPairV1(client, relay, inputA)
			if err != nil || fresh == nil || freshClient == nil || freshRelay == nil || clientDestroy.Load() != 1 || relayDestroy.Load() != 1 {
				t.Fatalf("same-profile retry=%v/%v/%v err=%v destroy=%d/%d", fresh, freshClient, freshRelay, err, clientDestroy.Load(), relayDestroy.Load())
			}
			t.Cleanup(freshClient.Close)
			coordinator.mu.Lock()
			cleared, committed := coordinator.retiredProfile == (pairProfileBindingV1{}), coordinator.restartSucceeded
			coordinator.mu.Unlock()
			if !cleared || !committed || freshClient.state.coordinator.retiredProfile != profileABinding {
				t.Fatalf("successful retry clear=%v committed=%v fresh_binding=%+v", cleared, committed, freshClient.state.coordinator.retiredProfile)
			}
		})
	}
}

func TestRestartSameProfileIDDifferentAuthorizedHashRejectsV1(t *testing.T) {
	const profileID = "kp_restart_same_id_distinct_hash"
	profileA := newLifecycleFixtureConfiguredV1(t, 7353, profileID, "session_only", security.NonceModeCounterXORBaseV1, 8, 2)
	profileB := newLifecycleFixtureConfiguredV1(t, 7354, profileID, "session_only", security.NonceModeCounterXORBaseV1, 8, 2)
	if profileA.snapshot.Client.ProfileHash == profileB.snapshot.Client.ProfileHash {
		t.Fatal("same-ID restart fixtures did not produce distinct valid hashes")
	}
	owner := lifecycleRuntimeV1(t, profileA, profileB)
	inputA, inputB := lifecyclePairInputV1(t, profileA), lifecyclePairInputV1(t, profileB)
	client, relay := newEstablishedLifecyclePairV1(t, owner, inputA)
	attempt := restartAttemptV1{entropy: bytes.NewReader(restartEntropyBytesV1(7353))}
	fresh, freshClient, freshRelay, witness, err := attempt.restartAuthenticatedChannelPairWithEntropyV1(owner, client, relay, inputB)
	if fresh != nil || freshClient != nil || freshRelay != nil || err != ErrProfileIncompatible {
		t.Fatalf("same-ID distinct-hash restart=%v/%v/%v err=%#v", fresh, freshClient, freshRelay, err)
	}
	assertRestartFailedWitnessCleanV1(t, witness, true)
	if !witness.contextProfileValid || witness.contextProfile.profileID != profileID || witness.retiredProfile.profileID != profileID ||
		witness.contextProfile.profileHash != profileB.snapshot.Client.ProfileHash || witness.retiredProfile.profileHash != profileB.snapshot.Client.ProfileHash {
		t.Fatalf("authorized same-ID candidate provenance=%+v/%+v", witness.contextProfile, witness.retiredProfile)
	}
	fresh, freshClient, freshRelay, err = owner.restartAuthenticatedChannelPairV1(client, relay, inputA)
	if err != nil || fresh == nil || freshClient == nil || freshRelay == nil {
		t.Fatalf("same-hash retry=%v/%v/%v err=%v", fresh, freshClient, freshRelay, err)
	}
	t.Cleanup(freshClient.Close)
}

func TestRestartRejectsWrongRuntimeOwnerV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7341, "session_only", 8, 2)
	input := lifecyclePairInputV1(t, fixture)
	owner := lifecycleRuntimeV1(t, fixture)
	other := lifecycleRuntimeV1(t, fixture)
	client, relay := newEstablishedLifecyclePairV1(t, owner, input)
	coordinator := client.state.coordinator
	var clientDestroy, relayDestroy atomic.Int32
	installScheduleDestroyCounterV1(client.state.life, &clientDestroy)
	installScheduleDestroyCounterV1(relay.state.life, &relayDestroy)
	other.epochMu.Lock()
	other.epoch = owner.epoch
	other.epochMu.Unlock()
	if !validHandshakeRuntimeIdentityV1(other) {
		t.Fatal("unrelated runtime lost its constructor identity")
	}
	originalOwnerTag := coordinator.ownerTag
	coordinator.mu.Lock()
	coordinator.ownerTag = other.instanceTag
	coordinator.mu.Unlock()
	fresh, freshClient, freshRelay, err := other.restartAuthenticatedChannelPairV1(client, relay, input)
	if fresh != nil || freshClient != nil || freshRelay != nil || err != ErrProfileIncompatible ||
		clientDestroy.Load() != 1 || relayDestroy.Load() != 1 || coordinator.owner != owner ||
		client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
		t.Fatalf("cross-owner restart=%v/%v/%v err=%v destroy=%d/%d owner=%v states=%s/%s", fresh, freshClient, freshRelay, err, clientDestroy.Load(), relayDestroy.Load(), coordinator.owner == owner, client.State(), relay.State())
	}
	coordinator.mu.Lock()
	coordinator.ownerTag = originalOwnerTag
	coordinator.mu.Unlock()
	fresh, freshClient, freshRelay, err = owner.restartAuthenticatedChannelPairV1(client, relay, input)
	if err != nil || fresh == nil || freshClient == nil || freshRelay == nil ||
		clientDestroy.Load() != 1 || relayDestroy.Load() != 1 || coordinator.owner != nil || coordinator.ownerTag != nil {
		t.Fatalf("true-owner retry=%v/%v/%v err=%v destroy=%d/%d owner=%v tag=%v", fresh, freshClient, freshRelay, err, clientDestroy.Load(), relayDestroy.Load(), coordinator.owner, coordinator.ownerTag)
	}
	t.Cleanup(freshClient.Close)
}

func TestRestartRejectsCopiedCallerRuntimeIdentityV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7344, "session_only", 8, 2)
	input := lifecyclePairInputV1(t, fixture)
	for _, test := range []struct {
		name   string
		caller func(*HandshakeRuntime) *HandshakeRuntime
	}{
		{name: "shallow_source_copy", caller: func(owner *HandshakeRuntime) *HandshakeRuntime {
			return copyHandshakeRuntimeStateWithoutLocksV1(owner)
		}},
		{name: "shallow_unrelated_pristine_copy", caller: func(owner *HandshakeRuntime) *HandshakeRuntime {
			unrelated := lifecycleRuntimeV1(t, fixture)
			copied := copyHandshakeRuntimeStateWithoutLocksV1(unrelated)
			copied.epoch = owner.epoch
			return copied
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := lifecycleRuntimeV1(t, fixture)
			client, relay := newEstablishedLifecyclePairV1(t, owner, input)
			var clientDestroy, relayDestroy atomic.Int32
			installScheduleDestroyCounterV1(client.state.life, &clientDestroy)
			installScheduleDestroyCounterV1(relay.state.life, &relayDestroy)
			caller := test.caller(owner)
			fresh, freshClient, freshRelay, err := caller.restartAuthenticatedChannelPairV1(client, relay, input)
			if fresh != nil || freshClient != nil || freshRelay != nil || err != ErrProfileIncompatible ||
				caller.self == caller || clientDestroy.Load() != 1 || relayDestroy.Load() != 1 ||
				client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
				t.Fatalf("copied caller restart=%v/%v/%v err=%v identity=%v destroy=%d/%d states=%s/%s", fresh, freshClient, freshRelay, err, caller.self == caller, clientDestroy.Load(), relayDestroy.Load(), client.State(), relay.State())
			}
		})
	}
}

func TestRestartTrustedConstructionSurfaceV1(t *testing.T) {
	if _, ok := reflect.TypeOf(HandshakeRuntime{}).FieldByName("restartFactoryV1"); ok {
		t.Fatal("HandshakeRuntime retained a restart successor factory")
	}
	_, thisFile, _, ok := gort.Caller(0)
	if !ok {
		t.Fatal("caller unavailable")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "handshake.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"restartRuntimeFactoryV1", "restartFactoryV1", "restartObserver", "restartCallback", "restartConstructor", "restartDeriver"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("restart production retained forbidden seam %q", forbidden)
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), "handshake.go", raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := make(map[string]*ast.FuncDecl)
	types := make(map[string]*ast.TypeSpec)
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			functions[function.Name.Name] = function
		}
		if general, ok := declaration.(*ast.GenDecl); ok && general.Tok == token.TYPE {
			for _, specification := range general.Specs {
				typeSpecification := specification.(*ast.TypeSpec)
				types[typeSpecification.Name.Name] = typeSpecification
			}
		}
	}
	wrapper := functions["restartAuthenticatedChannelPairV1"]
	core := functions["restartAuthenticatedChannelPairWithEntropyV1"]
	constructor := functions["newRestartHandshakeRuntimeV1"]
	if wrapper == nil || core == nil || constructor == nil {
		t.Fatal("fixed restart wrapper/core/constructor missing")
	}
	forbiddenLiveFields := map[string]bool{
		"clientDependencies": true, "serverDependencies": true,
		"clientSupport": true, "relaySupport": true,
		"clientRegistry": true, "relayRegistry": true,
	}
	ast.Inspect(constructor.Body, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || !forbiddenLiveFields[selector.Sel.Name] {
			return true
		}
		sourceSelector, ok := selector.X.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, identifierOK := sourceSelector.X.(*ast.Ident)
		if identifierOK && identifier.Name == "snapshot" && sourceSelector.Sel.Name == "source" {
			t.Fatalf("restart constructor reads live snapshot.source.%s", selector.Sel.Name)
		}
		return true
	})
	attemptType, ok := types["restartAttemptV1"].Type.(*ast.StructType)
	if !ok || len(attemptType.Fields.List) != 1 || len(attemptType.Fields.List[0].Names) != 1 || attemptType.Fields.List[0].Names[0].Name != "entropy" {
		t.Fatal("restart attempt is not a single call-scoped entropy owner")
	}
	selector, ok := attemptType.Fields.List[0].Type.(*ast.SelectorExpr)
	packageName, packageOK := selector.X.(*ast.Ident)
	if !ok || !packageOK || packageName.Name != "io" || selector.Sel.Name != "Reader" {
		t.Fatal("restart attempt dependency is not io.Reader")
	}
	for _, parameter := range core.Type.Params.List {
		ast.Inspect(parameter.Type, func(node ast.Node) bool {
			if _, forbidden := node.(*ast.FuncType); forbidden {
				t.Fatal("restart core accepts a callback or constructor")
			}
			return true
		})
	}
	hasCoreCall := false
	hasRandReader := false
	ast.Inspect(wrapper.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.CallExpr:
			if selector, ok := value.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "restartAuthenticatedChannelPairWithEntropyV1" {
				hasCoreCall = true
			}
		case *ast.SelectorExpr:
			if identifier, ok := value.X.(*ast.Ident); ok && identifier.Name == "rand" && value.Sel.Name == "Reader" {
				hasRandReader = true
			}
		}
		return true
	})
	hasTrustedConstructorCall := false
	ast.Inspect(core.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "newRestartHandshakeRuntimeV1" {
				hasTrustedConstructorCall = true
			}
		}
		return true
	})
	if !hasCoreCall || !hasRandReader || !hasTrustedConstructorCall || len(wrapper.Type.Results.List) != 4 {
		t.Fatalf("fixed restart route core=%v rand=%v constructor=%v results=%d", hasCoreCall, hasRandReader, hasTrustedConstructorCall, len(wrapper.Type.Results.List))
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || !ast.IsExported(function.Name.Name) || function.Type.Results == nil {
			continue
		}
		ast.Inspect(function.Type.Results, func(node ast.Node) bool {
			if identifier, ok := node.(*ast.Ident); ok && identifier.Name == "restartFailedAttemptWitnessV1" {
				t.Fatalf("exported function %s leaks restart failure witness", function.Name.Name)
			}
			return true
		})
	}
}

func TestRestartConstructorUsesClaimTimeDependencySupportAndRegistrySnapshotV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7348, "session_only", 8, 2)
	owner := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	client, relay := newEstablishedLifecyclePairV1(t, owner, input)
	snapshot, err := owner.claimAuthenticatedPairRestartV1(client, relay)
	if err != nil {
		t.Fatal(err)
	}
	expectedClientDependencies, expectedRelayDependencies := snapshot.clientDependencies, snapshot.relayDependencies
	expectedClientSupport, expectedRelaySupport := snapshot.clientSupport.clone(), snapshot.relaySupport.clone()
	expectedClientRegistry, expectedRelayRegistry := snapshot.clientRegistry.clone(), snapshot.relayRegistry.clone()
	originalClientDependencies, originalRelayDependencies := owner.clientDependencies, owner.serverDependencies
	originalClientSupport, originalRelaySupport := owner.clientSupport.clone(), owner.relaySupport.clone()
	originalClientRegistry, originalRelayRegistry := owner.clientRegistry.clone(), owner.relayRegistry.clone()

	owner.clientSupport.rotationPolicies[0] = "corrupt_live_client_support"
	owner.relaySupport.rotationPolicies[0] = "corrupt_live_relay_support"
	owner.clientRegistry.entries[0].profileHash[0] ^= 0x80
	owner.relayRegistry.entries[0].profileHash[0] ^= 0x80
	replacementDependencies := runtimeDependenciesFixture(t)
	owner.clientDependencies, owner.serverDependencies = replacementDependencies.client, replacementDependencies.server
	owner.clientSupport = reviewedClientImplementationSupportV1.clone()
	owner.relaySupport = reviewedRelayImplementationSupportV1.clone()
	owner.clientRegistry = strictSupportFixtureV1{}.clientRegistry
	owner.relayRegistry = strictSupportFixtureV1{}.relayRegistry

	attempt := restartAttemptV1{entropy: bytes.NewReader(restartEntropyBytesV1(7348))}
	fresh, err := attempt.newRestartHandshakeRuntimeV1(snapshot)
	if err != nil || fresh == nil {
		t.Fatalf("snapshot constructor fresh=%v err=%v", fresh, err)
	}
	if !reflect.DeepEqual(fresh.clientDependencies, expectedClientDependencies) || !reflect.DeepEqual(fresh.serverDependencies, expectedRelayDependencies) ||
		!reflect.DeepEqual(fresh.clientSupport, expectedClientSupport) || !reflect.DeepEqual(fresh.relaySupport, expectedRelaySupport) ||
		!reflect.DeepEqual(fresh.clientRegistry, expectedClientRegistry) || !reflect.DeepEqual(fresh.relayRegistry, expectedRelayRegistry) ||
		fresh.pairDeriveScheduleV1 == nil || fresh.pairConstructV1 == nil {
		t.Fatal("fresh runtime did not preserve complete claim-time constructor provenance")
	}
	snapshot.clientSupport.rotationPolicies[0] = "mutated_snapshot_client_support"
	snapshot.relaySupport.rotationPolicies[0] = "mutated_snapshot_relay_support"
	snapshot.clientRegistry.entries[0].profileHash[0] ^= 0x40
	snapshot.relayRegistry.entries[0].profileHash[0] ^= 0x40
	if !reflect.DeepEqual(fresh.clientSupport, expectedClientSupport) || !reflect.DeepEqual(fresh.relaySupport, expectedRelaySupport) ||
		!reflect.DeepEqual(fresh.clientRegistry, expectedClientRegistry) || !reflect.DeepEqual(fresh.relayRegistry, expectedRelayRegistry) {
		t.Fatal("fresh runtime aliases mutable snapshot support or registries")
	}

	owner.clientDependencies, owner.serverDependencies = originalClientDependencies, originalRelayDependencies
	owner.clientSupport, owner.relaySupport = originalClientSupport, originalRelaySupport
	owner.clientRegistry, owner.relayRegistry = originalClientRegistry, originalRelayRegistry
	client.state.coordinator.mu.Lock()
	client.state.coordinator.restartInProgress = false
	client.state.coordinator.mu.Unlock()
	fresh, freshClient, freshRelay, err := owner.restartAuthenticatedChannelPairV1(client, relay, input)
	if err != nil || fresh == nil || freshClient == nil || freshRelay == nil {
		t.Fatalf("restored source retry=%v/%v/%v err=%v", fresh, freshClient, freshRelay, err)
	}
	t.Cleanup(freshClient.Close)
}

func assertRestartFailedWitnessCleanV1(t *testing.T, witness restartFailedAttemptWitnessV1, wantPair bool) {
	t.Helper()
	pending := 0
	if witness.runtime != nil {
		pending = witness.runtime.pendingPairMaterialCountV1()
	}
	if witness.runtime == nil || pending != 0 {
		t.Fatalf("failed witness runtime=%v pending=%d", witness.runtime, pending)
	}
	if !wantPair {
		if witness.client != nil || witness.relay != nil {
			t.Fatalf("unexpected failed witness endpoints=%v/%v", witness.client, witness.relay)
		}
		return
	}
	if witness.client == nil || witness.relay == nil || witness.client.State() != auth.StateClosed || witness.relay.State() != auth.StateClosed ||
		!allRuntimeSlicesZeroV1(publicScheduleAliasesV1(witness.client.state.schedule)) ||
		!allRuntimeSlicesZeroV1(publicScheduleAliasesV1(witness.relay.state.schedule)) ||
		witness.client.state.config != (StrictSessionConfigV1{}) || witness.relay.state.config != (StrictSessionConfigV1{}) ||
		witness.client.state.controls != (ClientLocalRuntimeControlsV1{}) || witness.relay.state.controls != (RelayLocalRuntimeControlsV1{}) ||
		witness.client.state.life.config != (StrictSessionConfigV1{}) || witness.relay.state.life.config != (StrictSessionConfigV1{}) ||
		witness.client.state.coordinator.retiredProfile != (pairProfileBindingV1{}) || witness.client.state.coordinator.owner != nil ||
		witness.client.state.coordinator.ownerTag != nil || !zeroRuntimeEpoch(witness.client.state.coordinator.runtimeEpoch) {
		t.Fatalf("failed witness endpoints not closed and scrubbed: %v/%v", witness.client, witness.relay)
	}
}

func TestRestartHandshakeEntropyFailureCleansUpAndRetriesV1(t *testing.T) {
	for index, test := range []struct {
		name string
		data []byte
		err  error
	}{
		{name: "reader_error", err: errors.New("injected restart entropy failure")},
		{name: "all_zero_epoch", data: make([]byte, 32)},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLifecycleFixtureV1(t, int64(7470+index), "session_only", 8, 2)
			owner := lifecycleRuntimeV1(t, fixture)
			input := lifecyclePairInputV1(t, fixture)
			client, relay := newEstablishedLifecyclePairV1(t, owner, input)
			coordinator := client.state.coordinator
			var oldClientDestroy, oldRelayDestroy atomic.Int32
			installScheduleDestroyCounterV1(client.state.life, &oldClientDestroy)
			installScheduleDestroyCounterV1(relay.state.life, &oldRelayDestroy)
			reader := &observingRestartEntropyReaderV1{
				client: client, relay: relay, clientDestroy: &oldClientDestroy, relayDestroy: &oldRelayDestroy,
				data: test.data, err: test.err,
			}
			attempt := restartAttemptV1{entropy: reader}
			fresh, freshClient, freshRelay, witness, err := attempt.restartAuthenticatedChannelPairWithEntropyV1(owner, client, relay, input)
			if fresh != nil || freshClient != nil || freshRelay != nil || !errors.Is(err, ErrSecureChannel) || reader.reads.Load() != 1 || !reader.observedClosed.Load() ||
				oldClientDestroy.Load() != 1 || oldRelayDestroy.Load() != 1 || coordinator.restartInProgress || coordinator.restartSucceeded ||
				coordinator.owner != owner || coordinator.ownerTag != owner.instanceTag {
				t.Fatalf("entropy failure=%v/%v/%v err=%v reads=%d observed=%v destroy=%d/%d flags=%v/%v", fresh, freshClient, freshRelay, err, reader.reads.Load(), reader.observedClosed.Load(), oldClientDestroy.Load(), oldRelayDestroy.Load(), coordinator.restartInProgress, coordinator.restartSucceeded)
			}
			assertRestartFailedWitnessCleanV1(t, witness, false)
			if !witness.runtime.strictEntropyFailed || witness.runtime.strictEntropy != nil || !zeroRuntimeEpoch(witness.runtime.epoch) {
				t.Fatal("failed entropy candidate retained usable entropy state")
			}
			fresh, freshClient, freshRelay, err = owner.restartAuthenticatedChannelPairV1(client, relay, input)
			if err != nil || fresh == nil || freshClient == nil || freshRelay == nil || oldClientDestroy.Load() != 1 || oldRelayDestroy.Load() != 1 {
				t.Fatalf("retry after entropy failure=%v/%v/%v err=%v destroy=%d/%d", fresh, freshClient, freshRelay, err, oldClientDestroy.Load(), oldRelayDestroy.Load())
			}
			t.Cleanup(freshClient.Close)
		})
	}
}

func TestRestartEpochCollisionCleansFailedWitnessAndRetriesV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7450, "session_only", 8, 2)
	owner := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	client, relay := newEstablishedLifecyclePairV1(t, owner, input)
	coordinator := client.state.coordinator
	retiredEpoch := owner.epoch
	var oldClientDestroy, oldRelayDestroy atomic.Int32
	installScheduleDestroyCounterV1(client.state.life, &oldClientDestroy)
	installScheduleDestroyCounterV1(relay.state.life, &oldRelayDestroy)
	attempt := restartAttemptV1{entropy: bytes.NewReader(append([]byte(nil), retiredEpoch[:]...))}
	fresh, freshClient, freshRelay, witness, err := attempt.restartAuthenticatedChannelPairWithEntropyV1(owner, client, relay, input)
	if fresh != nil || freshClient != nil || freshRelay != nil || err != ErrProfileIncompatible || witness.runtime == nil || witness.runtime.epoch != retiredEpoch ||
		oldClientDestroy.Load() != 1 || oldRelayDestroy.Load() != 1 || coordinator.restartInProgress || coordinator.restartSucceeded ||
		coordinator.owner != owner || coordinator.ownerTag != owner.instanceTag {
		t.Fatalf("epoch collision=%v/%v/%v err=%v collision=%v destroy=%d/%d flags=%v/%v", fresh, freshClient, freshRelay, err, witness.runtime != nil && witness.runtime.epoch == retiredEpoch, oldClientDestroy.Load(), oldRelayDestroy.Load(), coordinator.restartInProgress, coordinator.restartSucceeded)
	}
	assertRestartFailedWitnessCleanV1(t, witness, true)
	attempt = restartAttemptV1{entropy: bytes.NewReader(restartEntropyBytesV1(7451))}
	fresh, freshClient, freshRelay, successWitness, err := attempt.restartAuthenticatedChannelPairWithEntropyV1(owner, client, relay, input)
	if err != nil || fresh == nil || freshClient == nil || freshRelay == nil || successWitness != (restartFailedAttemptWitnessV1{}) ||
		!coordinator.restartSucceeded || coordinator.owner != nil || coordinator.ownerTag != nil {
		t.Fatalf("retry after epoch collision=%v/%v/%v witness=%+v err=%v", fresh, freshClient, freshRelay, successWitness, err)
	}
	t.Cleanup(freshClient.Close)
}

func TestRestartSourceSnapshotMutationCleansWitnessAndRetriesV1(t *testing.T) {
	for index, mutation := range []string{
		"same_tag_replay_rebind", "source_tag_only", "source_epoch_only", "invalid_self",
		"coordinator_owner_only", "coordinator_owner_tag_only", "coordinator_epoch_only", "coordinator_closed_only",
		"coordinator_restart_in_progress_only", "coordinator_restart_succeeded_only",
		"coordinator_profile_id_only", "coordinator_profile_hash_only", "coordinator_client_role_tag_only", "coordinator_relay_role_tag_only",
	} {
		t.Run(mutation, func(t *testing.T) {
			fixture := newLifecycleFixtureV1(t, int64(7480+index), "session_only", 8, 2)
			owner := lifecycleRuntimeV1(t, fixture)
			input := lifecyclePairInputV1(t, fixture)
			client, relay := newEstablishedLifecyclePairV1(t, owner, input)
			coordinator := client.state.coordinator
			originalSelf, originalTag, originalReplay, originalEpoch := owner.self, owner.instanceTag, owner.replay, owner.epoch
			originalProfile, originalClientRoleTag, originalRelayRoleTag := coordinator.retiredProfile, coordinator.clientTag, coordinator.relayTag
			var oldClientDestroy, oldRelayDestroy atomic.Int32
			installScheduleDestroyCounterV1(client.state.life, &oldClientDestroy)
			installScheduleDestroyCounterV1(relay.state.life, &oldRelayDestroy)
			reader := &mutatingRestartEntropyReaderV1{data: restartEntropyBytesV1(int64(7580 + index))}
			reader.mutate = func() {
				switch mutation {
				case "same_tag_replay_rebind":
					replacement, replayErr := auth.NewHandshakeReplayCache(handshakeReplayCapacity)
					if replayErr != nil {
						panic(replayErr)
					}
					owner.replay = replacement
					originalTag.replay = replacement
				case "source_tag_only":
					replacementTag := &runtimeInstanceTagV1{marker: 1, owner: owner, replay: owner.replay}
					owner.instanceTag = replacementTag
				case "source_epoch_only":
					var replacement [32]byte
					copy(replacement[:], restartEntropyBytesV1(7680))
					owner.epochMu.Lock()
					owner.epoch = replacement
					owner.epochMu.Unlock()
				case "invalid_self":
					owner.self = nil
				case "coordinator_owner_only":
					coordinator.mu.Lock()
					coordinator.owner = nil
					coordinator.mu.Unlock()
				case "coordinator_owner_tag_only":
					coordinator.mu.Lock()
					coordinator.ownerTag = &runtimeInstanceTagV1{marker: 1, owner: owner, replay: owner.replay}
					coordinator.mu.Unlock()
				case "coordinator_epoch_only":
					coordinator.mu.Lock()
					coordinator.runtimeEpoch[0] ^= 0x80
					coordinator.mu.Unlock()
				case "coordinator_closed_only":
					coordinator.mu.Lock()
					coordinator.closed = false
					coordinator.mu.Unlock()
				case "coordinator_restart_in_progress_only":
					coordinator.mu.Lock()
					coordinator.restartInProgress = false
					coordinator.mu.Unlock()
				case "coordinator_restart_succeeded_only":
					coordinator.mu.Lock()
					coordinator.restartSucceeded = true
					coordinator.mu.Unlock()
				case "coordinator_profile_id_only":
					coordinator.mu.Lock()
					coordinator.retiredProfile.profileID += "_mutated"
					coordinator.mu.Unlock()
				case "coordinator_profile_hash_only":
					coordinator.mu.Lock()
					coordinator.retiredProfile.profileHash[0] ^= 0x80
					coordinator.mu.Unlock()
				case "coordinator_client_role_tag_only":
					coordinator.mu.Lock()
					coordinator.clientTag = &pairRoleTagV1{marker: 1}
					coordinator.mu.Unlock()
				case "coordinator_relay_role_tag_only":
					coordinator.mu.Lock()
					coordinator.relayTag = &pairRoleTagV1{marker: 2}
					coordinator.mu.Unlock()
				}
			}
			attempt := restartAttemptV1{entropy: reader}
			fresh, freshClient, freshRelay, witness, err := attempt.restartAuthenticatedChannelPairWithEntropyV1(owner, client, relay, input)
			if fresh != nil || freshClient != nil || freshRelay != nil || err != ErrProfileIncompatible || reader.reads.Load() != 1 ||
				oldClientDestroy.Load() != 1 || oldRelayDestroy.Load() != 1 || coordinator.restartInProgress ||
				coordinator.restartSucceeded != (mutation == "coordinator_restart_succeeded_only") {
				t.Fatalf("snapshot mutation=%v/%v/%v err=%v reads=%d destroy=%d/%d flags=%v/%v", fresh, freshClient, freshRelay, err, reader.reads.Load(), oldClientDestroy.Load(), oldRelayDestroy.Load(), coordinator.restartInProgress, coordinator.restartSucceeded)
			}
			assertRestartFailedWitnessCleanV1(t, witness, true)
			owner.self = originalSelf
			owner.instanceTag = originalTag
			owner.replay = originalReplay
			originalTag.replay = originalReplay
			owner.epochMu.Lock()
			owner.epoch = originalEpoch
			owner.epochMu.Unlock()
			coordinator.mu.Lock()
			coordinator.closed = true
			coordinator.owner = owner
			coordinator.runtimeEpoch = originalEpoch
			coordinator.ownerTag = originalTag
			coordinator.retiredProfile = originalProfile
			coordinator.clientTag = originalClientRoleTag
			coordinator.relayTag = originalRelayRoleTag
			coordinator.restartInProgress = false
			coordinator.restartSucceeded = false
			coordinator.mu.Unlock()
			if !validHandshakeRuntimeIdentityV1(owner) {
				t.Fatal("source identity did not restore")
			}
			fresh, freshClient, freshRelay, err = owner.restartAuthenticatedChannelPairV1(client, relay, input)
			if err != nil || fresh == nil || freshClient == nil || freshRelay == nil || oldClientDestroy.Load() != 1 || oldRelayDestroy.Load() != 1 {
				t.Fatalf("retry after snapshot mutation=%v/%v/%v err=%v destroy=%d/%d", fresh, freshClient, freshRelay, err, oldClientDestroy.Load(), oldRelayDestroy.Load())
			}
			t.Cleanup(freshClient.Close)
		})
	}
}

func TestRestartPendingPairMaterialDrainIsIdempotentAndClaimSafeV1(t *testing.T) {
	runtime := &HandshakeRuntime{pendingPairMaterials: make(map[*pairMaterialStateV1]struct{})}
	states := make([]*pairMaterialStateV1, 0, 3)
	aliases := make([][]byte, 0, 6)
	for index := byte(1); index <= 3; index++ {
		state := &pairMaterialStateV1{
			owner: runtime, epoch: [32]byte{index}, context: auth.AuthenticatedContextSnapshotV1{TranscriptHash: [32]byte{index}},
			clientSecret: bytes.Repeat([]byte{index}, 32), relaySecret: bytes.Repeat([]byte{index + 3}, 32),
			clientTranscript: [32]byte{index}, relayTranscript: [32]byte{index},
			clientSuite: security.Suite{KDF: "kdf"}, relaySuite: security.Suite{KDF: "kdf"},
			clientConfig: StrictSessionConfigV1{ProfileID: "client"}, relayConfig: StrictSessionConfigV1{ProfileID: "relay"},
			clientControls: ClientLocalRuntimeControlsV1{RuntimeID: "client", EventCapacity: 1, QueueCeiling: 1},
			relayControls:  RelayLocalRuntimeControlsV1{RuntimeID: "relay", EventCapacity: 1, QueueCeiling: 1},
		}
		runtime.pendingPairMaterials[state] = struct{}{}
		states = append(states, state)
		aliases = append(aliases, state.clientSecret, state.relaySecret)
	}
	runtime.drainPendingPairMaterialsV1()
	if runtime.pendingPairMaterialCountV1() != 0 || !allRuntimeSlicesZeroV1(aliases) {
		t.Fatalf("drain pending=%d aliases_zero=%v", runtime.pendingPairMaterialCountV1(), allRuntimeSlicesZeroV1(aliases))
	}
	for _, state := range states {
		if state.owner != nil || !zeroRuntimeEpoch(state.epoch) || !reflect.DeepEqual(state.context, auth.AuthenticatedContextSnapshotV1{}) ||
			!zeroRuntimeEpoch(state.clientTranscript) || !zeroRuntimeEpoch(state.relayTranscript) || state.clientSuite != (security.Suite{}) || state.relaySuite != (security.Suite{}) ||
			state.clientConfig != (StrictSessionConfigV1{}) || state.relayConfig != (StrictSessionConfigV1{}) ||
			state.clientControls != (ClientLocalRuntimeControlsV1{}) || state.relayControls != (RelayLocalRuntimeControlsV1{}) {
			t.Fatal("drain retained pair material bindings")
		}
	}
	runtime.drainPendingPairMaterialsV1()

	claimed := &pairMaterialStateV1{
		owner: runtime, epoch: [32]byte{9}, clientSecret: bytes.Repeat([]byte{9}, 32), relaySecret: bytes.Repeat([]byte{10}, 32),
		clientControls: ClientLocalRuntimeControlsV1{RuntimeID: "claimed"}, relayControls: RelayLocalRuntimeControlsV1{RuntimeID: "claimed"},
	}
	claimedAliases := [][]byte{claimed.clientSecret, claimed.relaySecret}
	runtime.pairMu.Lock()
	runtime.pendingPairMaterials[claimed] = struct{}{}
	runtime.pairMu.Unlock()
	claimedReady := make(chan struct{})
	releaseClaim := make(chan struct{})
	destroyed := make(chan struct{})
	go func() {
		if !claimed.claim() {
			panic("synthetic claimed material was not claimable")
		}
		close(claimedReady)
		<-releaseClaim
		claimed.destroy()
		close(destroyed)
	}()
	<-claimedReady
	runtime.drainPendingPairMaterialsV1()
	if runtime.pendingPairMaterialCountV1() != 0 || allRuntimeSlicesZeroV1(claimedAliases) || claimed.owner != runtime {
		t.Fatal("drain stole material from its claimed consumer")
	}
	close(releaseClaim)
	<-destroyed
	if !allRuntimeSlicesZeroV1(claimedAliases) || claimed.owner != nil || !zeroRuntimeEpoch(claimed.epoch) {
		t.Fatal("claimed consumer did not scrub material through normal ownership")
	}
	claimed.destroy()
}

func TestRestartPendingPairMaterialRealSourceDrainOnFailureAndRetryV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7498, "session_only", 8, 2)
	owner := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	client, relay := newEstablishedLifecyclePairV1(t, owner, input)
	result, context, err := owner.strictFirstContactWithContextV1(input.FirstContactInput)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := owner.registerPairMaterialV1(
		context, result.ChannelSecret, input.ClientConfig.value, input.RelayConfig.value,
		input.ClientControls, input.RelayControls,
	)
	wipeRuntimeBytesV1(result.ChannelSecret)
	if err != nil || handle.state == nil || owner.pendingPairMaterialCountV1() != 1 {
		t.Fatalf("real source material handle=%+v err=%v pending=%d", handle, err, owner.pendingPairMaterialCountV1())
	}
	state := handle.state
	aliases := [][]byte{state.clientSecret, state.relaySecret}
	attempt := restartAttemptV1{entropy: failingRestartEntropyReaderV1{}}
	fresh, freshClient, freshRelay, witness, err := attempt.restartAuthenticatedChannelPairWithEntropyV1(owner, client, relay, input)
	if fresh != nil || freshClient != nil || freshRelay != nil || !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("failed restart=%v/%v/%v err=%v", fresh, freshClient, freshRelay, err)
	}
	assertRestartFailedWitnessCleanV1(t, witness, false)
	if owner.pendingPairMaterialCountV1() != 0 || !allRuntimeSlicesZeroV1(aliases) || state.owner != nil || !zeroRuntimeEpoch(state.epoch) ||
		!reflect.DeepEqual(state.context, auth.AuthenticatedContextSnapshotV1{}) || !zeroRuntimeEpoch(state.clientTranscript) ||
		!zeroRuntimeEpoch(state.relayTranscript) || state.clientSuite != (security.Suite{}) || state.relaySuite != (security.Suite{}) ||
		state.clientConfig != (StrictSessionConfigV1{}) || state.relayConfig != (StrictSessionConfigV1{}) ||
		state.clientControls != (ClientLocalRuntimeControlsV1{}) || state.relayControls != (RelayLocalRuntimeControlsV1{}) {
		t.Fatal("restart failure retained registered source pair material")
	}
	fresh, freshClient, freshRelay, err = owner.restartAuthenticatedChannelPairV1(client, relay, input)
	if err != nil || fresh == nil || freshClient == nil || freshRelay == nil || owner.pendingPairMaterialCountV1() != 0 || fresh.pendingPairMaterialCountV1() != 0 {
		t.Fatalf("retry=%v/%v/%v err=%v pending=%d/%d", fresh, freshClient, freshRelay, err, owner.pendingPairMaterialCountV1(), fresh.pendingPairMaterialCountV1())
	}
	t.Cleanup(freshClient.Close)
}

func TestRollbackCopiedLifecycleFailsTerminallyV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7342, "session_only", 8, 8)
	client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
	clientAliases := publicScheduleAliasesV1(client.state.schedule)
	relayAliases := publicScheduleAliasesV1(relay.state.schedule)
	outstandingAlias := client.state.life.outstanding
	copied := *client.state.life
	copied.outSequence = 0
	copied.operationSequence = 0
	if _, err := copied.beginOperationV1(1); !errors.Is(err, ErrLifecycle) || client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
		t.Fatalf("copied lifecycle rollback err=%v states=%s/%s", err, client.State(), relay.State())
	}
	if len(outstandingAlias) != 0 || !allRuntimeSlicesZeroV1(clientAliases) || !allRuntimeSlicesZeroV1(relayAliases) {
		t.Fatal("copied lifecycle committed state or retained schedules")
	}
}

func TestRollbackCopiedOperationOwnerFailsTerminallyV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7343, "session_only", 8, 8)
	client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
	operation, err := client.state.life.beginOperationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	copiedOwner := *client.state.life
	operation.owner = &copiedOwner
	if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); !errors.Is(err, ErrLifecycle) || relay.State() != auth.StateClosed {
		t.Fatalf("copied operation owner err=%v state=%s", err, relay.State())
	}
}

func TestLifecycleExactTransmissionProvenanceV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7350, "session_only", 16, 16)
	input := lifecyclePairInputV1(t, fixture)

	t.Run("operation_requires_sender_reservation", func(t *testing.T) {
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
		forged := operationTransmissionV1{
			owner: client.state.life, coordinator: client.state.coordinator,
			originDirection: controlDirectionClientV1, originEpoch: 0, streamSlot: 1,
			operationSequence: 0, recordEpoch: 0, recordSequence: 0, attempt: 1,
		}
		forged.operationID = operationIDV1(client.state.life.th4, forged.originDirection, forged.originEpoch, forged.streamSlot, forged.operationSequence)
		replay := relay.state.life.replay
		beforeReplay := replay.MetadataV1()
		completed := relay.state.life.completed
		if _, err := relay.state.life.commitAuthenticatedOperationV1(forged); !errors.Is(err, ErrLifecycle) {
			t.Fatalf("unreserved operation err=%v", err)
		}
		if replay.MetadataV1() != beforeReplay || len(completed) != 0 || relay.state.life.receiveCompleted != 0 || relay.state.life.inKeyAttempts != 0 {
			t.Fatal("unreserved operation committed replay, counters, or completion")
		}
	})

	t.Run("ack_requires_completed_owner_reservation", func(t *testing.T) {
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		forged := acknowledgementTransmissionV1{
			owner: relay.state.life, coordinator: client.state.coordinator,
			ack:         OperationAckV1{OperationID: operation.operationID, CompletedCount: 1},
			recordEpoch: 0, recordSequence: 0, attempt: 1,
		}
		replay := client.state.life.replay
		beforeReplay := replay.MetadataV1()
		outstanding := client.state.life.outstanding
		err = client.state.life.commitAuthenticatedOperationAckV1(forged)
		if err != ErrOperationAckInvalid || err.Error() != "operation_ack_invalid" {
			t.Fatalf("unreserved ack err=%#v", err)
		}
		if replay.MetadataV1() != beforeReplay || client.state.life.sendCompleted != 0 || client.state.life.inKeyAttempts != 0 {
			t.Fatal("unreserved ack committed replay or counters")
		}
		if _, ok := outstanding[operation.operationID]; !ok {
			t.Fatal("unreserved ack removed outstanding operation")
		}
	})
}

func TestLifecycleThreeOperationAndThreeAckTransmissionsV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7351, "session_only", 16, 16)
	client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
	operations := make([]operationTransmissionV1, 0, lifecycleTransmissionLimitV1)
	first, err := client.state.life.beginOperationV1(7)
	if err != nil {
		t.Fatal(err)
	}
	operations = append(operations, first)
	for len(operations) < lifecycleTransmissionLimitV1 {
		retry, retryErr := client.state.life.retryOperationV1(first.operationID)
		if retryErr != nil {
			t.Fatal(retryErr)
		}
		operations = append(operations, retry)
	}
	for i, transmission := range operations {
		if transmission.recordEpoch != 0 || transmission.recordSequence != uint64(i) || transmission.attempt != uint8(i+1) {
			t.Fatalf("operation transmission %d=%+v", i, transmission)
		}
		ack, commitErr := relay.state.life.commitAuthenticatedOperationV1(transmission)
		if commitErr != nil || ack.OperationID != first.operationID || ack.CompletedCount != 1 {
			t.Fatalf("operation transmission %d ack=%+v err=%v", i, ack, commitErr)
		}
	}
	acks := make([]acknowledgementTransmissionV1, 0, lifecycleTransmissionLimitV1)
	ack, err := relay.state.life.beginOperationAckV1(first.operationID)
	if err != nil {
		t.Fatal(err)
	}
	acks = append(acks, ack)
	for len(acks) < lifecycleTransmissionLimitV1 {
		retry, retryErr := relay.state.life.retryOperationAckV1(first.operationID)
		if retryErr != nil {
			t.Fatal(retryErr)
		}
		acks = append(acks, retry)
	}
	for i, transmission := range acks {
		if transmission.recordEpoch != 0 || transmission.recordSequence != uint64(i) || transmission.attempt != uint8(i+1) {
			t.Fatalf("ack transmission %d=%+v", i, transmission)
		}
		if err := client.state.life.commitAuthenticatedOperationAckV1(transmission); err != nil {
			t.Fatalf("ack transmission %d err=%v", i, err)
		}
	}
	if client.state.life.sendCompleted != 1 || relay.state.life.receiveCompleted != 1 ||
		client.state.life.outKeyAttempts != 3 || relay.state.life.inKeyAttempts != 3 ||
		relay.state.life.outKeyAttempts != 3 || client.state.life.inKeyAttempts != 3 ||
		len(client.state.life.outstanding) != 0 || len(client.state.life.issuedOperations) != 3 || len(relay.state.life.issuedAcks) != 3 {
		t.Fatalf("final operation state send=%d receive=%d key_attempts client=%d/%d relay=%d/%d outstanding=%d issued=%d/%d",
			client.state.life.sendCompleted, relay.state.life.receiveCompleted,
			client.state.life.outKeyAttempts, client.state.life.inKeyAttempts,
			relay.state.life.outKeyAttempts, relay.state.life.inKeyAttempts,
			len(client.state.life.outstanding), len(client.state.life.issuedOperations), len(relay.state.life.issuedAcks))
	}
}

func TestOperationAckExactSentinelAndFreshDuplicateNegativesV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7352, "session_only", 16, 16)
	input := lifecyclePairInputV1(t, fixture)
	for _, test := range []struct {
		name   string
		mutate func(*acknowledgementTransmissionV1)
	}{
		{name: "lower_count", mutate: func(transmission *acknowledgementTransmissionV1) { transmission.ack.CompletedCount = 0 }},
		{name: "higher_count", mutate: func(transmission *acknowledgementTransmissionV1) { transmission.ack.CompletedCount++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
			operation, err := client.state.life.beginOperationV1(1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
				t.Fatal(err)
			}
			ack, err := relay.state.life.beginOperationAckV1(operation.operationID)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&ack)
			replay := client.state.life.replay
			before := replay.MetadataV1()
			if err := client.state.life.commitAuthenticatedOperationAckV1(ack); err != ErrOperationAckInvalid || err.Error() != "operation_ack_invalid" {
				t.Fatalf("ack semantic err=%#v", err)
			}
			if replay.MetadataV1() != before || client.state.life.sendCompleted != 0 {
				t.Fatal("invalid ack committed replay or send count")
			}
		})
	}

	t.Run("altered_fresh_duplicate_after_completion", func(t *testing.T) {
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
			t.Fatal(err)
		}
		first, err := relay.state.life.beginOperationAckV1(operation.operationID)
		if err != nil {
			t.Fatal(err)
		}
		second, err := relay.state.life.retryOperationAckV1(operation.operationID)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.state.life.commitAuthenticatedOperationAckV1(first); err != nil {
			t.Fatal(err)
		}
		second.ack.CompletedCount++
		replay := client.state.life.replay
		before := replay.MetadataV1()
		acknowledged := client.state.life.acknowledged
		assertOperationAckInvalidExactV1(t, client.state.life.commitAuthenticatedOperationAckV1(second))
		if replay.MetadataV1() != before || client.state.life.sendCompleted != 0 || acknowledged[operation.operationID] != 1 {
			t.Fatal("altered duplicate changed acknowledged state")
		}
	})
}

func TestLifecycleNonceModeCompositionV1(t *testing.T) {
	modes := []string{
		security.NonceModeCounterXORBaseV1,
		security.NonceModeCounterAppendBaseV1,
		security.NonceModeDirectionalCounterV1,
		security.NonceModeStreamPartitionedCounterV1,
	}
	for index, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			fixture := newLifecycleFixtureConfiguredV1(t, int64(7360+index), "", "session_only", mode, 8, 8)
			client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
			operation, err := client.state.life.beginOperationV1(9)
			if err != nil || operation.recordEpoch != 0 || operation.recordSequence != 0 || client.state.life.nonceMode != mode || relay.state.life.nonceMode != mode {
				t.Fatalf("mode operation=%+v err=%v lifecycle=%q/%q", operation, err, client.state.life.nonceMode, relay.state.life.nonceMode)
			}
			if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
				t.Fatal(err)
			}
			ack, err := relay.state.life.beginOperationAckV1(operation.operationID)
			if err != nil || ack.recordEpoch != 0 || ack.recordSequence != 0 {
				t.Fatalf("mode ack=%+v err=%v", ack, err)
			}
			if err := client.state.life.commitAuthenticatedOperationAckV1(ack); err != nil {
				t.Fatal(err)
			}
			if mode == security.NonceModeStreamPartitionedCounterV1 {
				if client.state.life.replay != nil || relay.state.life.replay != nil || client.state.life.replayStreams[0] == nil || relay.state.life.replayStreams[9] == nil ||
					client.state.life.outStreams[9].sequence != 1 || relay.state.life.outStreams[0].sequence != 1 {
					t.Fatal("stream-partitioned state was not composed per slot")
				}
			} else if client.state.life.replay == nil || relay.state.life.replay == nil || len(client.state.life.replayStreams) != 0 || len(relay.state.life.replayStreams) != 0 {
				t.Fatal("non-stream mode did not retain the single sequence/replay domain")
			}
		})
	}
}

func TestLifecycleStreamPartitionedSlotsControlReplayAndRatchetV1(t *testing.T) {
	t.Run("application_slot_zero_rejects_before_reservation", func(t *testing.T) {
		fixture := newLifecycleFixtureConfiguredV1(t, 7368, "", "session_only", security.NonceModeStreamPartitionedCounterV1, 8, 8)
		client, _ := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		life := client.state.life
		issued, outstanding, outbound := life.issuedOperations, life.outstanding, life.outStreams
		if transmission, err := life.beginOperationV1(0); transmission != (operationTransmissionV1{}) || err != ErrLifecycle {
			t.Fatalf("slot-zero transmission=%+v err=%#v", transmission, err)
		}
		if len(issued) != 0 || len(outstanding) != 0 || len(outbound) != 0 || life.outKeyAttempts != 0 || life.operationSequence != 0 {
			t.Fatalf("slot-zero reserved issued=%d outstanding=%d outbound=%d attempts=%d operation_sequence=%d",
				len(issued), len(outstanding), len(outbound), life.outKeyAttempts, life.operationSequence)
		}
	})

	t.Run("maximum_application_slot_is_usable", func(t *testing.T) {
		fixture := newLifecycleFixtureConfiguredV1(t, 7369, "", "session_only", security.NonceModeStreamPartitionedCounterV1, 8, 8)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		operation, err := client.state.life.beginOperationV1(^uint16(0))
		if err != nil || operation.streamSlot != ^uint16(0) || operation.recordSequence != 0 {
			t.Fatalf("maximum slot operation=%+v err=%v", operation, err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil || relay.state.life.replayStreams[^uint16(0)] == nil {
			t.Fatalf("maximum slot receive err=%v streams=%v", err, relay.state.life.replayStreams)
		}
	})

	t.Run("two_app_slots_and_control_start_at_zero", func(t *testing.T) {
		fixture := newLifecycleFixtureConfiguredV1(t, 7370, "", "session_only", security.NonceModeStreamPartitionedCounterV1, 8, 8)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		first, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		second, err := client.state.life.beginOperationV1(2)
		if err != nil || first.recordSequence != 0 || second.recordSequence != 0 {
			t.Fatalf("slot sequences=%d/%d err=%v", first.recordSequence, second.recordSequence, err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(first); err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(second); err != nil {
			t.Fatal(err)
		}
		firstAck, err := relay.state.life.beginOperationAckV1(first.operationID)
		if err != nil {
			t.Fatal(err)
		}
		secondAck, err := relay.state.life.beginOperationAckV1(second.operationID)
		if err != nil || firstAck.recordSequence != 0 || secondAck.recordSequence != 1 {
			t.Fatalf("control sequences=%d/%d err=%v", firstAck.recordSequence, secondAck.recordSequence, err)
		}
		if err := client.state.life.commitAuthenticatedOperationAckV1(firstAck); err != nil {
			t.Fatal(err)
		}
		if err := client.state.life.commitAuthenticatedOperationAckV1(secondAck); err != nil {
			t.Fatal(err)
		}
		if relay.state.life.replayStreams[1].MetadataV1().SeenCount != 1 || relay.state.life.replayStreams[2].MetadataV1().SeenCount != 1 ||
			client.state.life.replayStreams[0].MetadataV1().SeenCount != 2 {
			t.Fatal("per-slot replay domains did not commit independently")
		}
	})

	t.Run("same_slot_exact_replay_rejects", func(t *testing.T) {
		fixture := newLifecycleFixtureConfiguredV1(t, 7371, "", "session_only", security.NonceModeStreamPartitionedCounterV1, 8, 8)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		operation, err := client.state.life.beginOperationV1(4)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
			t.Fatal(err)
		}
		replay := relay.state.life.replayStreams[4]
		before := replay.MetadataV1()
		completed := relay.state.life.completed
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); !errors.Is(err, ErrLifecycle) || replay.MetadataV1() != before || len(completed) != 1 || relay.state.life.receiveCompleted != 0 {
			t.Fatalf("same-slot replay err=%v replay=%+v", err, replay.MetadataV1())
		}
	})

	t.Run("ratchet_replaces_all_slot_state", func(t *testing.T) {
		fixture := newLifecycleFixtureConfiguredV1(t, 7372, "", "message_lifetime_bound", security.NonceModeStreamPartitionedCounterV1, 8, 2)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		first, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		second, err := client.state.life.beginOperationV1(2)
		if err != nil {
			t.Fatal(err)
		}
		oldOutbound := client.state.life.outStreams
		third, err := client.state.life.beginOperationV1(1)
		if err != nil || third.recordEpoch != 1 || third.recordSequence != 0 || client.state.life.outKeyAttempts != 1 || len(client.state.life.outStreams) != 1 || client.state.life.outStreams[1].sequence != 1 {
			t.Fatalf("sender ratchet third=%+v err=%v attempts=%d streams=%v", third, err, client.state.life.outKeyAttempts, client.state.life.outStreams)
		}
		if len(oldOutbound) != 2 {
			t.Fatalf("old outbound slot snapshot=%v", oldOutbound)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(first); err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(second); err != nil {
			t.Fatal(err)
		}
		oldReplay := relay.state.life.replayStreams
		if _, err := relay.state.life.commitAuthenticatedOperationV1(third); err != nil {
			t.Fatal(err)
		}
		if relay.state.life.keyEpoch != 1 || relay.state.life.inKeyAttempts != 1 || len(relay.state.life.replayStreams) != 1 || relay.state.life.replayStreams[1] == nil || len(oldReplay) != 2 {
			t.Fatalf("receiver ratchet epoch=%d attempts=%d current=%d old=%d", relay.state.life.keyEpoch, relay.state.life.inKeyAttempts, len(relay.state.life.replayStreams), len(oldReplay))
		}
	})

	t.Run("per_slot_max_sequence_ratchets_without_wrap", func(t *testing.T) {
		fixture := newLifecycleFixtureConfiguredV1(t, 7373, "", "message_lifetime_bound", security.NonceModeStreamPartitionedCounterV1, 8, 8)
		client, _ := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		const slot = uint16(65535)
		client.state.life.outStreams[slot] = outboundSequenceStateV1{sequence: math.MaxUint64}
		last, err := client.state.life.beginOperationV1(slot)
		if err != nil || last.recordEpoch != 0 || last.recordSequence != math.MaxUint64 || !client.state.life.outStreams[slot].ended {
			t.Fatalf("last per-slot record=%+v err=%v state=%+v", last, err, client.state.life.outStreams[slot])
		}
		next, err := client.state.life.beginOperationV1(slot)
		if err != nil || next.recordEpoch != 1 || next.recordSequence != 0 || next.operationSequence != last.operationSequence+1 ||
			client.state.life.outStreams[slot].ended || client.state.life.outStreams[slot].sequence != 1 {
			t.Fatalf("post-max per-slot record=%+v err=%v state=%+v", next, err, client.state.life.outStreams[slot])
		}
	})

	t.Run("current_epoch_lazy_replay_failure_does_not_attach_slot", func(t *testing.T) {
		fixture := newLifecycleFixtureConfiguredV1(t, 7374, "", "message_lifetime_bound", security.NonceModeStreamPartitionedCounterV1, 8, 8)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		operation, err := client.state.life.beginOperationV1(11)
		if err != nil {
			t.Fatal(err)
		}
		replayStreams := relay.state.life.replayStreams
		completed := relay.state.life.completed
		commitCalls := 0
		relay.state.life.commitReplay = func(*security.ReplayWindowV1, uint64) error {
			commitCalls++
			return errors.New("injected lazy replay commit failure")
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != ErrRekeyFailed {
			t.Fatalf("lazy replay commit err=%#v", err)
		}
		if _, attached := replayStreams[11]; attached || len(completed) != 0 || commitCalls != 1 || relay.state.life.inKeyAttempts != 0 || relay.state.life.receiveCompleted != 0 {
			t.Fatalf("lazy replay attached=%v completed=%d calls=%d attempts=%d receive=%d", attached, len(completed), commitCalls, relay.state.life.inKeyAttempts, relay.state.life.receiveCompleted)
		}
	})
}

func TestLifecycleSessionLimitTwoBothDirectionsV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7380, "session_only", 2, 2)
	input := lifecyclePairInputV1(t, fixture)
	for _, direction := range []string{"client_to_relay", "relay_to_client"} {
		t.Run(direction, func(t *testing.T) {
			client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
			sender, receiver := client.state.life, relay.state.life
			if direction == "relay_to_client" {
				sender, receiver = relay.state.life, client.state.life
			}
			first, err := sender.beginOperationV1(1)
			if err != nil {
				t.Fatal(err)
			}
			second, err := sender.beginOperationV1(2)
			if err != nil {
				t.Fatal(err)
			}
			if sender.sendCompleted != 0 || len(sender.outstanding) != 2 {
				t.Fatalf("admission send=%d outstanding=%d", sender.sendCompleted, len(sender.outstanding))
			}
			if _, err := receiver.commitAuthenticatedOperationV1(first); err != nil {
				t.Fatal(err)
			}
			if _, err := receiver.commitAuthenticatedOperationV1(second); err != nil {
				t.Fatal(err)
			}
			if receiver.receiveCompleted != 2 || sender.sendCompleted != 0 {
				t.Fatalf("receiver completion=%d sender completion=%d", receiver.receiveCompleted, sender.sendCompleted)
			}
			ack, err := receiver.beginOperationAckV1(first.operationID)
			if err != nil {
				t.Fatal(err)
			}
			if err := sender.commitAuthenticatedOperationAckV1(ack); err != nil || sender.sendCompleted != 1 {
				t.Fatalf("first ack err=%v send=%d", err, sender.sendCompleted)
			}
			outstanding := sender.outstanding
			if _, err := sender.beginOperationV1(3); !errors.Is(err, ErrSessionMessageLimit) || sender.sendCompleted != 0 || len(outstanding) != 1 {
				t.Fatalf("third operation err=%v send=%d", err, sender.sendCompleted)
			}
		})
	}

	for _, test := range []struct {
		name          string
		beforeReceive uint64
		wantErr       error
		wantCompleted uint64
	}{
		{name: "last_allowed", beforeReceive: 1, wantCompleted: 2},
		{name: "over_limit", beforeReceive: 2, wantErr: ErrSessionMessageLimit, wantCompleted: 2},
	} {
		for _, direction := range []string{"client_to_relay", "relay_to_client"} {
			t.Run("receiver_"+test.name+"_"+direction, func(t *testing.T) {
				client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), input)
				sender, receiver := client.state.life, relay.state.life
				if direction == "relay_to_client" {
					sender, receiver = relay.state.life, client.state.life
				}
				operation, err := sender.beginOperationV1(1)
				if err != nil {
					t.Fatal(err)
				}
				replay := receiver.replay
				beforeReplay := replay.MetadataV1()
				completed := receiver.completed
				receiver.receiveCompleted = test.beforeReceive
				_, err = receiver.commitAuthenticatedOperationV1(operation)
				if test.wantErr == nil {
					if err != nil || receiver.receiveCompleted != test.wantCompleted || replay.MetadataV1().SeenCount != beforeReplay.SeenCount+1 {
						t.Fatalf("last receive err=%v completed=%d replay=%+v", err, receiver.receiveCompleted, replay.MetadataV1())
					}
				} else if !errors.Is(err, test.wantErr) || receiver.receiveCompleted != 0 || replay.MetadataV1() != beforeReplay || len(completed) != 0 {
					t.Fatalf("over receive err=%v completed=%d replay=%+v", err, receiver.receiveCompleted, replay.MetadataV1())
				}
			})
		}
	}
}

func TestLifecycleKeyAttemptDirectionAndAckAccountingV1(t *testing.T) {
	t.Run("directions_are_independent", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7381, "session_only", 8, 1)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
			t.Fatal(err)
		}
		ack, err := relay.state.life.beginOperationAckV1(operation.operationID)
		if err != nil || ack.recordSequence != 0 {
			t.Fatalf("ack reservation=%+v err=%v", ack, err)
		}
		if err := client.state.life.commitAuthenticatedOperationAckV1(ack); err != nil {
			t.Fatal(err)
		}
		if client.state.life.outKeyAttempts != 1 || client.state.life.inKeyAttempts != 1 ||
			relay.state.life.outKeyAttempts != 1 || relay.state.life.inKeyAttempts != 1 {
			t.Fatalf("direction attempts client=%d/%d relay=%d/%d", client.state.life.outKeyAttempts, client.state.life.inKeyAttempts, relay.state.life.outKeyAttempts, relay.state.life.inKeyAttempts)
		}
	})

	t.Run("stream_slots_share_key_attempt_limit", func(t *testing.T) {
		fixture := newLifecycleFixtureConfiguredV1(t, 7382, "", "message_lifetime_bound", security.NonceModeStreamPartitionedCounterV1, 8, 2)
		client, _ := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		first, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		second, err := client.state.life.beginOperationV1(2)
		if err != nil || first.recordSequence != 0 || second.recordSequence != 0 || client.state.life.outKeyAttempts != 2 {
			t.Fatalf("first epoch attempts=%d records=%+v/%+v err=%v", client.state.life.outKeyAttempts, first, second, err)
		}
		third, err := client.state.life.beginOperationV1(3)
		if err != nil || third.recordEpoch != 1 || third.recordSequence != 0 || client.state.life.outKeyAttempts != 1 {
			t.Fatalf("cross-slot ratchet=%+v attempts=%d err=%v", third, client.state.life.outKeyAttempts, err)
		}
	})
}

func TestLifecycleInboundOperationSequenceNoWrapV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7383, "session_only", 8, 8)
	client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
	client.state.life.operationSequence = math.MaxUint64
	relay.state.life.inOperationSequence = math.MaxUint64
	last, err := client.state.life.beginOperationV1(1)
	if err != nil || last.operationSequence != math.MaxUint64 {
		t.Fatalf("last operation=%+v err=%v", last, err)
	}
	if _, err := relay.state.life.commitAuthenticatedOperationV1(last); err != nil || !relay.state.life.inOperationSequenceEnd {
		t.Fatalf("last receive err=%v end=%v", err, relay.state.life.inOperationSequenceEnd)
	}
	client.state.life.operationSequence = 0
	client.state.life.operationSequenceEnd = false
	wrapped, err := client.state.life.beginOperationV1(2)
	if err != nil {
		t.Fatal(err)
	}
	completed := relay.state.life.completed
	replay := relay.state.life.replay
	beforeReplay := replay.MetadataV1()
	if _, err := relay.state.life.commitAuthenticatedOperationV1(wrapped); !errors.Is(err, ErrLifecycle) || relay.state.life.receiveCompleted != 0 || len(completed) != 1 || replay.MetadataV1() != beforeReplay {
		t.Fatalf("wrapped receive err=%v completed=%d", err, relay.state.life.receiveCompleted)
	}
}

func installScheduleDestroyCounterV1(life *endpointLifecycleV1, counter *atomic.Int32) {
	life.destroySchedule = func(schedule *security.KeySchedule) {
		counter.Add(1)
		schedule.Destroy()
	}
}

func TestLifecycleScheduleDestroyExactOnceAcrossConcurrentTerminalCallsV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7390, "session_only", 8, 8)
	client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
	var clientDestroy, relayDestroy atomic.Int32
	installScheduleDestroyCounterV1(client.state.life, &clientDestroy)
	installScheduleDestroyCounterV1(relay.state.life, &relayDestroy)
	copied := *client.state.life
	var originalFatal, copiedFatal atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 96; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			switch index % 4 {
			case 0:
				client.Close()
			case 1:
				relay.Close()
			case 2:
				if _, err := client.state.life.beginOperationV1(0); err != nil {
					originalFatal.Add(1)
				}
			case 3:
				if _, err := copied.beginOperationV1(0); err != nil {
					copiedFatal.Add(1)
				}
			}
		}(index)
	}
	wait.Wait()
	if clientDestroy.Load() != 1 || relayDestroy.Load() != 1 || originalFatal.Load() == 0 || copiedFatal.Load() == 0 ||
		client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
		t.Fatalf("destroy client=%d relay=%d fatal=%d/%d states=%s/%s", clientDestroy.Load(), relayDestroy.Load(), originalFatal.Load(), copiedFatal.Load(), client.State(), relay.State())
	}
}

func TestRestartOrderingFailureAndSafeRetryV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7391, "session_only", 8, 2)
	runtime := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	client, relay := newEstablishedLifecyclePairV1(t, runtime, input)
	var clientDestroy, relayDestroy atomic.Int32
	installScheduleDestroyCounterV1(client.state.life, &clientDestroy)
	installScheduleDestroyCounterV1(relay.state.life, &relayDestroy)
	injected := errors.New("injected restart entropy failure")
	reader := &observingRestartEntropyReaderV1{
		client: client, relay: relay, clientDestroy: &clientDestroy, relayDestroy: &relayDestroy, err: injected,
	}
	attempt := restartAttemptV1{entropy: reader}
	fresh, freshClient, freshRelay, witness, err := attempt.restartAuthenticatedChannelPairWithEntropyV1(runtime, client, relay, input)
	if fresh != nil || freshClient != nil || freshRelay != nil || !errors.Is(err, ErrSecureChannel) || reader.reads.Load() != 1 || !reader.observedClosed.Load() ||
		client.State() != auth.StateClosed || relay.State() != auth.StateClosed || client.state.coordinator.restartInProgress {
		t.Fatalf("failed restart=%v/%v/%v err=%v reads=%d observed=%v in_progress=%v", fresh, freshClient, freshRelay, err, reader.reads.Load(), reader.observedClosed.Load(), client.state.coordinator.restartInProgress)
	}
	assertRestartFailedWitnessCleanV1(t, witness, false)
	fresh, freshClient, freshRelay, err = runtime.restartAuthenticatedChannelPairV1(client, relay, input)
	if err != nil || fresh == nil || freshClient == nil || freshRelay == nil || !client.state.coordinator.restartSucceeded {
		t.Fatalf("safe retry=%v/%v/%v err=%v", fresh, freshClient, freshRelay, err)
	}
	t.Cleanup(freshClient.Close)
}

func TestRestartFreshHandshakeFailureLeavesTerminalAndRetryableV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7392, "session_only", 8, 2)
	runtime := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	client, relay := newEstablishedLifecyclePairV1(t, runtime, input)
	bad := input
	bad.ClientControls.RuntimeID = ""
	fresh, freshClient, freshRelay, err := runtime.restartAuthenticatedChannelPairV1(client, relay, bad)
	if fresh != nil || freshClient != nil || freshRelay != nil || !errors.Is(err, ErrConfigInvalid) ||
		client.State() != auth.StateClosed || relay.State() != auth.StateClosed || client.state.coordinator.restartInProgress || client.state.coordinator.restartSucceeded {
		t.Fatalf("failed fresh handshake=%v/%v/%v err=%v flags=%v/%v", fresh, freshClient, freshRelay, err, client.state.coordinator.restartInProgress, client.state.coordinator.restartSucceeded)
	}
	fresh, freshClient, freshRelay, err = runtime.restartAuthenticatedChannelPairV1(client, relay, input)
	if err != nil || fresh == nil || freshClient == nil || freshRelay == nil {
		t.Fatalf("retry after fresh handshake failure=%v/%v/%v err=%v", fresh, freshClient, freshRelay, err)
	}
	t.Cleanup(freshClient.Close)
}

func TestRestartConstructionAloneAndSessionExhaustionV1(t *testing.T) {
	t.Run("mere_runtime_construction_keeps_old_live", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7393, "session_only", 8, 2)
		runtime := lifecycleRuntimeV1(t, fixture)
		client, relay := newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, fixture))
		snapshot := restartSourceSnapshotV1{
			source: runtime, tag: runtime.instanceTag, replay: runtime.replay, retiredEpoch: runtime.epoch,
			retiredProfile: client.state.coordinator.retiredProfile, coordinator: client.state.coordinator,
			clientDependencies: runtime.clientDependencies, relayDependencies: runtime.serverDependencies,
			clientSupport: runtime.clientSupport.clone(), relaySupport: runtime.relaySupport.clone(),
			clientRegistry: runtime.clientRegistry.clone(), relayRegistry: runtime.relayRegistry.clone(),
		}
		attempt := restartAttemptV1{entropy: bytes.NewReader(restartEntropyBytesV1(7393))}
		fresh, err := attempt.newRestartHandshakeRuntimeV1(snapshot)
		if err != nil || fresh == nil || fresh == runtime || client.State() != auth.StateEstablished || relay.State() != auth.StateEstablished {
			t.Fatalf("construction fresh=%v err=%v old=%s/%s", fresh, err, client.State(), relay.State())
		}
	})

	t.Run("session_key_exhaustion_can_restart", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7394, "session_only", 8, 1)
		runtime := lifecycleRuntimeV1(t, fixture)
		input := lifecyclePairInputV1(t, fixture)
		client, relay := newEstablishedLifecyclePairV1(t, runtime, input)
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.state.life.retryOperationV1(operation.operationID); !errors.Is(err, ErrKeyLifetimeExhausted) || client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
			t.Fatalf("exhaustion err=%v states=%s/%s", err, client.State(), relay.State())
		}
		fresh, freshClient, freshRelay, err := runtime.restartAuthenticatedChannelPairV1(client, relay, input)
		if err != nil || fresh == nil || freshClient == nil || freshRelay == nil {
			t.Fatalf("terminal restart=%v/%v/%v err=%v", fresh, freshClient, freshRelay, err)
		}
		t.Cleanup(freshClient.Close)
	})

	for _, terminal := range []string{"local_close", "fatal_close"} {
		t.Run(terminal+"_can_restart", func(t *testing.T) {
			fixture := newLifecycleFixtureV1(t, 7397+int64(len(terminal)), "session_only", 8, 2)
			runtime := lifecycleRuntimeV1(t, fixture)
			input := lifecyclePairInputV1(t, fixture)
			client, relay := newEstablishedLifecyclePairV1(t, runtime, input)
			if terminal == "local_close" {
				client.Close()
			} else if _, err := client.state.life.beginOperationV1(0); !errors.Is(err, ErrLifecycle) {
				t.Fatalf("fatal close err=%v", err)
			}
			if client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
				t.Fatalf("terminal states=%s/%s", client.State(), relay.State())
			}
			fresh, freshClient, freshRelay, err := runtime.restartAuthenticatedChannelPairV1(client, relay, input)
			if err != nil || fresh == nil || freshClient == nil || freshRelay == nil {
				t.Fatalf("%s restart=%v/%v/%v err=%v", terminal, fresh, freshClient, freshRelay, err)
			}
			t.Cleanup(freshClient.Close)
		})
	}
}

func TestRestartConcurrentSingleWinnerV1(t *testing.T) {
	for iteration := 0; iteration < 4; iteration++ {
		fixture := newLifecycleFixtureV1(t, int64(7395+iteration), "session_only", 8, 2)
		runtime := lifecycleRuntimeV1(t, fixture)
		input := lifecyclePairInputV1(t, fixture)
		client, relay := newEstablishedLifecyclePairV1(t, runtime, input)
		var clientDestroy, relayDestroy atomic.Int32
		installScheduleDestroyCounterV1(client.state.life, &clientDestroy)
		installScheduleDestroyCounterV1(relay.state.life, &relayDestroy)
		reader := &blockingRestartEntropyReaderV1{
			data: restartEntropyBytesV1(int64(7790 + iteration)), entered: make(chan struct{}), release: make(chan struct{}),
		}
		type result struct {
			runtime *HandshakeRuntime
			client  *ClientAuthenticatedEndpointV1
			relay   *RelayAuthenticatedEndpointV1
			witness restartFailedAttemptWitnessV1
			err     error
		}
		results := make(chan result, 16)
		go func() {
			attempt := restartAttemptV1{entropy: reader}
			fresh, freshClient, freshRelay, witness, err := attempt.restartAuthenticatedChannelPairWithEntropyV1(runtime, client, relay, input)
			results <- result{runtime: fresh, client: freshClient, relay: freshRelay, witness: witness, err: err}
		}()
		<-reader.entered
		if reader.reads.Load() != 1 || clientDestroy.Load() != 1 || relayDestroy.Load() != 1 {
			t.Fatalf("iteration %d entered reads=%d destroy=%d/%d", iteration, reader.reads.Load(), clientDestroy.Load(), relayDestroy.Load())
		}
		for index := 0; index < 15; index++ {
			go func(index int) {
				if (index+iteration)%3 == 0 {
					gort.Gosched()
				}
				attempt := restartAttemptV1{entropy: reader}
				fresh, freshClient, freshRelay, witness, err := attempt.restartAuthenticatedChannelPairWithEntropyV1(runtime, client, relay, input)
				results <- result{runtime: fresh, client: freshClient, relay: freshRelay, witness: witness, err: err}
			}(index)
		}
		for index := 0; index < 15; index++ {
			got := <-results
			if got.runtime != nil || got.client != nil || got.relay != nil || got.witness != (restartFailedAttemptWitnessV1{}) || got.err != ErrProfileIncompatible {
				t.Fatalf("iteration %d concurrent loser=%v/%v/%v witness=%+v err=%v", iteration, got.runtime, got.client, got.relay, got.witness, got.err)
			}
		}
		if reader.reads.Load() != 1 {
			t.Fatalf("iteration %d loser reached entropy reads=%d", iteration, reader.reads.Load())
		}
		close(reader.release)
		winner := <-results
		if winner.err != nil || winner.runtime == nil || winner.client == nil || winner.relay == nil || winner.witness != (restartFailedAttemptWitnessV1{}) ||
			reader.reads.Load() != 1 || clientDestroy.Load() != 1 || relayDestroy.Load() != 1 {
			t.Fatalf("iteration %d winner=%v/%v/%v witness=%+v err=%v reads=%d destroy=%d/%d", iteration, winner.runtime, winner.client, winner.relay, winner.witness, winner.err, reader.reads.Load(), clientDestroy.Load(), relayDestroy.Load())
		}
		t.Cleanup(winner.client.Close)
		if fresh, freshClient, freshRelay, err := runtime.restartAuthenticatedChannelPairV1(client, relay, input); fresh != nil || freshClient != nil || freshRelay != nil || err != ErrProfileIncompatible {
			t.Fatalf("iteration %d post-success duplicate=%v/%v/%v err=%v", iteration, fresh, freshClient, freshRelay, err)
		}
	}
}

func TestRestartMixedPairRejectsAndClosesBothPairsV1(t *testing.T) {
	fixture := newLifecycleFixtureV1(t, 7396, "session_only", 8, 2)
	runtime := lifecycleRuntimeV1(t, fixture)
	input := lifecyclePairInputV1(t, fixture)
	clientA, relayA := newEstablishedLifecyclePairV1(t, runtime, input)
	clientB, relayB := newEstablishedLifecyclePairV1(t, runtime, input)
	if fresh, freshClient, freshRelay, err := runtime.restartAuthenticatedChannelPairV1(clientA, relayB, input); fresh != nil || freshClient != nil || freshRelay != nil || !errors.Is(err, ErrProfileIncompatible) {
		t.Fatalf("mixed restart=%v/%v/%v err=%v", fresh, freshClient, freshRelay, err)
	}
	if clientA.State() != auth.StateClosed || relayA.State() != auth.StateClosed || clientB.State() != auth.StateClosed || relayB.State() != auth.StateClosed {
		t.Fatalf("mixed pair states A=%s/%s B=%s/%s", clientA.State(), relayA.State(), clientB.State(), relayB.State())
	}
}

func TestRekeyRatchetFailureAndPendingReceiveCommitSnapshotsV1(t *testing.T) {
	t.Run("sender_ratchet_failure_does_not_reset_or_reserve", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7400, "message_lifetime_bound", 8, 1)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		var clientDestroy, relayDestroy atomic.Int32
		installScheduleDestroyCounterV1(client.state.life, &clientDestroy)
		installScheduleDestroyCounterV1(relay.state.life, &relayDestroy)
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		replay := client.state.life.replay
		beforeReplay := replay.MetadataV1()
		issued := client.state.life.issuedOperations
		client.state.schedule.ExporterSecret = nil
		if _, err := client.state.life.retryOperationV1(operation.operationID); !errors.Is(err, ErrRekeyFailed) {
			t.Fatalf("ratchet failure err=%v", err)
		}
		if client.state.life.keyEpoch != 0 || client.state.life.outSequence != 0 || client.state.life.outKeyAttempts != 0 ||
			issued[operationReservationKeyV1(operation)].attempt != 1 || len(issued) != 1 || replay.MetadataV1() != beforeReplay {
			t.Fatalf("ratchet failure mutated epoch=%d sequence=%d attempts=%d issued=%d replay=%+v", client.state.life.keyEpoch, client.state.life.outSequence, client.state.life.outKeyAttempts, len(issued), replay.MetadataV1())
		}
		if clientDestroy.Load() != 1 || relayDestroy.Load() != 1 {
			t.Fatalf("ratchet destroy calls client=%d relay=%d", clientDestroy.Load(), relayDestroy.Load())
		}
	})

	t.Run("pending_receive_replay_commit_failure_does_not_install", func(t *testing.T) {
		fixture := newLifecycleFixtureV1(t, 7401, "message_lifetime_bound", 8, 1)
		client, relay := newEstablishedLifecyclePairV1(t, lifecycleRuntimeV1(t, fixture), lifecyclePairInputV1(t, fixture))
		var clientDestroy, relayDestroy atomic.Int32
		installScheduleDestroyCounterV1(client.state.life, &clientDestroy)
		installScheduleDestroyCounterV1(relay.state.life, &relayDestroy)
		first, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		next, err := client.state.life.retryOperationV1(first.operationID)
		if err != nil || next.recordEpoch != 1 {
			t.Fatalf("next epoch=%+v err=%v", next, err)
		}
		replay := relay.state.life.replay
		beforeReplay := replay.MetadataV1()
		completed := relay.state.life.completed
		relay.state.life.commitReplay = func(*security.ReplayWindowV1, uint64) error {
			return errors.New("injected replay commit failure")
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(next); !errors.Is(err, ErrRekeyFailed) {
			t.Fatalf("pending receive err=%v", err)
		}
		if relay.state.life.keyEpoch != 0 || relay.state.life.inKeyAttempts != 0 || relay.state.life.receiveCompleted != 0 || len(completed) != 0 || replay.MetadataV1() != beforeReplay {
			t.Fatalf("pending receive installed epoch=%d attempts=%d completed=%d replay=%+v", relay.state.life.keyEpoch, relay.state.life.inKeyAttempts, relay.state.life.receiveCompleted, replay.MetadataV1())
		}
		if relayDestroy.Load() != 2 || clientDestroy.Load() != 2 {
			t.Fatalf("pending destroy calls client=%d relay=%d", clientDestroy.Load(), relayDestroy.Load())
		}
	})
}

func TestProfileStaleSendOpenAndRekeyPairsV1(t *testing.T) {
	profileA := newLifecycleFixtureV1(t, 7410, "profile_lifetime_bound", 8, 1)
	profileB := newLifecycleFixtureV1(t, 7411, "profile_lifetime_bound", 8, 1)
	runtime := lifecycleRuntimeV1(t, profileA, profileB)
	inputA := lifecyclePairInputV1(t, profileA)
	sendClient, _ := newEstablishedLifecyclePairV1(t, runtime, inputA)
	openClient, openRelay := newEstablishedLifecyclePairV1(t, runtime, inputA)
	openTransmission, err := openClient.state.life.beginOperationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	rekeyClient, _ := newEstablishedLifecyclePairV1(t, runtime, inputA)
	rekeyTransmission, err := rekeyClient.state.life.beginOperationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileB))
	if current.state.life.generation != 1 {
		t.Fatalf("current generation=%d", current.state.life.generation)
	}
	if _, err := sendClient.state.life.beginOperationV1(1); !errors.Is(err, ErrProfileRotationRequired) {
		t.Fatalf("stale send err=%v", err)
	}
	if _, err := openRelay.state.life.commitAuthenticatedOperationV1(openTransmission); !errors.Is(err, ErrProfileRotationRequired) {
		t.Fatalf("stale open err=%v", err)
	}
	if _, err := rekeyClient.state.life.retryOperationV1(rekeyTransmission.operationID); !errors.Is(err, ErrProfileRotationRequired) {
		t.Fatalf("stale rekey err=%v", err)
	}
}

func TestProfileGenerationSecondCheckTOCTOUV1(t *testing.T) {
	profileA := newLifecycleFixtureV1(t, 7412, "profile_lifetime_bound", 8, 1)
	profileB := newLifecycleFixtureV1(t, 7413, "profile_lifetime_bound", 8, 1)

	t.Run("ratchet_install", func(t *testing.T) {
		runtime := lifecycleRuntimeV1(t, profileA, profileB)
		client, relay := newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileA))
		var clientDestroy, relayDestroy atomic.Int32
		installScheduleDestroyCounterV1(client.state.life, &clientDestroy)
		installScheduleDestroyCounterV1(relay.state.life, &relayDestroy)
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		replay := client.state.life.replay
		beforeReplay := replay.MetadataV1()
		client.state.life.beforeRatchetInstall = func() {
			newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileB))
		}
		if _, err := client.state.life.retryOperationV1(operation.operationID); !errors.Is(err, ErrProfileRotationRequired) {
			t.Fatalf("ratchet TOCTOU err=%v", err)
		}
		if client.state.life.keyEpoch != 0 || client.state.life.outSequence != 0 || client.state.life.outKeyAttempts != 0 || replay.MetadataV1() != beforeReplay ||
			clientDestroy.Load() != 2 || relayDestroy.Load() != 1 {
			t.Fatalf("ratchet TOCTOU mutated epoch=%d seq=%d attempts=%d replay=%+v destroy=%d/%d", client.state.life.keyEpoch, client.state.life.outSequence, client.state.life.outKeyAttempts, replay.MetadataV1(), clientDestroy.Load(), relayDestroy.Load())
		}
	})

	t.Run("receive_commit", func(t *testing.T) {
		runtime := lifecycleRuntimeV1(t, profileA, profileB)
		client, relay := newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileA))
		operation, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		replay := relay.state.life.replay
		beforeReplay := replay.MetadataV1()
		relay.state.life.beforeReceiveCommit = func() {
			newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileB))
		}
		if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); !errors.Is(err, ErrProfileRotationRequired) {
			t.Fatalf("receive TOCTOU err=%v", err)
		}
		if relay.state.life.keyEpoch != 0 || relay.state.life.inKeyAttempts != 0 || relay.state.life.receiveCompleted != 0 || replay.MetadataV1() != beforeReplay {
			t.Fatalf("receive TOCTOU mutated epoch=%d attempts=%d completed=%d replay=%+v", relay.state.life.keyEpoch, relay.state.life.inKeyAttempts, relay.state.life.receiveCompleted, replay.MetadataV1())
		}
	})

	t.Run("next_epoch_receive_pending_schedule", func(t *testing.T) {
		runtime := lifecycleRuntimeV1(t, profileA, profileB)
		client, relay := newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileA))
		first, err := client.state.life.beginOperationV1(1)
		if err != nil {
			t.Fatal(err)
		}
		next, err := client.state.life.retryOperationV1(first.operationID)
		if err != nil || next.recordEpoch != 1 {
			t.Fatalf("next-epoch operation=%+v err=%v", next, err)
		}
		replay := relay.state.life.replay
		beforeReplay := replay.MetadataV1()
		completed := relay.state.life.completed
		originalDestroy := relay.state.life.destroySchedule
		var pendingAliases [][]byte
		pendingDestroyCalls := 0
		relay.state.life.destroySchedule = func(schedule *security.KeySchedule) {
			if schedule != nil && schedule.Epoch == 1 {
				pendingDestroyCalls++
				pendingAliases = append(pendingAliases, publicScheduleAliasesV1(*schedule)...)
			}
			originalDestroy(schedule)
		}
		originalCommit := relay.state.life.commitReplay
		replayCommitCalls := 0
		relay.state.life.commitReplay = func(window *security.ReplayWindowV1, sequence uint64) error {
			replayCommitCalls++
			return originalCommit(window, sequence)
		}
		var profileBClient *ClientAuthenticatedEndpointV1
		var profileBRelay *RelayAuthenticatedEndpointV1
		var profileBErr error
		relay.state.life.beforeReceiveCommit = func() {
			profileBClient, profileBRelay, profileBErr = runtime.NewAuthenticatedChannelPair(lifecyclePairInputV1(t, profileB))
		}
		_, err = relay.state.life.commitAuthenticatedOperationV1(next)
		if err != ErrProfileRotationRequired || err.Error() != "profile_rotation_required" {
			t.Fatalf("next-epoch profile TOCTOU err=%#v", err)
		}
		if profileBErr != nil || profileBClient == nil || profileBRelay == nil {
			t.Fatalf("real profile-B pair=%v/%v err=%v", profileBClient, profileBRelay, profileBErr)
		}
		if pendingDestroyCalls != 1 || len(pendingAliases) == 0 || !allRuntimeSlicesZeroV1(pendingAliases) || replayCommitCalls != 0 ||
			relay.state.life.keyEpoch != 0 || relay.state.life.inKeyAttempts != 0 || relay.state.life.receiveCompleted != 0 ||
			len(completed) != 0 || replay.MetadataV1() != beforeReplay {
			t.Fatalf("next-epoch pending destroy=%d aliases=%d zero=%v replay_calls=%d epoch=%d attempts=%d completed=%d replay=%+v",
				pendingDestroyCalls, len(pendingAliases), allRuntimeSlicesZeroV1(pendingAliases), replayCommitCalls,
				relay.state.life.keyEpoch, relay.state.life.inKeyAttempts, relay.state.life.receiveCompleted, replay.MetadataV1())
		}
		if err := profileBRelay.state.life.postAuthenticationCommitV1(); err != nil || profileBClient.State() != auth.StateEstablished || profileBRelay.State() != auth.StateEstablished {
			t.Fatalf("profile-B pair invalid after hook states=%s/%s err=%v", profileBClient.State(), profileBRelay.State(), err)
		}
		profileBClient.Close()
	})
}

func TestProfileGenerationLifecycleCommitLinearizationV1(t *testing.T) {
	profileA := newLifecycleFixtureV1(t, 7440, "profile_lifetime_bound", 16, 1)
	profileB := newLifecycleFixtureV1(t, 7441, "profile_lifetime_bound", 16, 1)
	inputA := lifecyclePairInputV1(t, profileA)
	inputB := lifecyclePairInputV1(t, profileB)
	type scenarioV1 struct {
		name  string
		setup func(*testing.T, *HandshakeRuntime) (*endpointLifecycleV1, func() error, func(), func())
	}
	scenarios := []scenarioV1{
		{
			name: "post_auth",
			setup: func(t *testing.T, runtime *HandshakeRuntime) (*endpointLifecycleV1, func() error, func(), func()) {
				client, relay, err := runtime.NewAuthenticatedChannelPair(inputA)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(client.Close)
				return relay.state.life, relay.state.life.postAuthenticationCommitV1, func() {
						if client.State() != auth.StateEstablished || relay.State() != auth.StateEstablished {
							t.Fatalf("post-auth states=%s/%s", client.State(), relay.State())
						}
					}, func() {
						if client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
							t.Fatalf("rejected post-auth states=%s/%s", client.State(), relay.State())
						}
					}
			},
		},
		{
			name: "begin_operation",
			setup: func(t *testing.T, runtime *HandshakeRuntime) (*endpointLifecycleV1, func() error, func(), func()) {
				client, relay := newEstablishedLifecyclePairV1(t, runtime, inputA)
				life := client.state.life
				outstanding, issued := life.outstanding, life.issuedOperations
				replay, beforeReplay := life.replay, life.replay.MetadataV1()
				var transmission operationTransmissionV1
				invoke := func() error {
					var err error
					transmission, err = life.beginOperationV1(1)
					return err
				}
				return life, invoke, func() {
						if transmission.attempt != 1 || len(outstanding) != 1 || len(issued) != 1 || life.outKeyAttempts != 1 || life.operationSequence != 1 {
							t.Fatalf("begin transmission=%+v outstanding=%d issued=%d attempts=%d sequence=%d", transmission, len(outstanding), len(issued), life.outKeyAttempts, life.operationSequence)
						}
					}, func() {
						if transmission != (operationTransmissionV1{}) || len(outstanding) != 0 || len(issued) != 0 || replay.MetadataV1() != beforeReplay ||
							client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
							t.Fatalf("rejected begin transmission=%+v outstanding=%d issued=%d replay=%+v/%+v states=%s/%s", transmission, len(outstanding), len(issued), replay.MetadataV1(), beforeReplay, client.State(), relay.State())
						}
					}
			},
		},
		{
			name: "retry_operation_ratchet",
			setup: func(t *testing.T, runtime *HandshakeRuntime) (*endpointLifecycleV1, func() error, func(), func()) {
				client, relay := newEstablishedLifecyclePairV1(t, runtime, inputA)
				life := client.state.life
				first, err := life.beginOperationV1(2)
				if err != nil {
					t.Fatal(err)
				}
				entry := life.outstanding[first.operationID]
				issued := life.issuedOperations
				replay, beforeReplay := life.replay, life.replay.MetadataV1()
				originalDestroy := life.destroySchedule
				pendingCalls := 0
				var pendingAliases [][]byte
				life.destroySchedule = func(schedule *security.KeySchedule) {
					if schedule != nil && schedule.Epoch == 1 {
						pendingCalls++
						pendingAliases = append(pendingAliases, publicScheduleAliasesV1(*schedule)...)
					}
					originalDestroy(schedule)
				}
				var retry operationTransmissionV1
				invoke := func() error {
					var err error
					retry, err = life.retryOperationV1(first.operationID)
					return err
				}
				return life, invoke, func() {
						if retry.recordEpoch != 1 || retry.recordSequence != 0 || retry.attempt != 2 || entry.attempts != 2 || len(issued) != 2 || life.keyEpoch != 1 || pendingCalls != 0 {
							t.Fatalf("retry=%+v entry_attempts=%d issued=%d epoch=%d pending_destroy=%d", retry, entry.attempts, len(issued), life.keyEpoch, pendingCalls)
						}
					}, func() {
						if retry != (operationTransmissionV1{}) || entry.attempts != 1 || len(issued) != 1 || replay.MetadataV1() != beforeReplay || pendingCalls != 1 ||
							len(pendingAliases) == 0 || !allRuntimeSlicesZeroV1(pendingAliases) || client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
							t.Fatalf("rejected retry=%+v attempts=%d issued=%d replay=%+v/%+v pending=%d aliases=%d zero=%v states=%s/%s", retry, entry.attempts, len(issued), replay.MetadataV1(), beforeReplay, pendingCalls, len(pendingAliases), allRuntimeSlicesZeroV1(pendingAliases), client.State(), relay.State())
						}
					}
			},
		},
		{
			name: "commit_operation_duplicate",
			setup: func(t *testing.T, runtime *HandshakeRuntime) (*endpointLifecycleV1, func() error, func(), func()) {
				client, relay := newEstablishedLifecyclePairV1(t, runtime, inputA)
				first, err := client.state.life.beginOperationV1(3)
				if err != nil {
					t.Fatal(err)
				}
				firstAck, err := relay.state.life.commitAuthenticatedOperationV1(first)
				if err != nil {
					t.Fatal(err)
				}
				retry, err := client.state.life.retryOperationV1(first.operationID)
				if err != nil || retry.recordEpoch != 1 {
					t.Fatalf("duplicate next-epoch retry=%+v err=%v", retry, err)
				}
				life := relay.state.life
				oldReplay, beforeReplay := life.replay, life.replay.MetadataV1()
				completed := life.completed
				originalDestroy := life.destroySchedule
				pendingCalls := 0
				var pendingAliases [][]byte
				life.destroySchedule = func(schedule *security.KeySchedule) {
					if schedule != nil && schedule.Epoch == 1 {
						pendingCalls++
						pendingAliases = append(pendingAliases, publicScheduleAliasesV1(*schedule)...)
					}
					originalDestroy(schedule)
				}
				originalCommit := life.commitReplay
				replayCommits := 0
				life.commitReplay = func(window *security.ReplayWindowV1, sequence uint64) error {
					replayCommits++
					return originalCommit(window, sequence)
				}
				var ack OperationAckV1
				invoke := func() error {
					var err error
					ack, err = life.commitAuthenticatedOperationV1(retry)
					return err
				}
				return life, invoke, func() {
						if ack != firstAck || life.keyEpoch != 1 || life.replay == oldReplay || life.replay.MetadataV1().SeenCount != 1 || len(completed) != 1 || life.receiveCompleted != 1 || replayCommits != 1 || pendingCalls != 0 {
							t.Fatalf("duplicate ack=%+v/%+v epoch=%d replay_same=%v completed=%d receive=%d replay_commits=%d pending=%d", ack, firstAck, life.keyEpoch, life.replay == oldReplay, len(completed), life.receiveCompleted, replayCommits, pendingCalls)
						}
					}, func() {
						if ack != (OperationAckV1{}) || oldReplay.MetadataV1() != beforeReplay || len(completed) != 1 || replayCommits != 0 || pendingCalls != 1 ||
							len(pendingAliases) == 0 || !allRuntimeSlicesZeroV1(pendingAliases) || client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
							t.Fatalf("rejected duplicate ack=%+v replay=%+v/%+v completed=%d commits=%d pending=%d aliases=%d zero=%v states=%s/%s", ack, oldReplay.MetadataV1(), beforeReplay, len(completed), replayCommits, pendingCalls, len(pendingAliases), allRuntimeSlicesZeroV1(pendingAliases), client.State(), relay.State())
						}
					}
			},
		},
		{
			name: "commit_operation_fresh",
			setup: func(t *testing.T, runtime *HandshakeRuntime) (*endpointLifecycleV1, func() error, func(), func()) {
				client, relay := newEstablishedLifecyclePairV1(t, runtime, inputA)
				operation, err := client.state.life.beginOperationV1(4)
				if err != nil {
					t.Fatal(err)
				}
				life := relay.state.life
				replay, beforeReplay := life.replay, life.replay.MetadataV1()
				completed := life.completed
				originalCommit := life.commitReplay
				replayCommits := 0
				life.commitReplay = func(window *security.ReplayWindowV1, sequence uint64) error {
					replayCommits++
					return originalCommit(window, sequence)
				}
				var ack OperationAckV1
				invoke := func() error {
					var err error
					ack, err = life.commitAuthenticatedOperationV1(operation)
					return err
				}
				return life, invoke, func() {
						if ack.CompletedCount != 1 || replay.MetadataV1().SeenCount != beforeReplay.SeenCount+1 || len(completed) != 1 || life.receiveCompleted != 1 || life.inOperationSequence != 1 || replayCommits != 1 {
							t.Fatalf("fresh ack=%+v replay=%+v/%+v completed=%d receive=%d sequence=%d commits=%d", ack, replay.MetadataV1(), beforeReplay, len(completed), life.receiveCompleted, life.inOperationSequence, replayCommits)
						}
					}, func() {
						if ack != (OperationAckV1{}) || replay.MetadataV1() != beforeReplay || len(completed) != 0 || replayCommits != 0 ||
							client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
							t.Fatalf("rejected fresh ack=%+v replay=%+v/%+v completed=%d commits=%d states=%s/%s", ack, replay.MetadataV1(), beforeReplay, len(completed), replayCommits, client.State(), relay.State())
						}
					}
			},
		},
		{
			name: "reserve_ack_retry",
			setup: func(t *testing.T, runtime *HandshakeRuntime) (*endpointLifecycleV1, func() error, func(), func()) {
				client, relay := newEstablishedLifecyclePairV1(t, runtime, inputA)
				operation, err := client.state.life.beginOperationV1(5)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
					t.Fatal(err)
				}
				life := relay.state.life
				if _, err := life.beginOperationAckV1(operation.operationID); err != nil {
					t.Fatal(err)
				}
				completed := life.completed[operation.operationID]
				issued := life.issuedAcks
				originalDestroy := life.destroySchedule
				pendingCalls := 0
				var pendingAliases [][]byte
				life.destroySchedule = func(schedule *security.KeySchedule) {
					if schedule != nil && schedule.Epoch == 1 {
						pendingCalls++
						pendingAliases = append(pendingAliases, publicScheduleAliasesV1(*schedule)...)
					}
					originalDestroy(schedule)
				}
				var ack acknowledgementTransmissionV1
				invoke := func() error {
					var err error
					ack, err = life.retryOperationAckV1(operation.operationID)
					return err
				}
				return life, invoke, func() {
						if ack.recordEpoch != 1 || ack.attempt != 2 || completed.ackAttempts != 2 || len(issued) != 2 || life.keyEpoch != 1 || pendingCalls != 0 {
							t.Fatalf("ack retry=%+v attempts=%d issued=%d epoch=%d pending=%d", ack, completed.ackAttempts, len(issued), life.keyEpoch, pendingCalls)
						}
					}, func() {
						if ack != (acknowledgementTransmissionV1{}) || completed.ackAttempts != 1 || len(issued) != 1 || pendingCalls != 1 ||
							len(pendingAliases) == 0 || !allRuntimeSlicesZeroV1(pendingAliases) || client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
							t.Fatalf("rejected ack retry=%+v attempts=%d issued=%d pending=%d aliases=%d zero=%v states=%s/%s", ack, completed.ackAttempts, len(issued), pendingCalls, len(pendingAliases), allRuntimeSlicesZeroV1(pendingAliases), client.State(), relay.State())
						}
					}
			},
		},
		{
			name: "commit_ack",
			setup: func(t *testing.T, runtime *HandshakeRuntime) (*endpointLifecycleV1, func() error, func(), func()) {
				client, relay := newEstablishedLifecyclePairV1(t, runtime, inputA)
				operation, err := client.state.life.beginOperationV1(6)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := relay.state.life.commitAuthenticatedOperationV1(operation); err != nil {
					t.Fatal(err)
				}
				if _, err := relay.state.life.beginOperationAckV1(operation.operationID); err != nil {
					t.Fatal(err)
				}
				ack, err := relay.state.life.retryOperationAckV1(operation.operationID)
				if err != nil {
					t.Fatal(err)
				}
				if ack.recordEpoch != 1 {
					t.Fatalf("ack next-epoch setup=%+v", ack)
				}
				life := client.state.life
				oldReplay, beforeReplay := life.replay, life.replay.MetadataV1()
				outstanding, acknowledged := life.outstanding, life.acknowledged
				originalDestroy := life.destroySchedule
				pendingCalls := 0
				var pendingAliases [][]byte
				life.destroySchedule = func(schedule *security.KeySchedule) {
					if schedule != nil && schedule.Epoch == 1 {
						pendingCalls++
						pendingAliases = append(pendingAliases, publicScheduleAliasesV1(*schedule)...)
					}
					originalDestroy(schedule)
				}
				originalCommit := life.commitReplay
				replayCommits := 0
				life.commitReplay = func(window *security.ReplayWindowV1, sequence uint64) error {
					replayCommits++
					return originalCommit(window, sequence)
				}
				invoke := func() error { return life.commitAuthenticatedOperationAckV1(ack) }
				return life, invoke, func() {
						if life.keyEpoch != 1 || life.replay == oldReplay || life.replay.MetadataV1().SeenCount != 1 || len(outstanding) != 0 ||
							acknowledged[operation.operationID] != 1 || life.sendCompleted != 1 || replayCommits != 1 || pendingCalls != 0 {
							t.Fatalf("ack commit epoch=%d replay_same=%v replay=%+v outstanding=%d acknowledged=%v send=%d commits=%d pending=%d", life.keyEpoch, life.replay == oldReplay, life.replay.MetadataV1(), len(outstanding), acknowledged, life.sendCompleted, replayCommits, pendingCalls)
						}
					}, func() {
						if oldReplay.MetadataV1() != beforeReplay || len(outstanding) != 1 || len(acknowledged) != 0 || replayCommits != 0 || pendingCalls != 1 ||
							len(pendingAliases) == 0 || !allRuntimeSlicesZeroV1(pendingAliases) || client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
							t.Fatalf("rejected ack commit replay=%+v/%+v outstanding=%d acknowledged=%v commits=%d pending=%d aliases=%d zero=%v states=%s/%s", oldReplay.MetadataV1(), beforeReplay, len(outstanding), acknowledged, replayCommits, pendingCalls, len(pendingAliases), allRuntimeSlicesZeroV1(pendingAliases), client.State(), relay.State())
						}
					}
			},
		},
	}
	assertProfileRotation := func(t *testing.T, err error) {
		t.Helper()
		if err != ErrProfileRotationRequired || err.Error() != "profile_rotation_required" {
			t.Fatalf("profile-linearization err=%#v", err)
		}
	}
	type pairResultV1 struct {
		client *ClientAuthenticatedEndpointV1
		relay  *RelayAuthenticatedEndpointV1
		err    error
	}
	type lifecycleCommitSnapshotV1 struct {
		state                                                          auth.State
		keyEpoch, outSequence, operationSequence, inOperationSequence  uint64
		outKeyAttempts, inKeyAttempts, sendCompleted, receiveCompleted uint64
		outSequenceEnd, operationSequenceEnd, inOperationSequenceEnd   bool
	}
	snapshotLifecycle := func(life *endpointLifecycleV1) lifecycleCommitSnapshotV1 {
		return lifecycleCommitSnapshotV1{
			state: life.state, keyEpoch: life.keyEpoch, outSequence: life.outSequence,
			operationSequence: life.operationSequence, inOperationSequence: life.inOperationSequence,
			outKeyAttempts: life.outKeyAttempts, inKeyAttempts: life.inKeyAttempts,
			sendCompleted: life.sendCompleted, receiveCompleted: life.receiveCompleted,
			outSequenceEnd: life.outSequenceEnd, operationSequenceEnd: life.operationSequenceEnd,
			inOperationSequenceEnd: life.inOperationSequenceEnd,
		}
	}
	establishCurrentPair := func(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) error {
		if err := relay.state.life.postAuthenticationCommitV1(); err != nil {
			return err
		}
		if client.State() != auth.StateEstablished || relay.State() != auth.StateEstablished {
			return fmt.Errorf("current pair states=%s/%s", client.State(), relay.State())
		}
		return nil
	}
	assertCurrentPairOperation := func(t *testing.T, client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) {
		t.Helper()
		if _, err := client.state.life.beginOperationV1(14); err != nil {
			t.Fatalf("current pair operation err=%v", err)
		}
		if client.State() != auth.StateEstablished || relay.State() != auth.StateEstablished {
			t.Fatalf("current pair changed state=%s/%s", client.State(), relay.State())
		}
	}
	for _, scenario := range scenarios {
		scenario := scenario
		t.Run(scenario.name+"/profile_advance_first", func(t *testing.T) {
			runtime := lifecycleRuntimeV1(t, profileA, profileB)
			life, invoke, _, assertRejected := scenario.setup(t, runtime)
			beforeCommit := snapshotLifecycle(life)
			coordinator := life.coordinator
			originalDestroy := coordinator.destroy
			if originalDestroy == nil {
				t.Fatal("profile-first coordinator has no destroy closure")
			}
			destroyCalls := 0
			var atDestroy lifecycleCommitSnapshotV1
			coordinator.destroy = func() {
				destroyCalls++
				atDestroy = snapshotLifecycle(life)
				originalDestroy()
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var observerCalls atomic.Int32
			life.beforeProfileCommitObserver = func() {
				observerCalls.Add(1)
				once.Do(func() {
					close(entered)
					<-release
				})
			}
			result := make(chan error, 1)
			go func() { result <- invoke() }()
			<-entered
			currentClient, currentRelay, advanceErr := runtime.NewAuthenticatedChannelPair(inputB)
			if advanceErr != nil || currentClient == nil || currentRelay == nil {
				close(release)
				<-result
				t.Fatalf("profile advance pair=%v/%v err=%v", currentClient, currentRelay, advanceErr)
			}
			t.Cleanup(currentClient.Close)
			establishErr := establishCurrentPair(currentClient, currentRelay)
			generation, overflow := runtime.currentProfileGenerationV1()
			if establishErr != nil || generation != 1 || overflow || currentClient.state.life.generation != 1 || currentRelay.state.life.generation != 1 {
				close(release)
				<-result
				t.Fatalf("profile advance current pair generation=%d/%d runtime=%d overflow=%v err=%v", currentClient.state.life.generation, currentRelay.state.life.generation, generation, overflow, establishErr)
			}
			close(release)
			invokeErr := <-result
			if observerCalls.Load() != 1 || destroyCalls != 1 || atDestroy != beforeCommit {
				t.Fatalf("profile-first observer=%d destroy=%d snapshot=%+v want=%+v", observerCalls.Load(), destroyCalls, atDestroy, beforeCommit)
			}
			assertProfileRotation(t, invokeErr)
			assertRejected()
			assertCurrentPairOperation(t, currentClient, currentRelay)
		})

		t.Run(scenario.name+"/lifecycle_commit_first", func(t *testing.T) {
			runtime := lifecycleRuntimeV1(t, profileA, profileB)
			life, invoke, assertCommitted, _ := scenario.setup(t, runtime)
			originalConstruct := runtime.pairConstructV1
			constructed, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var constructCalls atomic.Int32
			runtime.pairConstructV1 = func(input pairConstructionInputV1) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error) {
				constructCalls.Add(1)
				client, relay, err := originalConstruct(input)
				once.Do(func() {
					close(constructed)
					<-release
				})
				return client, relay, err
			}
			advance := make(chan pairResultV1, 1)
			go func() {
				client, relay, err := runtime.NewAuthenticatedChannelPair(inputB)
				advance <- pairResultV1{client: client, relay: relay, err: err}
			}()
			<-constructed
			invokeErr := invoke()
			close(release)
			current := <-advance
			runtime.pairConstructV1 = originalConstruct
			if invokeErr != nil {
				t.Fatalf("lifecycle-first invoke err=%#v", invokeErr)
			}
			if current.err != nil || current.client == nil || current.relay == nil {
				t.Fatalf("delayed profile advance pair=%v/%v err=%v", current.client, current.relay, current.err)
			}
			t.Cleanup(current.client.Close)
			if constructCalls.Load() != 1 {
				t.Fatalf("delayed profile constructor calls=%d", constructCalls.Load())
			}
			if generation, overflow := runtime.currentProfileGenerationV1(); generation != 1 || overflow {
				t.Fatalf("delayed advance generation=%d overflow=%v", generation, overflow)
			}
			if err := establishCurrentPair(current.client, current.relay); err != nil {
				t.Fatalf("delayed current pair post-auth err=%v", err)
			}
			assertCommitted()
			_, nextErr := life.beginOperationV1(15)
			assertProfileRotation(t, nextErr)
			assertCurrentPairOperation(t, current.client, current.relay)
		})
	}
}

func TestNonProfileRotationIgnoresProfileGenerationV1(t *testing.T) {
	for phaseIndex, phase := range []string{"real_generation_change", "overflow"} {
		for rotationIndex, rotation := range []string{"message_lifetime_bound", "session_only"} {
			t.Run(phase+"_"+rotation, func(t *testing.T) {
				seed := int64(7414 + phaseIndex*10 + rotationIndex*3)
				profileA := newLifecycleFixtureV1(t, seed, rotation, 8, 1)
				profileB := newLifecycleFixtureV1(t, seed+1, rotation, 8, 1)
				profileC := newLifecycleFixtureV1(t, seed+2, rotation, 8, 1)
				runtime := lifecycleRuntimeV1(t, profileA, profileB, profileC)
				client, _ := newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileA))
				newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileB))
				if phase == "overflow" {
					runtime.profileMu.Lock()
					runtime.profileGeneration = math.MaxUint64
					runtime.profileSeen = true
					runtime.profileID = profileB.snapshot.Client.ProfileID
					runtime.profileHash = profileB.snapshot.Client.ProfileHash
					runtime.profileOverflow = false
					runtime.profileMu.Unlock()
					if overflowClient, overflowRelay, err := runtime.NewAuthenticatedChannelPair(lifecyclePairInputV1(t, profileC)); overflowClient != nil || overflowRelay != nil || err != ErrProfileRotationRequired {
						t.Fatalf("overflow transition pair=%v/%v err=%#v", overflowClient, overflowRelay, err)
					}
					if _, overflow := runtime.currentProfileGenerationV1(); !overflow {
						t.Fatal("overflow latch was not committed")
					}
				}
				operation, err := client.state.life.beginOperationV1(1)
				if err != nil {
					t.Fatalf("non-profile first send err=%v", err)
				}
				retry, err := client.state.life.retryOperationV1(operation.operationID)
				if rotation == "message_lifetime_bound" {
					if err != nil || retry.recordEpoch != 1 || retry.recordSequence != 0 {
						t.Fatalf("message lifetime retry=%+v err=%v", retry, err)
					}
				} else if err != ErrKeyLifetimeExhausted || err.Error() != "key_lifetime_exhausted" {
					t.Fatalf("session-only retry err=%#v", err)
				}
			})
		}
	}
}

func TestProfileGenerationIdentityHashAndConcurrentOrderingV1(t *testing.T) {
	t.Run("same_id_different_hash_and_A_B_A", func(t *testing.T) {
		const profileID = "kp_lifecycle_same_id"
		profileA := newLifecycleFixtureConfiguredV1(t, 7420, profileID, "profile_lifetime_bound", security.NonceModeCounterXORBaseV1, 8, 2)
		profileB := newLifecycleFixtureConfiguredV1(t, 7421, profileID, "profile_lifetime_bound", security.NonceModeCounterXORBaseV1, 8, 2)
		if profileA.snapshot.Client.ProfileHash == profileB.snapshot.Client.ProfileHash {
			t.Fatal("same-ID fixtures did not produce distinct hashes")
		}
		runtime := lifecycleRuntimeV1(t, profileA, profileB)
		firstA, _ := newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileA))
		firstB, _ := newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileB))
		secondA, _ := newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileA))
		if firstA.state.life.generation != 0 || firstB.state.life.generation != 1 || secondA.state.life.generation != 2 {
			t.Fatalf("A-B-A generations=%d/%d/%d", firstA.state.life.generation, firstB.state.life.generation, secondA.state.life.generation)
		}
	})

	t.Run("baseline_A_concurrent_B_C_final_plus_two", func(t *testing.T) {
		profileA := newLifecycleFixtureV1(t, 7422, "profile_lifetime_bound", 8, 2)
		profileB := newLifecycleFixtureV1(t, 7423, "profile_lifetime_bound", 8, 2)
		profileC := newLifecycleFixtureV1(t, 7424, "profile_lifetime_bound", 8, 2)
		runtime := lifecycleRuntimeV1(t, profileA, profileB, profileC)
		newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileA))
		inputs := []PairInputV1{lifecyclePairInputV1(t, profileB), lifecyclePairInputV1(t, profileC)}
		type pairResultV1 struct {
			client *ClientAuthenticatedEndpointV1
			relay  *RelayAuthenticatedEndpointV1
			err    error
		}
		results := make(chan pairResultV1, 2)
		var wait sync.WaitGroup
		for _, input := range inputs {
			input := input
			wait.Add(1)
			go func() {
				defer wait.Done()
				client, relay, err := runtime.NewAuthenticatedChannelPair(input)
				results <- pairResultV1{client: client, relay: relay, err: err}
			}()
		}
		wait.Wait()
		close(results)
		pairs := make([]pairResultV1, 0, 2)
		generations := make([]uint64, 0, 2)
		for result := range results {
			if result.err != nil || result.client == nil || result.relay == nil {
				t.Fatalf("concurrent B/C pair=%v/%v err=%v", result.client, result.relay, result.err)
			}
			if result.client.state.life.generation != result.relay.state.life.generation {
				t.Fatalf("concurrent B/C generations=%d/%d", result.client.state.life.generation, result.relay.state.life.generation)
			}
			pairs = append(pairs, result)
			generations = append(generations, result.client.state.life.generation)
		}
		sort.Slice(generations, func(i, j int) bool { return generations[i] < generations[j] })
		if !reflect.DeepEqual(generations, []uint64{1, 2}) {
			t.Fatalf("concurrent B/C captures=%v", generations)
		}
		if generation, overflow := runtime.currentProfileGenerationV1(); generation != 2 || overflow {
			t.Fatalf("B/C final generation=%d overflow=%v", generation, overflow)
		}
		for _, pair := range pairs {
			generation := pair.client.state.life.generation
			if generation == 1 {
				if _, err := pair.client.state.life.beginOperationV1(1); err != ErrProfileRotationRequired {
					t.Fatalf("generation-one pair next hook err=%#v", err)
				}
			} else {
				if err := pair.relay.state.life.postAuthenticationCommitV1(); err != nil {
					t.Fatalf("generation-two relay post-auth err=%v", err)
				}
				if _, err := pair.client.state.life.beginOperationV1(1); err != nil {
					t.Fatalf("generation-two pair unusable err=%v", err)
				}
			}
			pair.client.Close()
		}
	})

	t.Run("concurrent_same_profile_increments_once", func(t *testing.T) {
		profileA := newLifecycleFixtureV1(t, 7425, "profile_lifetime_bound", 8, 2)
		profileB := newLifecycleFixtureV1(t, 7426, "profile_lifetime_bound", 8, 2)
		runtime := lifecycleRuntimeV1(t, profileA, profileB)
		newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileA))
		inputB := lifecyclePairInputV1(t, profileB)
		type pairResultV1 struct {
			client *ClientAuthenticatedEndpointV1
			relay  *RelayAuthenticatedEndpointV1
			err    error
		}
		results := make(chan pairResultV1, 2)
		var wait sync.WaitGroup
		for index := 0; index < 2; index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				client, relay, err := runtime.NewAuthenticatedChannelPair(inputB)
				results <- pairResultV1{client: client, relay: relay, err: err}
			}()
		}
		wait.Wait()
		close(results)
		pairs := make([]pairResultV1, 0, 2)
		for result := range results {
			if result.err != nil || result.client == nil || result.relay == nil {
				t.Fatalf("concurrent B/B pair=%v/%v err=%v", result.client, result.relay, result.err)
			}
			if result.client.state.life.generation != 1 || result.relay.state.life.generation != 1 {
				t.Fatalf("concurrent B/B generations=%d/%d", result.client.state.life.generation, result.relay.state.life.generation)
			}
			pairs = append(pairs, result)
		}
		if generation, overflow := runtime.currentProfileGenerationV1(); generation != 1 || overflow {
			t.Fatalf("same-profile final generation=%d overflow=%v", generation, overflow)
		}
		for _, pair := range pairs {
			if err := pair.relay.state.life.postAuthenticationCommitV1(); err != nil {
				t.Fatalf("concurrent same-profile post-auth err=%v", err)
			}
			if _, err := pair.client.state.life.beginOperationV1(1); err != nil {
				t.Fatalf("concurrent same-profile pair unusable err=%v", err)
			}
			pair.client.Close()
		}
	})
}

func TestProfileGenerationFailedDerivationTrustAndSupportStableV1(t *testing.T) {
	profileA := newLifecycleFixtureV1(t, 7430, "profile_lifetime_bound", 8, 2)
	profileB := newLifecycleFixtureV1(t, 7431, "profile_lifetime_bound", 8, 2)
	runtime := lifecycleRuntimeV1(t, profileA, profileB)
	newEstablishedLifecyclePairV1(t, runtime, lifecyclePairInputV1(t, profileA))
	inputB := lifecyclePairInputV1(t, profileB)
	assertStable := func(stage string) {
		t.Helper()
		if generation, overflow := runtime.currentProfileGenerationV1(); generation != 0 || overflow {
			t.Fatalf("%s generation=%d overflow=%v", stage, generation, overflow)
		}
	}
	for _, failAt := range []int{1, 2} {
		calls := 0
		runtime.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
			calls++
			if calls == failAt {
				wipeRuntimeBytesV1(input.ApplicationSecret)
				return security.KeySchedule{}, errors.New("injected schedule derivation failure")
			}
			return security.DeriveKeyScheduleV1(input)
		}
		if client, relay, err := runtime.NewAuthenticatedChannelPair(inputB); client != nil || relay != nil || err == nil || calls != failAt {
			t.Fatalf("derivation %d pair=%v/%v err=%v calls=%d", failAt, client, relay, err, calls)
		}
		assertStable(fmt.Sprintf("derivation_%d", failAt))
	}
	runtime.pairDeriveScheduleV1 = security.DeriveKeyScheduleV1

	originalTrust := runtime.clientDependencies.Trust
	runtime.clientDependencies.Trust = handshakeTrust{id: "runtime-server", key: make(ed25519.PublicKey, ed25519.PublicKeySize)}
	if client, relay, err := runtime.NewAuthenticatedChannelPair(inputB); client != nil || relay != nil || err == nil {
		t.Fatalf("untrusted pair=%v/%v err=%v", client, relay, err)
	}
	runtime.clientDependencies.Trust = originalTrust
	assertStable("untrusted")

	originalClientModes := runtime.clientSupport.nonceModes
	originalRelayModes := runtime.relaySupport.nonceModes
	runtime.clientSupport.nonceModes = []string{security.NonceModeDirectionalCounterV1}
	runtime.relaySupport.nonceModes = []string{security.NonceModeDirectionalCounterV1}
	if client, relay, err := runtime.NewAuthenticatedChannelPair(inputB); client != nil || relay != nil || err == nil {
		t.Fatalf("unsupported pair=%v/%v err=%v", client, relay, err)
	}
	runtime.clientSupport.nonceModes = originalClientModes
	runtime.relaySupport.nonceModes = originalRelayModes
	assertStable("unsupported")
}
