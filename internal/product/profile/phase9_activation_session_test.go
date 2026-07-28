// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"errors"
	"reflect"
	"testing"

	"kurdistan/internal/product/lifecycle"
)

func TestPhase9ActivationSessionMatchesSynchronousAdapter(t *testing.T) {
	directRequest, directStore := validActivationRequest(t)
	var directStages []ActivationStage
	directRequest.Observe = func(stage ActivationStage) { directStages = append(directStages, stage) }
	direct, err := ActivateVerifiedProfile(directRequest)
	if err != nil {
		t.Fatal(err)
	}

	stepRequest, stepStore := validActivationRequest(t)
	var stepStages []ActivationStage
	stepRequest.Observe = func(stage ActivationStage) { stepStages = append(stepStages, stage) }
	stepwise, err := driveActivationSession(stepRequest, stepStore)
	if err != nil {
		t.Fatal(err)
	}

	if !activationRecordEqual(direct, stepwise) ||
		!activationRecordEqual(directStore.active, stepStore.active) ||
		!activationRecordEqual(directStore.lkg, stepStore.lkg) {
		t.Fatal("stepwise activation diverged from synchronous adapter")
	}
	if !reflect.DeepEqual(directStages, stepStages) {
		t.Fatalf("stage order mismatch:\ndirect=%v\nstep=%v", directStages, stepStages)
	}
}

func TestPhase9ActivationSessionRejectsCommandReplayAndMutation(t *testing.T) {
	request, _ := validActivationRequest(t)
	session := NewActivationSession(request)
	command, ok := session.Next()
	if !ok || command.Kind != ActivationCommandSnapshot {
		t.Fatalf("first command=%#v ok=%v", command, ok)
	}
	mutated := command
	mutated.Sequence++
	if err := session.Submit(mutated, ActivationCommandResult{}); activationCode(err) != ActivationPolicyRejected {
		t.Fatalf("mutated sequence error=%v", err)
	}
	if err := session.Submit(command, ActivationCommandResult{}); err != nil {
		t.Fatal(err)
	}
	if err := session.Submit(command, ActivationCommandResult{}); activationCode(err) != ActivationPolicyRejected {
		t.Fatalf("replayed command error=%v", err)
	}
}

func TestPhase9ActivationSessionRecoversEveryDurableBoundary(t *testing.T) {
	for _, stage := range []ActivationStage{
		StageCandidateStored,
		StageCandidateReopened,
		StageActivationMarked,
		StageActivationCommitted,
		StageActivationFinalized,
	} {
		for _, after := range []bool{false, true} {
			name := "before"
			if after {
				name = "after"
			}
			t.Run(name+"/"+string(stage), func(t *testing.T) {
				request, store := validActivationRequest(t)
				if after {
					store.failAfter = stage
				} else {
					store.failAt = stage
				}
				_, err := driveActivationSession(request, store)
				if activationCode(err) != ActivationStorageFailure {
					t.Fatalf("error=%v", err)
				}
				safePrior := activationRecordEqual(store.active, ActivationRecord{}) &&
					activationRecordEqual(store.lkg, ActivationRecord{})
				safeCommitted := store.active.State.Status == lifecycle.Admitted &&
					activationRecordEqual(store.lkg, ActivationRecord{})
				if !safePrior && !safeCommitted {
					t.Fatal("failure exposed partial activation state")
				}
			})
		}
	}
}

func TestPhase9ActivationSessionQuarantinesUnprovableRecovery(t *testing.T) {
	request, store := validActivationRequest(t)
	store.failAfter = StageCandidateStored
	store.corruptRecovery = true
	_, err := driveActivationSession(request, store)
	if activationCode(err) != ActivationRecoveryFailure {
		t.Fatalf("error=%v", err)
	}
	if !store.quarantined {
		t.Fatal("store was not quarantined")
	}
}

func driveActivationSession(request ActivationRequest, store TransactionalActivationProvider) (ActivationRecord, error) {
	session := NewActivationSession(request)
	for {
		command, ok := session.Next()
		if !ok {
			return session.Result()
		}
		result := ActivationCommandResult{}
		switch command.Kind {
		case ActivationCommandSnapshot:
			result.Active, result.LastKnownGood, result.Err = store.Snapshot()
		case ActivationCommandStageCandidate:
			result.Err = store.StageCandidate(command.Record)
		case ActivationCommandReopenCandidate:
			result.Record, result.Err = store.ReopenCandidate()
		case ActivationCommandMarkActivation:
			result.Err = store.MarkActivation()
		case ActivationCommandCommitMarked:
			result.Err = store.CommitMarked()
		case ActivationCommandFinalizeActivation:
			result.Err = store.FinalizeActivation()
		case ActivationCommandRecover:
			result.Err = store.Recover()
		case ActivationCommandQuarantine:
			result.Err = store.Quarantine()
		default:
			return ActivationRecord{}, errors.New("unexpected command")
		}
		if err := session.Submit(command, result); err != nil {
			return ActivationRecord{}, err
		}
	}
}
