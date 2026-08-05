// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestCommandEngineMatchesCompatibilityService(t *testing.T) {
	requester, approverA, approverB, executor := testActors()
	input := testRequest("operation-command-parity", ActionIssueProfile, 0, 0)

	service := newTestService(t, NewMemoryStore())
	if _, err := service.Request(requester, input); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(approverA, input.ID, "approve-command-a", 1, 101); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(approverB, input.ID, "approve-command-b", 2, 102); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(executor, input.ID, "execute-command", 3, 103); err != nil {
		t.Fatal(err)
	}

	state := NewState()
	commands := []Command{
		mustRequestCommand(t, requester, input, 100, 1),
		mustApproveCommand(t, approverA, input.ID, "approve-command-a", 1, 101, 2),
		mustApproveCommand(t, approverB, input.ID, "approve-command-b", 2, 102, 3),
		mustExecuteCommand(t, executor, input.ID, "execute-command", 3, 103, 4),
	}
	for _, command := range commands {
		var err error
		state, _, err = ApplyCommand(state, command)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(service.State(), state) {
		t.Fatal("pure command engine diverged from compatibility service")
	}
}

func TestCommandTransitionIsDeterministicAndDoesNotAliasInput(t *testing.T) {
	requester, _, _, _ := testActors()
	input := testRequest("operation-command-determinism", ActionIssueProfile, 0, 0)
	command := mustRequestCommand(t, requester, input, 100, 1)
	initial := NewState()

	first, firstResult, err := ApplyCommand(initial, command)
	if err != nil {
		t.Fatal(err)
	}
	second, secondResult, err := ApplyCommand(initial, command)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(firstResult, secondResult) {
		t.Fatal("identical command retry produced different state or receipt")
	}

	operation := first.Operations[input.ID]
	operation.ApproverIDs = append(operation.ApproverIDs, "operator-mutated")
	first.Operations[input.ID] = operation
	if len(initial.Operations) != 0 || len(second.Operations[input.ID].ApproverIDs) != 0 {
		t.Fatal("returned command state aliases its input or another result")
	}
}

func TestCommandReplayIsNoopEvenAfterRevisionAdvanced(t *testing.T) {
	requester, _, _, _ := testActors()
	input := testRequest("operation-command-replay", ActionIssueProfile, 0, 0)
	command := mustRequestCommand(t, requester, input, 100, 1)
	state, original, err := ApplyCommand(NewState(), command)
	if err != nil {
		t.Fatal(err)
	}
	replayed, replay, err := ApplyCommand(state, command)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Noop || replayed.Revision != state.Revision || replay.Receipt != original.Receipt || !reflect.DeepEqual(replayed, state) {
		t.Fatal("exact idempotent replay changed durable state")
	}
}

func TestCommandRejectsRevisionConflict(t *testing.T) {
	requester, _, _, _ := testActors()
	input := testRequest("operation-command-conflict", ActionIssueProfile, 0, 0)
	input.ExpectedRevision = 1
	input = sealRequestInput(input, requestProofProfile)
	command := mustRequestCommand(t, requester, input, 100, 2)
	if _, _, err := ApplyCommand(NewState(), command); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected revision conflict, got %v", err)
	}
}

func TestRejectCommandIsDurableIdempotentAndCannotBeExecuted(t *testing.T) {
	requester, approver, _, executor := testActors()
	input := testRequest("operation-command-reject", ActionIssueProfile, 0, 0)
	state, _, err := ApplyCommand(NewState(), mustRequestCommand(t, requester, input, 100, 1))
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := NewTrustedInstant(101, "test-authority-database", 2)
	if err != nil {
		t.Fatal(err)
	}
	command, err := NewRejectCommand(approver, input.ID, "reject-command", 1, trusted)
	if err != nil {
		t.Fatal(err)
	}
	rejected, result, err := ApplyCommand(state, command)
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Operations[input.ID].State != OperationRejected || result.Receipt.State != OperationRejected {
		t.Fatal("rejection did not become durable")
	}
	replayed, replay, err := ApplyCommand(rejected, command)
	if err != nil || !replay.Noop || !reflect.DeepEqual(replayed, rejected) {
		t.Fatalf("rejection replay changed state: result=%+v err=%v", replay, err)
	}
	if _, _, err := ApplyCommand(rejected, mustExecuteCommand(t, executor, input.ID, "execute-rejected", 2, 102, 3)); !errors.Is(err, ErrInsufficientQuorum) {
		t.Fatalf("rejected operation executed: %v", err)
	}
}

func TestProductionOperationTransitionsFailClosed(t *testing.T) {
	allowed := [][2]ProductionOperationState{
		{ProductionPending, ProductionApproved},
		{ProductionApproved, ProductionCommitted},
		{ProductionCommitted, ProductionEffectPending},
		{ProductionEffectPending, ProductionAnchored},
		{ProductionEffectPending, ProductionFailedRetryable},
		{ProductionEffectPending, ProductionFailedTerminal},
		{ProductionFailedRetryable, ProductionEffectPending},
		{ProductionFailedRetryable, ProductionFailedTerminal},
		{ProductionAnchored, ProductionPublished},
		{ProductionAnchored, ProductionFinalized},
		{ProductionPublished, ProductionFinalized},
	}
	for _, transition := range allowed {
		if !ValidProductionStateTransition(transition[0], transition[1]) {
			t.Fatalf("required transition rejected: %s -> %s", transition[0], transition[1])
		}
	}
	if ValidProductionStateTransition(ProductionPending, ProductionFinalized) ||
		ValidProductionStateTransition(ProductionFinalized, ProductionPending) ||
		ValidProductionStateTransition(ProductionFailedTerminal, ProductionEffectPending) {
		t.Fatal("invalid production transition accepted")
	}
}

func TestCompatibilityTransactionHonorsCancellation(t *testing.T) {
	store, err := NewCompatibilityTransactionStore(NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("snapshot cancellation = %v", err)
	}
}

func FuzzApplyCommandDeterministic(f *testing.F) {
	f.Add("fuzz-operation-001")
	f.Fuzz(func(t *testing.T, operationID string) {
		if !validID(operationID) {
			t.Skip()
		}
		requester, _, _, _ := testActors()
		input := testRequest(operationID, ActionIssueProfile, 0, 0)
		command := mustRequestCommand(t, requester, input, 100, 1)
		left, leftResult, leftErr := ApplyCommand(NewState(), command)
		right, rightResult, rightErr := ApplyCommand(NewState(), command)
		if !errors.Is(leftErr, rightErr) || !reflect.DeepEqual(left, right) || !reflect.DeepEqual(leftResult, rightResult) {
			t.Fatal("command application is not deterministic")
		}
	})
}

func mustRequestCommand(t *testing.T, actor Actor, input RequestInput, at int64, sequence uint64) Command {
	t.Helper()
	trusted, err := NewTrustedInstant(at, "test-authority-database", sequence)
	if err != nil {
		t.Fatal(err)
	}
	command, err := NewRequestCommand(actor, input, trusted)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func mustApproveCommand(t *testing.T, actor Actor, operationID, idempotencyKey string, revision uint64, at int64, sequence uint64) Command {
	t.Helper()
	trusted, err := NewTrustedInstant(at, "test-authority-database", sequence)
	if err != nil {
		t.Fatal(err)
	}
	command, err := NewApproveCommand(actor, operationID, idempotencyKey, revision, trusted)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func mustExecuteCommand(t *testing.T, actor Actor, operationID, idempotencyKey string, revision uint64, at int64, sequence uint64) Command {
	t.Helper()
	trusted, err := NewTrustedInstant(at, "test-authority-database", sequence)
	if err != nil {
		t.Fatal(err)
	}
	command, err := NewExecuteCommand(actor, operationID, idempotencyKey, revision, trusted)
	if err != nil {
		t.Fatal(err)
	}
	return command
}
