// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import "fmt"

type CommandKind string

const (
	CommandRequest CommandKind = "request"
	CommandApprove CommandKind = "approve"
	CommandExecute CommandKind = "execute"
)

// Command contains only already-verified authority input and a trusted instant.
// ApplyCommand is pure: it performs no I/O, randomness, KMS work, object writes,
// or wall-clock reads.
type Command struct {
	Kind             CommandKind
	Actor            Actor
	Request          *RequestInput
	OperationID      string
	IdempotencyKey   string
	ExpectedRevision uint64
	TrustedAt        TrustedInstant
}

type CommandResult struct {
	Receipt   Receipt
	AuditHash string
	OutboxIDs []string
	Noop      bool
}

func NewRequestCommand(actor Actor, input RequestInput, trusted TrustedInstant) (Command, error) {
	if input.CreatedAt != trusted.UnixSeconds {
		return Command{}, fmt.Errorf("%w: request time is not trusted time", ErrInvalidInput)
	}
	request := input
	request.Publication = clonePublicationInput(input.Publication)
	command := Command{
		Kind: CommandRequest, Actor: actor, Request: &request,
		ExpectedRevision: input.ExpectedRevision, TrustedAt: trusted,
	}
	if err := command.Validate(); err != nil {
		return Command{}, err
	}
	return command, nil
}

func NewApproveCommand(actor Actor, operationID, idempotencyKey string, expectedRevision uint64, trusted TrustedInstant) (Command, error) {
	command := Command{
		Kind: CommandApprove, Actor: actor, OperationID: operationID,
		IdempotencyKey: idempotencyKey, ExpectedRevision: expectedRevision, TrustedAt: trusted,
	}
	if err := command.Validate(); err != nil {
		return Command{}, err
	}
	return command, nil
}

func NewExecuteCommand(actor Actor, operationID, idempotencyKey string, expectedRevision uint64, trusted TrustedInstant) (Command, error) {
	command := Command{
		Kind: CommandExecute, Actor: actor, OperationID: operationID,
		IdempotencyKey: idempotencyKey, ExpectedRevision: expectedRevision, TrustedAt: trusted,
	}
	if err := command.Validate(); err != nil {
		return Command{}, err
	}
	return command, nil
}

func (command Command) Validate() error {
	if err := command.TrustedAt.Validate(); err != nil {
		return err
	}
	switch command.Kind {
	case CommandRequest:
		if command.Request == nil || command.OperationID != "" || command.IdempotencyKey != "" ||
			command.ExpectedRevision != command.Request.ExpectedRevision {
			return ErrInvalidInput
		}
	case CommandApprove, CommandExecute:
		if command.Request != nil || !validID(command.OperationID) || !validID(command.IdempotencyKey) {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

// ApplyCommand deterministically applies one command to an immutable snapshot.
// The returned state owns all of its mutable collections.
func ApplyCommand(current State, command Command) (State, CommandResult, error) {
	if err := current.Validate(); err != nil {
		return State{}, CommandResult{}, err
	}
	if err := command.Validate(); err != nil {
		return State{}, CommandResult{}, err
	}
	if result, replay, err := commandReplay(current, command); err != nil {
		return State{}, CommandResult{}, err
	} else if replay {
		return current.clone(), result, nil
	}
	if current.Revision != command.ExpectedRevision {
		return State{}, CommandResult{}, ErrConflict
	}
	next := current.clone()
	result, err := applyCommandMutation(&next, command)
	if err != nil {
		return State{}, CommandResult{}, err
	}
	next.Revision++
	if err := next.Validate(); err != nil {
		return State{}, CommandResult{}, err
	}
	result.Receipt.Revision = next.Revision
	return next, result, nil
}

func commandReplay(state State, command Command) (CommandResult, bool, error) {
	var key string
	switch command.Kind {
	case CommandRequest:
		key = command.Request.IdempotencyKey
	case CommandApprove, CommandExecute:
		key = command.IdempotencyKey
	default:
		return CommandResult{}, false, ErrInvalidInput
	}
	receipt, exists := state.Idempotency[key]
	if !exists {
		return CommandResult{}, false, nil
	}
	if command.Kind == CommandRequest {
		operation := Operation{
			ID: command.Request.ID, Action: command.Request.Action, TargetID: command.Request.TargetID,
			SubjectDigest: command.Request.SubjectDigest, ScopeDigest: command.Request.ScopeDigest,
			AuthorityScopeDigest: command.Request.AuthorityScopeDigest, AuthorityRootDigest: command.Request.AuthorityRootDigest,
			ExpectedArtifactDigest: command.Request.ExpectedArtifactDigest, RequesterID: command.Actor.ID,
			State: OperationPending, ExpectedRevision: command.Request.ExpectedRevision,
			ExpectedEpoch: command.Request.ExpectedEpoch, ResultEpoch: command.Request.ResultEpoch,
			CreatedAt: command.Request.CreatedAt, ExpiresAt: command.Request.ExpiresAt,
			Publication: clonePublicationInput(command.Request.Publication),
		}
		existing, found := state.Operations[receipt.OperationID]
		if !found || !sameRequestIntent(existing, operation) {
			return CommandResult{}, false, ErrIdempotency
		}
	} else if receipt.OperationID != command.OperationID {
		return CommandResult{}, false, ErrIdempotency
	}
	result := commandResult(state, receipt, len(state.Outbox))
	result.Noop = true
	return result, true, nil
}

func applyCommandMutation(state *State, command Command) (CommandResult, error) {
	switch command.Kind {
	case CommandRequest:
		return applyRequestCommand(state, command.Actor, *command.Request)
	case CommandApprove:
		return applyApproveCommand(state, command.Actor, command.OperationID, command.IdempotencyKey, command.TrustedAt.UnixSeconds)
	case CommandExecute:
		return applyExecuteCommand(state, command.Actor, command.OperationID, command.IdempotencyKey, command.TrustedAt.UnixSeconds)
	default:
		return CommandResult{}, ErrInvalidInput
	}
}

func commandResult(state State, receipt Receipt, outboxStart int) CommandResult {
	result := CommandResult{Receipt: receipt}
	if len(state.Audit) > 0 {
		result.AuditHash = state.Audit[len(state.Audit)-1].Hash
	}
	for _, event := range state.Outbox[outboxStart:] {
		result.OutboxIDs = append(result.OutboxIDs, event.ID)
	}
	return result
}

func applyRequestCommand(state *State, actor Actor, input RequestInput) (CommandResult, error) {
	if err := ValidateActor(actor); err != nil || !actor.has(DutyRequest) {
		return CommandResult{}, ErrUnauthorized
	}
	if err := validateRequestProof(input); err != nil {
		return CommandResult{}, err
	}
	if !validID(input.IdempotencyKey) {
		return CommandResult{}, ErrInvalidInput
	}
	operation := Operation{
		ID: input.ID, Action: input.Action, TargetID: input.TargetID,
		SubjectDigest: input.SubjectDigest, ScopeDigest: input.ScopeDigest,
		AuthorityScopeDigest: input.AuthorityScopeDigest, AuthorityRootDigest: input.AuthorityRootDigest,
		ExpectedArtifactDigest: input.ExpectedArtifactDigest, RequesterID: actor.ID,
		State: OperationPending, ExpectedRevision: input.ExpectedRevision,
		ExpectedEpoch: input.ExpectedEpoch, ResultEpoch: input.ResultEpoch,
		CreatedAt: input.CreatedAt, ExpiresAt: input.ExpiresAt,
		Publication: clonePublicationInput(input.Publication),
	}
	if err := ValidateOperation(operation); err != nil {
		return CommandResult{}, err
	}
	if receipt, ok := state.Idempotency[input.IdempotencyKey]; ok {
		existing, found := state.Operations[receipt.OperationID]
		if !found || !sameRequestIntent(existing, operation) {
			return CommandResult{}, ErrIdempotency
		}
		return commandResult(*state, receipt, len(state.Outbox)), nil
	}
	if _, exists := state.Operations[operation.ID]; exists ||
		!mutationCapacityAvailable(*state, operation.Action, 1, 1, 1, 0, 0) {
		return CommandResult{}, ErrConflict
	}
	state.Operations[operation.ID] = operation
	if err := appendAudit(state, input.CreatedAt, actor.ID, "request-"+string(input.Action), operation.ID, "accepted"); err != nil {
		return CommandResult{}, err
	}
	receipt := Receipt{OperationID: operation.ID, State: operation.State, Revision: state.Revision + 1, Sequence: state.NextSequence - 1}
	state.Idempotency[input.IdempotencyKey] = receipt
	return commandResult(*state, receipt, len(state.Outbox)), nil
}

func applyApproveCommand(state *State, actor Actor, operationID, idempotencyKey string, now int64) (CommandResult, error) {
	if err := ValidateActor(actor); err != nil || !actor.has(DutyApprove) {
		return CommandResult{}, ErrUnauthorized
	}
	if !validID(operationID) || !validID(idempotencyKey) || now <= 0 {
		return CommandResult{}, ErrInvalidInput
	}
	if receipt, ok := state.Idempotency[idempotencyKey]; ok {
		if receipt.OperationID != operationID {
			return CommandResult{}, ErrIdempotency
		}
		return commandResult(*state, receipt, len(state.Outbox)), nil
	}
	operation, ok := state.Operations[operationID]
	if !ok || operation.State == OperationExecuted || operation.State == OperationRejected {
		return CommandResult{}, ErrConflict
	}
	if now >= operation.ExpiresAt {
		return CommandResult{}, ErrExpired
	}
	if actor.ID == operation.RequesterID {
		return CommandResult{}, ErrUnauthorized
	}
	for _, approver := range operation.ApproverIDs {
		if approver == actor.ID {
			return CommandResult{}, ErrConflict
		}
	}
	if !mutationCapacityAvailable(*state, operation.Action, 0, 1, 1, 0, 0) {
		return CommandResult{}, ErrConflict
	}
	operation.ApproverIDs = canonicalApprovers(append(operation.ApproverIDs, actor.ID))
	if len(operation.ApproverIDs) >= MinApprovalQuorum {
		operation.State = OperationApproved
	}
	state.Operations[operationID] = operation
	if err := appendAudit(state, now, actor.ID, "approve-"+string(operation.Action), operation.ID, string(operation.State)); err != nil {
		return CommandResult{}, err
	}
	receipt := Receipt{OperationID: operation.ID, State: operation.State, Revision: state.Revision + 1, Sequence: state.NextSequence - 1}
	state.Idempotency[idempotencyKey] = receipt
	return commandResult(*state, receipt, len(state.Outbox)), nil
}

func applyExecuteCommand(state *State, actor Actor, operationID, idempotencyKey string, now int64) (CommandResult, error) {
	if err := ValidateActor(actor); err != nil || !actor.has(DutyExecute) {
		return CommandResult{}, ErrUnauthorized
	}
	if !validID(operationID) || !validID(idempotencyKey) || now <= 0 {
		return CommandResult{}, ErrInvalidInput
	}
	if receipt, ok := state.Idempotency[idempotencyKey]; ok {
		if receipt.OperationID != operationID {
			return CommandResult{}, ErrIdempotency
		}
		return commandResult(*state, receipt, len(state.Outbox)), nil
	}
	operation, ok := state.Operations[operationID]
	if !ok || operation.State != OperationApproved {
		return CommandResult{}, ErrInsufficientQuorum
	}
	if now >= operation.ExpiresAt {
		return CommandResult{}, ErrExpired
	}
	if len(operation.ApproverIDs) < MinApprovalQuorum || actor.ID == operation.RequesterID || contains(operation.ApproverIDs, actor.ID) {
		return CommandResult{}, ErrUnauthorized
	}
	if err := authorizeExecution(actor, operation.Action); err != nil {
		return CommandResult{}, err
	}
	if !mutationCapacityAvailable(*state, operation.Action, 0, 1, 1, 1, MaxEffectAttempts) {
		return CommandResult{}, ErrConflict
	}
	outboxStart := len(state.Outbox)
	if err := applyOperation(state, operation, now); err != nil {
		return CommandResult{}, err
	}
	operation.State = OperationExecuted
	operation.ExecutedAt = now
	state.Operations[operationID] = operation
	if err := appendOutbox(state, now, operation.ID, string(operation.Action), operation.SubjectDigest); err != nil {
		return CommandResult{}, err
	}
	if err := appendAudit(state, now, actor.ID, "execute-"+string(operation.Action), operation.ID, "executed"); err != nil {
		return CommandResult{}, err
	}
	receipt := Receipt{OperationID: operation.ID, State: operation.State, Revision: state.Revision + 1, Sequence: state.NextSequence - 1}
	state.Idempotency[idempotencyKey] = receipt
	return commandResult(*state, receipt, outboxStart), nil
}
