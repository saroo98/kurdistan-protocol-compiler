// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import "fmt"

type ProductionEffectOutcome string

const (
	ProductionEffectDelivered ProductionEffectOutcome = "DELIVERED"
	ProductionEffectRetry     ProductionEffectOutcome = "RETRY"
	ProductionEffectTerminal  ProductionEffectOutcome = "TERMINAL"
)

type ProductionEffectResolution struct {
	EventID     string
	EffectID    string
	ReceiptHash string
	WorkerID    string
	Attempt     uint32
	At          int64
	Outcome     ProductionEffectOutcome
}

type ProductionEffectResult struct {
	Revision  uint64
	AuditHash string
	Event     OutboxEvent
}

// ApplyProductionEffectResolution is the pure state transition used by the
// external transaction store after it has verified the durable lease and
// fencing token. It cannot grant a lease and cannot acknowledge an event with
// stale attempt state or substituted effect identity.
func ApplyProductionEffectResolution(current State, resolution ProductionEffectResolution) (State, ProductionEffectResult, error) {
	if err := current.Validate(); err != nil || !validID(resolution.EventID) ||
		!validID(resolution.EffectID) || resolution.EffectID != "phase16-effect-"+resolution.EventID ||
		!validID(resolution.WorkerID) || resolution.Attempt == 0 || resolution.At <= 0 {
		return State{}, ProductionEffectResult{}, ErrInvalidInput
	}
	if resolution.Outcome == ProductionEffectDelivered {
		if !validDigest(resolution.ReceiptHash) {
			return State{}, ProductionEffectResult{}, ErrInvalidInput
		}
	} else if resolution.ReceiptHash != "" ||
		(resolution.Outcome != ProductionEffectRetry && resolution.Outcome != ProductionEffectTerminal) {
		return State{}, ProductionEffectResult{}, ErrInvalidInput
	}
	next := current.clone()
	index := -1
	for candidate := range next.Outbox {
		if next.Outbox[candidate].ID == resolution.EventID {
			index = candidate
			break
		}
	}
	if index < 0 {
		return State{}, ProductionEffectResult{}, ErrConflict
	}
	event := next.Outbox[index]
	operation, exists := next.Operations[event.OperationID]
	if !exists || operation.State != OperationExecuted || event.Kind != string(operation.Action) ||
		event.SubjectDigest != operation.SubjectDigest || event.DeliveredAt != 0 || event.FailedAt != 0 ||
		resolution.Attempt != event.Attempts+1 || resolution.Attempt > MaxEffectAttempts || resolution.At < event.CreatedAt {
		return State{}, ProductionEffectResult{}, ErrConflict
	}
	auditAction := "record-outbox-failure"
	auditResult := "retry"
	idempotencyKey := fmt.Sprintf("fail-%s-%d", event.ID, resolution.Attempt)
	switch resolution.Outcome {
	case ProductionEffectDelivered:
		event.DeliveredAt = resolution.At
		event.OutcomeDigest = resolution.ReceiptHash
		auditAction = "acknowledge-outbox"
		auditResult = "delivered"
		idempotencyKey = "ack-" + event.ID
	case ProductionEffectRetry:
		if resolution.Attempt >= MaxEffectAttempts {
			return State{}, ProductionEffectResult{}, ErrConflict
		}
		event.Attempts = resolution.Attempt
		event.LastAttemptAt = resolution.At
	case ProductionEffectTerminal:
		if resolution.Attempt != MaxEffectAttempts {
			return State{}, ProductionEffectResult{}, ErrConflict
		}
		event.Attempts = resolution.Attempt
		event.LastAttemptAt = resolution.At
		event.FailedAt = resolution.At
		auditResult = "terminal"
	default:
		return State{}, ProductionEffectResult{}, ErrInvalidInput
	}
	next.Outbox[index] = event
	if _, exists := next.Idempotency[idempotencyKey]; exists {
		return State{}, ProductionEffectResult{}, ErrConflict
	}
	if err := appendAudit(&next, resolution.At, resolution.WorkerID, auditAction, event.ID, auditResult); err != nil {
		return State{}, ProductionEffectResult{}, err
	}
	next.Revision++
	next.Idempotency[idempotencyKey] = Receipt{
		OperationID: event.ID, State: OperationExecuted,
		Revision: next.Revision, Sequence: next.NextSequence - 1,
	}
	if err := next.Validate(); err != nil {
		return State{}, ProductionEffectResult{}, fmt.Errorf("%w: resolved state invalid", ErrInvalidInput)
	}
	return next, ProductionEffectResult{Revision: next.Revision, AuditHash: next.Audit[len(next.Audit)-1].Hash, Event: event}, nil
}
