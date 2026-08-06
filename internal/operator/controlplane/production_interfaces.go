// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import "context"

// ProductionOperationState describes the durable cross-system lifecycle. It is
// intentionally separate from the Phase 12 compatibility OperationState.
type ProductionOperationState string

const (
	ProductionPending         ProductionOperationState = "PENDING"
	ProductionApproved        ProductionOperationState = "APPROVED"
	ProductionCommitted       ProductionOperationState = "COMMITTED"
	ProductionEffectPending   ProductionOperationState = "EFFECT_PENDING"
	ProductionAnchored        ProductionOperationState = "ANCHORED"
	ProductionPublished       ProductionOperationState = "PUBLISHED"
	ProductionFinalized       ProductionOperationState = "FINALIZED"
	ProductionRejected        ProductionOperationState = "REJECTED"
	ProductionFailedRetryable ProductionOperationState = "FAILED_RETRYABLE"
	ProductionFailedTerminal  ProductionOperationState = "FAILED_TERMINAL"
)

func ValidProductionStateTransition(from, to ProductionOperationState) bool {
	switch from {
	case ProductionPending:
		return to == ProductionApproved || to == ProductionRejected
	case ProductionApproved:
		return to == ProductionCommitted
	case ProductionCommitted:
		return to == ProductionEffectPending
	case ProductionEffectPending:
		return to == ProductionAnchored || to == ProductionFailedRetryable || to == ProductionFailedTerminal
	case ProductionFailedRetryable:
		return to == ProductionEffectPending || to == ProductionFailedTerminal
	case ProductionAnchored:
		return to == ProductionPublished || to == ProductionFinalized
	case ProductionPublished:
		return to == ProductionFinalized
	default:
		return false
	}
}

type TransactionResult struct {
	Receipt           Receipt
	Revision          uint64
	Sequence          uint64
	TrustedCommitTime TrustedInstant
	AuditHash         string
	OutboxIDs         []string
}

// ProductionTransactionStore is the context-aware authority-store boundary.
// Implementations must execute ApplyCommand in a serializable transaction and
// return only after same-transaction audit and outbox persistence is durable.
type ProductionTransactionStore interface {
	Snapshot(ctx context.Context) (State, error)
	Execute(ctx context.Context, command Command) (TransactionResult, error)
}
