// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import "context"

// CompatibilityTransactionStore exposes the production transaction contract
// over an existing Store. It is for local evidence and migration parity only;
// production implementations must provide serializable external persistence
// and trusted commit-time evidence.
type CompatibilityTransactionStore struct {
	store Store
}

func NewCompatibilityTransactionStore(store Store) (*CompatibilityTransactionStore, error) {
	if store == nil {
		return nil, ErrInvalidInput
	}
	if err := store.Snapshot().Validate(); err != nil {
		return nil, err
	}
	return &CompatibilityTransactionStore{store: store}, nil
}

func (store *CompatibilityTransactionStore) Snapshot(ctx context.Context) (State, error) {
	if err := ctx.Err(); err != nil {
		return State{}, err
	}
	return store.store.Snapshot(), nil
}

func (store *CompatibilityTransactionStore) Execute(ctx context.Context, command Command) (TransactionResult, error) {
	if err := ctx.Err(); err != nil {
		return TransactionResult{}, err
	}
	current := store.store.Snapshot()
	if result, replay, err := commandReplay(current, command); err != nil {
		return TransactionResult{}, err
	} else if replay {
		return TransactionResult{
			Receipt: result.Receipt, Revision: current.Revision,
			Sequence: result.Receipt.Sequence, TrustedCommitTime: command.TrustedAt,
			AuditHash: result.AuditHash,
		}, nil
	}
	var commandResultValue CommandResult
	next, err := store.store.Update(command.ExpectedRevision, func(state *State) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := applyCommandMutation(state, command)
		if err != nil {
			return err
		}
		commandResultValue = result
		return nil
	})
	if err != nil {
		return TransactionResult{}, err
	}
	commandResultValue.Receipt.Revision = next.Revision
	return TransactionResult{
		Receipt: commandResultValue.Receipt, Revision: next.Revision,
		Sequence: commandResultValue.Receipt.Sequence, TrustedCommitTime: command.TrustedAt,
		AuditHash: commandResultValue.AuditHash,
		OutboxIDs: append([]string(nil), commandResultValue.OutboxIDs...),
	}, nil
}
