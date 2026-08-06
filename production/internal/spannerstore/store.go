// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package spannerstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"kurdistan/internal/operator/controlplane"
	"kurdistan/production/internal/authoritysource"
)

var environmentRE = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)
var recordIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)

var (
	ErrInvalidConfiguration = errors.New("spannerstore: invalid configuration")
	ErrTrustedTimeMismatch  = errors.New("spannerstore: trusted time mismatch")
)

type Store struct {
	client      Client
	environment string
}

func New(client Client, environment string) (*Store, error) {
	if client == nil || !environmentRE.MatchString(environment) {
		return nil, ErrInvalidConfiguration
	}
	return &Store{client: client, environment: environment}, nil
}

func (store *Store) Snapshot(ctx context.Context) (controlplane.State, error) {
	head, err := store.client.StrongReadHead(ctx, store.environment)
	if err != nil {
		return controlplane.State{}, err
	}
	return decodeHead(head, store.environment)
}

func (store *Store) Execute(ctx context.Context, command controlplane.Command) (controlplane.TransactionResult, error) {
	return store.execute(ctx, command, nil)
}

func (store *Store) ExecuteAdmitted(ctx context.Context, command controlplane.Command, source authoritysource.Protected) (controlplane.TransactionResult, error) {
	if command.Kind != controlplane.CommandRequest || source.Schema != authoritysource.Schema ||
		source.OperationID != command.Request.ID || source.SubjectDigest != command.Request.SubjectDigest {
		return controlplane.TransactionResult{}, ErrInvalidConfiguration
	}
	return store.execute(ctx, command, &source)
}

func (store *Store) execute(ctx context.Context, command controlplane.Command, source *authoritysource.Protected) (controlplane.TransactionResult, error) {
	if err := command.Validate(); err != nil {
		return controlplane.TransactionResult{}, err
	}
	var result controlplane.CommandResult
	commitTime, err := store.client.ReadWrite(ctx, func(callbackContext context.Context, transaction Transaction) error {
		head, err := transaction.ReadHead(callbackContext, store.environment)
		if err != nil {
			return err
		}
		current, err := decodeHead(head, store.environment)
		if err != nil {
			return err
		}
		if head.TrustedSequence != command.TrustedAt.Sequence ||
			head.LastTrustedAt.Unix() != command.TrustedAt.UnixSeconds ||
			command.TrustedAt.Source != trustedReservationSource(store.environment) {
			return ErrTrustedTimeMismatch
		}
		next, commandResult, err := controlplane.ApplyCommand(current, command)
		if err != nil {
			return err
		}
		writes, err := buildWriteSet(store.environment, head, current, next, command, commandResult, source)
		if err != nil {
			return err
		}
		if err := transaction.Buffer(writes); err != nil {
			return err
		}
		result = commandResult
		return nil
	})
	if err != nil {
		return controlplane.TransactionResult{}, err
	}
	trusted, err := controlplane.NewTrustedInstant(commitTime.Unix(), authorityCommitSource(store.environment), command.TrustedAt.Sequence)
	if err != nil {
		return controlplane.TransactionResult{}, err
	}
	return controlplane.TransactionResult{
		Receipt: result.Receipt, Revision: result.Receipt.Revision,
		Sequence: result.Receipt.Sequence, TrustedCommitTime: trusted,
		AuditHash: result.AuditHash, OutboxIDs: append([]string(nil), result.OutboxIDs...),
	}, nil
}

func (store *Store) ReadAuthoritySource(ctx context.Context, operationID string) (authoritysource.Protected, error) {
	reader, ok := store.client.(interface {
		StrongReadRecord(context.Context, string, string, string) (JSONRecord, error)
	})
	if !ok || !environmentRE.MatchString(store.environment) || !recordIDRE.MatchString(operationID) {
		return authoritysource.Protected{}, ErrInvalidConfiguration
	}
	record, err := reader.StrongReadRecord(ctx, "AuthoritySources", store.environment, operationID)
	if err != nil {
		return authoritysource.Protected{}, err
	}
	var source authoritysource.Protected
	if err := json.Unmarshal(record.Payload, &source); err != nil || source.Schema != authoritysource.Schema ||
		source.OperationID != operationID || source.SubjectDigest != record.Parent {
		return authoritysource.Protected{}, ErrInvalidConfiguration
	}
	return source, nil
}

func (store *Store) Reserve(ctx context.Context, minimumExclusive int64) (controlplane.TrustedInstant, error) {
	var sequence uint64
	commitTime, err := store.client.ReadWrite(ctx, func(callbackContext context.Context, transaction Transaction) error {
		head, err := transaction.ReadHead(callbackContext, store.environment)
		if err != nil {
			return err
		}
		if head.SchemaVersion != SchemaVersion || head.LastTrustedAt.Unix() < minimumExclusive {
			return ErrTrustedTimeMismatch
		}
		sequence = head.TrustedSequence + 1
		head.TrustedSequence = sequence
		return transaction.Buffer(WriteSet{Head: head, ReserveCommitTime: true})
	})
	if err != nil {
		return controlplane.TrustedInstant{}, err
	}
	if commitTime.Unix() <= minimumExclusive {
		return controlplane.TrustedInstant{}, ErrTrustedTimeMismatch
	}
	return controlplane.NewTrustedInstant(commitTime.Unix(), trustedReservationSource(store.environment), sequence)
}

func decodeHead(head Head, environment string) (controlplane.State, error) {
	if head.Environment != environment || head.SchemaVersion != SchemaVersion ||
		head.NextSequence == 0 || head.TrustedSequence == 0 ||
		head.LastTrustedAt.IsZero() || len(head.StateJSON) == 0 {
		return controlplane.State{}, ErrInvalidConfiguration
	}
	var state controlplane.State
	if err := json.Unmarshal(head.StateJSON, &state); err != nil {
		return controlplane.State{}, fmt.Errorf("%w: state decode", ErrInvalidConfiguration)
	}
	if err := state.Validate(); err != nil || state.Revision != head.Revision || state.NextSequence != head.NextSequence {
		return controlplane.State{}, ErrInvalidConfiguration
	}
	return state, nil
}

func trustedReservationSource(environment string) string { return "spanner-reservation-" + environment }
func authorityCommitSource(environment string) string {
	return "spanner-authority-commit-" + environment
}

func encodeJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, ErrInvalidConfiguration
	}
	return raw, nil
}

func buildWriteSet(environment string, head Head, current, next controlplane.State, command controlplane.Command, result controlplane.CommandResult, source *authoritysource.Protected) (WriteSet, error) {
	rawState, err := encodeJSON(next)
	if err != nil {
		return WriteSet{}, err
	}
	writes := WriteSet{Head: Head{
		Environment: environment, Revision: next.Revision, NextSequence: next.NextSequence,
		TrustedSequence: head.TrustedSequence, LastTrustedAt: head.LastTrustedAt,
		StateJSON: rawState, SchemaVersion: SchemaVersion,
	}, ReserveCommitTime: true}
	if source != nil {
		if source.Schema != authoritysource.Schema || source.OperationID != result.Receipt.OperationID ||
			source.SubjectDigest != command.Request.SubjectDigest {
			return WriteSet{}, ErrInvalidConfiguration
		}
		raw, err := encodeJSON(*source)
		if err != nil {
			return WriteSet{}, err
		}
		writes.AuthoritySources = append(writes.AuthoritySources, JSONRecord{
			ID: source.OperationID, Parent: source.SubjectDigest, State: "STAGED", Payload: raw,
		})
	}

	operationID := result.Receipt.OperationID
	operation, exists := next.Operations[operationID]
	if !exists {
		return WriteSet{}, ErrInvalidConfiguration
	}
	operationRaw, err := encodeJSON(operation)
	if err != nil {
		return WriteSet{}, err
	}
	writes.Operations = append(writes.Operations, JSONRecord{ID: operation.ID, State: string(operation.State), Payload: operationRaw})
	for index, actorID := range operation.ApproverIDs {
		approvalRaw, err := encodeJSON(map[string]any{"actor_digest": controlplane.DigestLabel(actorID)})
		if err != nil {
			return WriteSet{}, err
		}
		writes.Approvals = append(writes.Approvals, JSONRecord{ID: controlplane.DigestLabel(actorID), Parent: operation.ID, Ordinal: uint64(index + 1), Payload: approvalRaw})
	}

	if command.Kind == controlplane.CommandExecute {
		if record, ok := next.Profiles[operation.TargetID]; ok {
			raw, err := encodeJSON(record)
			if err != nil {
				return WriteSet{}, err
			}
			writes.Profiles = append(writes.Profiles, JSONRecord{ID: record.ID, State: string(record.State), Payload: raw})
		}
		if record, ok := next.Relays[operation.TargetID]; ok {
			raw, err := encodeJSON(record)
			if err != nil {
				return WriteSet{}, err
			}
			writes.Relays = append(writes.Relays, JSONRecord{ID: record.ID, State: string(record.State), Payload: raw})
		}
		if len(next.Publications) > len(current.Publications) {
			publication := next.Publications[len(next.Publications)-1]
			raw, err := encodeJSON(publication)
			if err != nil {
				return WriteSet{}, err
			}
			writes.Publications = append(writes.Publications, JSONRecord{ID: fmt.Sprintf("%020d", publication.Version), Ordinal: publication.Version, Payload: raw})
		}
		if record, ok := next.EmergencyAuthorities[operation.ScopeDigest]; ok {
			raw, err := encodeJSON(record)
			if err != nil {
				return WriteSet{}, err
			}
			writes.EmergencyAuth = append(writes.EmergencyAuth, JSONRecord{ID: operation.ScopeDigest, State: fmt.Sprintf("revoked=%t", record.Revoked), Payload: raw})
		}
		if record, ok := next.Restrictions[operation.ScopeDigest]; ok {
			raw, err := encodeJSON(record)
			if err != nil {
				return WriteSet{}, err
			}
			writes.EmergencyRules = append(writes.EmergencyRules, JSONRecord{ID: operation.ScopeDigest, Ordinal: record.Epoch, Payload: raw})
		}
	}

	for _, entry := range next.Audit[len(current.Audit):] {
		raw, err := encodeJSON(entry)
		if err != nil {
			return WriteSet{}, err
		}
		writes.Audit = append(writes.Audit, JSONRecord{ID: fmt.Sprintf("%020d", entry.Sequence), Ordinal: entry.Sequence, Payload: raw})
	}
	for _, event := range next.Outbox[len(current.Outbox):] {
		raw, err := encodeJSON(event)
		if err != nil {
			return WriteSet{}, err
		}
		writes.Outbox = append(writes.Outbox, JSONRecord{ID: event.ID, Parent: event.OperationID, Ordinal: event.Sequence, State: "PENDING", Payload: raw})
	}
	key := command.IdempotencyKey
	if command.Kind == controlplane.CommandRequest {
		key = command.Request.IdempotencyKey
	}
	receiptRaw, err := encodeJSON(result.Receipt)
	if err != nil {
		return WriteSet{}, err
	}
	writes.Idempotency = append(writes.Idempotency, JSONRecord{ID: key, Parent: result.Receipt.OperationID, Ordinal: result.Receipt.Revision, Payload: receiptRaw})
	return writes, nil
}

var _ controlplane.ProductionTransactionStore = (*Store)(nil)
var _ controlplane.TrustedTimeSource = (*Store)(nil)
