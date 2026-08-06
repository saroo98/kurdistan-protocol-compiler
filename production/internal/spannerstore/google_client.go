// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package spannerstore

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/spanner"
)

type GoogleClient struct{ client *spanner.Client }

func NewGoogleClient(client *spanner.Client) (*GoogleClient, error) {
	if client == nil {
		return nil, ErrInvalidConfiguration
	}
	return &GoogleClient{client: client}, nil
}

func (client *GoogleClient) StrongReadHead(ctx context.Context, environment string) (Head, error) {
	row, err := client.client.Single().ReadRow(ctx, "AuthorityHead", spanner.Key{environment}, headColumns)
	if err != nil {
		return Head{}, err
	}
	return decodeHeadRow(row)
}

func (client *GoogleClient) StrongReadRecord(ctx context.Context, table, environment, recordID string) (JSONRecord, error) {
	row, err := client.client.Single().ReadRow(ctx, table, spanner.Key{environment, recordID}, []string{"RecordID", "ParentID", "Ordinal", "State", "PayloadJSON"})
	if err != nil {
		return JSONRecord{}, err
	}
	var value JSONRecord
	var ordinal int64
	var payload string
	if err := row.Columns(&value.ID, &value.Parent, &ordinal, &value.State, &payload); err != nil || ordinal < 0 {
		return JSONRecord{}, ErrInvalidConfiguration
	}
	value.Ordinal = uint64(ordinal)
	value.Payload = []byte(payload)
	return value, nil
}

func (client *GoogleClient) ReadWrite(ctx context.Context, callback func(context.Context, Transaction) error) (time.Time, error) {
	return client.client.ReadWriteTransaction(ctx, func(transactionContext context.Context, transaction *spanner.ReadWriteTransaction) error {
		return callback(transactionContext, &googleTransaction{transaction: transaction})
	})
}

type googleTransaction struct{ transaction *spanner.ReadWriteTransaction }

func (transaction *googleTransaction) ReadHead(ctx context.Context, environment string) (Head, error) {
	row, err := transaction.transaction.ReadRow(ctx, "AuthorityHead", spanner.Key{environment}, headColumns)
	if err != nil {
		return Head{}, err
	}
	return decodeHeadRow(row)
}

func (transaction *googleTransaction) Buffer(writes WriteSet) error {
	mutations, err := googleMutations(writes)
	if err != nil {
		return err
	}
	return transaction.transaction.BufferWrite(mutations)
}

var headColumns = []string{"Environment", "Revision", "NextSequence", "TrustedSequence", "LastTrustedAt", "StateJSON", "SchemaVersion"}

func decodeHeadRow(row *spanner.Row) (Head, error) {
	var environment, stateJSON, schemaVersion string
	var revision, nextSequence, trustedSequence int64
	var lastTrustedAt time.Time
	if err := row.Columns(&environment, &revision, &nextSequence, &trustedSequence, &lastTrustedAt, &stateJSON, &schemaVersion); err != nil {
		return Head{}, err
	}
	if revision < 0 || nextSequence <= 0 || trustedSequence <= 0 {
		return Head{}, ErrInvalidConfiguration
	}
	return Head{
		Environment: environment, Revision: uint64(revision), NextSequence: uint64(nextSequence),
		TrustedSequence: uint64(trustedSequence), LastTrustedAt: lastTrustedAt,
		StateJSON: []byte(stateJSON), SchemaVersion: schemaVersion,
	}, nil
}

func googleMutations(writes WriteSet) ([]*spanner.Mutation, error) {
	if writes.Head.Environment == "" || writes.Head.SchemaVersion != SchemaVersion {
		return nil, ErrInvalidConfiguration
	}
	lastTrustedAt := any(writes.Head.LastTrustedAt)
	if writes.ReserveCommitTime {
		lastTrustedAt = spanner.CommitTimestamp
	}
	mutations := []*spanner.Mutation{spanner.UpdateMap("AuthorityHead", map[string]any{
		"Environment": writes.Head.Environment, "Revision": int64(writes.Head.Revision),
		"NextSequence": int64(writes.Head.NextSequence), "TrustedSequence": int64(writes.Head.TrustedSequence),
		"LastTrustedAt": lastTrustedAt, "StateJSON": string(writes.Head.StateJSON), "SchemaVersion": writes.Head.SchemaVersion,
		"UpdatedAt": spanner.CommitTimestamp,
	})}
	for _, record := range writes.AuthoritySources {
		mutations = append(mutations, spanner.InsertMap("AuthoritySources", recordMap(writes.Head.Environment, record)))
	}
	appendRecords := func(table string, records []JSONRecord) {
		for _, record := range records {
			mutations = append(mutations, spanner.InsertOrUpdateMap(table, recordMap(writes.Head.Environment, record)))
		}
	}
	appendRecords("Operations", writes.Operations)
	appendRecords("Approvals", writes.Approvals)
	appendRecords("Profiles", writes.Profiles)
	appendRecords("Relays", writes.Relays)
	appendRecords("Publications", writes.Publications)
	appendRecords("EmergencyAuthorities", writes.EmergencyAuth)
	appendRecords("EmergencyRestrictions", writes.EmergencyRules)
	appendRecords("OutboxEvents", writes.Outbox)
	appendRecords("AuditEvents", writes.Audit)
	appendRecords("IdempotencyReceipts", writes.Idempotency)
	return mutations, nil
}

func recordMap(environment string, record JSONRecord) map[string]any {
	return map[string]any{
		"Environment": environment, "RecordID": record.ID, "ParentID": record.Parent,
		"Ordinal": int64(record.Ordinal), "State": record.State, "PayloadJSON": string(record.Payload),
		"UpdatedAt": spanner.CommitTimestamp,
	}
}

func InitializeGoogle(ctx context.Context, client *spanner.Client, environment string, initialStateJSON []byte) (time.Time, error) {
	if client == nil || !environmentRE.MatchString(environment) || len(initialStateJSON) == 0 {
		return time.Time{}, ErrInvalidConfiguration
	}
	mutation := spanner.InsertMap("AuthorityHead", map[string]any{
		"Environment": environment, "Revision": int64(0), "NextSequence": int64(1),
		"TrustedSequence": int64(1), "LastTrustedAt": spanner.CommitTimestamp,
		"StateJSON": string(initialStateJSON), "SchemaVersion": SchemaVersion, "UpdatedAt": spanner.CommitTimestamp,
	})
	commitTime, err := client.Apply(ctx, []*spanner.Mutation{mutation})
	if err != nil {
		return time.Time{}, fmt.Errorf("initialize authority head: %w", err)
	}
	return commitTime, nil
}

var _ Client = (*GoogleClient)(nil)
