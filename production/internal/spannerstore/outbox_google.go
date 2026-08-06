// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package spannerstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"cloud.google.com/go/spanner"
	"google.golang.org/api/iterator"

	"kurdistan/internal/operator/controlplane"
	"kurdistan/production/internal/outbox"
)

const maxOutboxScan = controlplane.MaxOutboxEvents

var outboxIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)
var outboxDigestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

type GoogleOutboxRepository struct {
	client      *spanner.Client
	environment string
}

type leasedOutboxRow struct {
	ID, OperationID, State, Payload, LeaseOwner string
	Sequence, FencingToken, AttemptCount        int64
	LeaseUntil                                  time.Time
}

func NewGoogleOutboxRepository(client *spanner.Client, environment string) (*GoogleOutboxRepository, error) {
	if client == nil || !environmentRE.MatchString(environment) {
		return nil, ErrInvalidConfiguration
	}
	return &GoogleOutboxRepository{client: client, environment: environment}, nil
}

func (repository *GoogleOutboxRepository) Lease(ctx context.Context, workerID string, _ time.Time, lease time.Duration, limit int) ([]outbox.Event, error) {
	if ctx == nil || !environmentRE.MatchString(repository.environment) || !outboxIDRE.MatchString(workerID) ||
		lease < 5*time.Second || lease > 5*time.Minute || limit < 1 || limit > outbox.MaxBatchSize {
		return nil, outbox.ErrInvalid
	}
	var leased []outbox.Event
	_, err := repository.client.ReadWriteTransaction(ctx, func(txctx context.Context, transaction *spanner.ReadWriteTransaction) error {
		now, err := transactionTime(txctx, transaction)
		if err != nil {
			return err
		}
		rows, err := eligibleOutboxRows(txctx, transaction, repository.environment, now)
		if err != nil {
			return err
		}
		sort.SliceStable(rows, func(i, j int) bool {
			left, right := emergencyKind(rows[i].Payload), emergencyKind(rows[j].Payload)
			if left != right {
				return left
			}
			return rows[i].Sequence < rows[j].Sequence
		})
		if len(rows) > limit {
			rows = rows[:limit]
		}
		mutations := make([]*spanner.Mutation, 0, len(rows))
		leaseUntil := now.Add(lease)
		for _, row := range rows {
			if row.FencingToken < 0 || row.AttemptCount < 0 || row.AttemptCount >= outbox.MaxAttempts {
				return outbox.ErrInvalid
			}
			var event controlplane.OutboxEvent
			if len(row.Payload) == 0 || len(row.Payload) > 1<<20 || json.Unmarshal([]byte(row.Payload), &event) != nil ||
				event.ID != row.ID || event.OperationID != row.OperationID || event.Sequence != uint64(row.Sequence) ||
				event.Attempts != uint32(row.AttemptCount) || event.DeliveredAt != 0 || event.FailedAt != 0 {
				return outbox.ErrInvalid
			}
			fence := row.FencingToken + 1
			mutations = append(mutations, spanner.UpdateMap("OutboxEvents", map[string]any{
				"Environment": repository.environment, "RecordID": row.ID, "State": "LEASED",
				"LeaseOwner": workerID, "LeaseUntil": leaseUntil, "FencingToken": fence,
				"AttemptCount": row.AttemptCount, "UpdatedAt": spanner.CommitTimestamp,
			}))
			leased = append(leased, outbox.Event{
				ID: event.ID, Kind: event.Kind, OperationID: event.OperationID, SubjectDigest: event.SubjectDigest,
				Sequence: event.Sequence, Attempts: event.Attempts, Emergency: isEmergencyAction(event.Kind),
				LeaseToken: uint64(fence), LeaseUntil: leaseUntil,
			})
		}
		return transaction.BufferWrite(mutations)
	})
	if err != nil {
		return nil, err
	}
	return leased, nil
}

func (repository *GoogleOutboxRepository) Complete(ctx context.Context, eventID string, leaseToken uint64, outcome outbox.Outcome) error {
	if ctx == nil || !outboxIDRE.MatchString(eventID) || leaseToken == 0 ||
		outcome.EffectID != "phase16-effect-"+eventID || !outboxDigestRE.MatchString(outcome.Digest) {
		return outbox.ErrInvalid
	}
	return repository.resolve(ctx, eventID, leaseToken, outcome, false, false)
}

func (repository *GoogleOutboxRepository) Retry(ctx context.Context, eventID string, leaseToken uint64, reason string, terminal bool) error {
	if ctx == nil || !outboxIDRE.MatchString(eventID) || leaseToken == 0 || reason == "" || len(reason) > 64 {
		return outbox.ErrInvalid
	}
	return repository.resolve(ctx, eventID, leaseToken, outbox.Outcome{}, true, terminal)
}

func (repository *GoogleOutboxRepository) resolve(ctx context.Context, eventID string, leaseToken uint64, outcome outbox.Outcome, failed, terminal bool) error {
	_, err := repository.client.ReadWriteTransaction(ctx, func(txctx context.Context, transaction *spanner.ReadWriteTransaction) error {
		now, err := transactionTime(txctx, transaction)
		if err != nil {
			return err
		}
		row, err := readLeasedOutboxRow(txctx, transaction, repository.environment, eventID)
		if err != nil {
			return err
		}
		if row.State == "DELIVERED" && !failed {
			var delivered controlplane.OutboxEvent
			if json.Unmarshal([]byte(row.Payload), &delivered) == nil && delivered.OutcomeDigest == outcome.Digest {
				return nil
			}
		}
		if row.State != "LEASED" || row.LeaseOwner == "" || row.FencingToken != int64(leaseToken) ||
			!row.LeaseUntil.After(now) || row.AttemptCount < 0 || row.AttemptCount >= outbox.MaxAttempts {
			return outbox.ErrLeaseLost
		}
		head, err := readHeadInTransaction(txctx, transaction, repository.environment)
		if err != nil {
			return err
		}
		state, err := decodeHead(head, repository.environment)
		if err != nil {
			return err
		}
		resolution := controlplane.ProductionEffectResolution{
			EventID: eventID, EffectID: "phase16-effect-" + eventID, WorkerID: row.LeaseOwner,
			Attempt: uint32(row.AttemptCount + 1), At: now.Unix(), Outcome: controlplane.ProductionEffectDelivered,
			ReceiptHash: outcome.Digest,
		}
		stateLabel := "DELIVERED"
		if failed {
			resolution.ReceiptHash = ""
			resolution.Outcome = controlplane.ProductionEffectRetry
			stateLabel = "RETRY"
			if terminal {
				resolution.Outcome = controlplane.ProductionEffectTerminal
				stateLabel = "DEAD"
			}
		}
		next, _, err := controlplane.ApplyProductionEffectResolution(state, resolution)
		if err != nil {
			return err
		}
		return bufferResolvedState(transaction, repository.environment, head, state, next, eventID, stateLabel)
	})
	if errors.Is(err, spanner.ErrRowNotFound) {
		return outbox.ErrLeaseLost
	}
	return err
}

func transactionTime(ctx context.Context, transaction *spanner.ReadWriteTransaction) (time.Time, error) {
	rows := transaction.Query(ctx, spanner.Statement{SQL: "SELECT CURRENT_TIMESTAMP()"})
	defer rows.Stop()
	row, err := rows.Next()
	if err != nil {
		return time.Time{}, err
	}
	var now time.Time
	if err := row.Columns(&now); err != nil || now.IsZero() {
		return time.Time{}, ErrTrustedTimeMismatch
	}
	return now.UTC(), nil
}

func eligibleOutboxRows(ctx context.Context, transaction *spanner.ReadWriteTransaction, environment string, now time.Time) ([]leasedOutboxRow, error) {
	statement := spanner.Statement{SQL: `SELECT RecordID, ParentID, Ordinal, State, PayloadJSON, FencingToken, AttemptCount
FROM OutboxEvents
WHERE Environment=@environment AND State IN ('PENDING','RETRY')
  AND (LeaseUntil IS NULL OR LeaseUntil<=@now) AND AttemptCount<@maxAttempts
ORDER BY Ordinal LIMIT @limit`, Params: map[string]any{
		"environment": environment, "now": now, "maxAttempts": int64(outbox.MaxAttempts), "limit": int64(maxOutboxScan),
	}}
	rowsIterator := transaction.Query(ctx, statement)
	defer rowsIterator.Stop()
	rows := make([]leasedOutboxRow, 0, outbox.MaxBatchSize)
	for {
		row, err := rowsIterator.Next()
		if errors.Is(err, iterator.Done) {
			return rows, nil
		}
		if err != nil {
			return nil, err
		}
		var value leasedOutboxRow
		if err := row.Columns(&value.ID, &value.OperationID, &value.Sequence, &value.State, &value.Payload, &value.FencingToken, &value.AttemptCount); err != nil {
			return nil, err
		}
		rows = append(rows, value)
	}
}

func readLeasedOutboxRow(ctx context.Context, transaction *spanner.ReadWriteTransaction, environment, eventID string) (leasedOutboxRow, error) {
	row, err := transaction.ReadRow(ctx, "OutboxEvents", spanner.Key{environment, eventID}, []string{
		"RecordID", "ParentID", "Ordinal", "State", "PayloadJSON", "LeaseOwner", "LeaseUntil", "FencingToken", "AttemptCount",
	})
	if err != nil {
		return leasedOutboxRow{}, err
	}
	var value leasedOutboxRow
	var owner spanner.NullString
	var until spanner.NullTime
	if err := row.Columns(&value.ID, &value.OperationID, &value.Sequence, &value.State, &value.Payload, &owner, &until, &value.FencingToken, &value.AttemptCount); err != nil {
		return leasedOutboxRow{}, err
	}
	if owner.Valid {
		value.LeaseOwner = owner.StringVal
	}
	if until.Valid {
		value.LeaseUntil = until.Time
	}
	return value, nil
}

func readHeadInTransaction(ctx context.Context, transaction *spanner.ReadWriteTransaction, environment string) (Head, error) {
	row, err := transaction.ReadRow(ctx, "AuthorityHead", spanner.Key{environment}, headColumns)
	if err != nil {
		return Head{}, err
	}
	return decodeHeadRow(row)
}

func bufferResolvedState(transaction *spanner.ReadWriteTransaction, environment string, head Head, previous, next controlplane.State, eventID, stateLabel string) error {
	rawState, err := encodeJSON(next)
	if err != nil {
		return err
	}
	var event controlplane.OutboxEvent
	for _, candidate := range next.Outbox {
		if candidate.ID == eventID {
			event = candidate
			break
		}
	}
	if event.ID == "" || len(next.Audit) != len(previous.Audit)+1 {
		return ErrInvalidConfiguration
	}
	eventRaw, err := encodeJSON(event)
	if err != nil {
		return err
	}
	audit := next.Audit[len(next.Audit)-1]
	auditRaw, err := encodeJSON(audit)
	if err != nil {
		return err
	}
	mutations := []*spanner.Mutation{
		spanner.UpdateMap("AuthorityHead", map[string]any{
			"Environment": environment, "Revision": int64(next.Revision), "NextSequence": int64(next.NextSequence),
			"TrustedSequence": int64(head.TrustedSequence + 1), "LastTrustedAt": spanner.CommitTimestamp,
			"StateJSON": string(rawState), "SchemaVersion": SchemaVersion, "UpdatedAt": spanner.CommitTimestamp,
		}),
		spanner.UpdateMap("OutboxEvents", map[string]any{
			"Environment": environment, "RecordID": event.ID, "State": stateLabel, "PayloadJSON": string(eventRaw),
			"LeaseOwner": nil, "LeaseUntil": nil, "AttemptCount": int64(event.Attempts), "UpdatedAt": spanner.CommitTimestamp,
		}),
		spanner.InsertOrUpdateMap("AuditEvents", recordMap(environment, JSONRecord{ID: formatSequence(audit.Sequence), Ordinal: audit.Sequence, Payload: auditRaw})),
	}
	for key, receipt := range next.Idempotency {
		if _, existed := previous.Idempotency[key]; existed {
			continue
		}
		raw, encodeErr := encodeJSON(receipt)
		if encodeErr != nil {
			return encodeErr
		}
		mutations = append(mutations, spanner.InsertOrUpdateMap("IdempotencyReceipts", recordMap(environment, JSONRecord{ID: key, Parent: receipt.OperationID, Ordinal: receipt.Revision, Payload: raw})))
	}
	return transaction.BufferWrite(mutations)
}

func formatSequence(sequence uint64) string { return fmt.Sprintf("%020d", sequence) }

func emergencyKind(payload string) bool {
	var event controlplane.OutboxEvent
	return json.Unmarshal([]byte(payload), &event) == nil && isEmergencyAction(event.Kind)
}

func isEmergencyAction(kind string) bool {
	return kind == string(controlplane.ActionEmergencyDeny) || kind == string(controlplane.ActionEmergencyNarrow) || kind == string(controlplane.ActionRevokeProfile)
}

var _ outbox.Repository = (*GoogleOutboxRepository)(nil)
