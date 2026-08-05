// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package spannerstore

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"kurdistan/internal/operator/controlplane"
	"kurdistan/internal/product/profile"
)

type memoryClient struct {
	mu            sync.Mutex
	head          Head
	commit        time.Time
	retryCallback bool
	writes        []WriteSet
}

type memoryTransaction struct {
	head   Head
	writes *WriteSet
}

func newMemoryClient(t *testing.T) *memoryClient {
	t.Helper()
	state := controlplane.NewState()
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return &memoryClient{head: Head{
		Environment: "qualification", Revision: 0, NextSequence: 1,
		TrustedSequence: 1, LastTrustedAt: time.Unix(100, 0).UTC(),
		StateJSON: raw, SchemaVersion: SchemaVersion,
	}, commit: time.Unix(100, 0).UTC()}
}

func (client *memoryClient) StrongReadHead(context.Context, string) (Head, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	return cloneHead(client.head), nil
}

func (client *memoryClient) ReadWrite(ctx context.Context, callback func(context.Context, Transaction) error) (time.Time, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	attempts := 1
	if client.retryCallback {
		attempts = 2
	}
	for attempt := 0; attempt < attempts; attempt++ {
		transaction := &memoryTransaction{head: cloneHead(client.head)}
		if err := callback(ctx, transaction); err != nil {
			return time.Time{}, err
		}
		if attempt+1 != attempts {
			continue
		}
		if transaction.writes == nil {
			return time.Time{}, errors.New("memory client: missing writes")
		}
		client.commit = client.commit.Add(time.Second)
		client.head = cloneHead(transaction.writes.Head)
		if transaction.writes.ReserveCommitTime {
			client.head.LastTrustedAt = client.commit
		}
		client.writes = append(client.writes, *transaction.writes)
		return client.commit, nil
	}
	return time.Time{}, errors.New("memory client: unreachable")
}

func (transaction *memoryTransaction) ReadHead(context.Context, string) (Head, error) {
	return cloneHead(transaction.head), nil
}

func (transaction *memoryTransaction) Buffer(writes WriteSet) error {
	copy := writes
	copy.Head = cloneHead(writes.Head)
	transaction.writes = &copy
	return nil
}

func cloneHead(head Head) Head {
	head.StateJSON = append([]byte(nil), head.StateJSON...)
	return head
}

func TestReserveAndExecuteUseTrustedSpannerTime(t *testing.T) {
	client := newMemoryClient(t)
	client.retryCallback = true
	store, err := New(client, "qualification")
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := store.Reserve(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if trusted.UnixSeconds != 101 || trusted.Sequence != 2 || trusted.Source != "spanner-reservation-qualification" {
		t.Fatalf("trusted instant=%+v", trusted)
	}

	request := publicationRequest(trusted.UnixSeconds)
	actor := controlplane.Actor{ID: "operator-requester", AuthorityRole: profile.RoleOperator, Duties: []controlplane.Duty{controlplane.DutyRequest}}
	command, err := controlplane.NewRequestCommand(actor, request, trusted)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.Execute(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if result.Revision != 1 || result.Sequence != 1 || result.TrustedCommitTime.UnixSeconds != 102 || len(result.OutboxIDs) != 0 {
		t.Fatalf("transaction result=%+v", result)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || snapshot.Operations[request.ID].State != controlplane.OperationPending {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	if len(client.writes) != 2 || len(client.writes[1].Operations) != 1 || len(client.writes[1].Audit) != 1 || len(client.writes[1].Idempotency) != 1 {
		t.Fatalf("same-transaction projections missing: %+v", client.writes)
	}
}

func TestExecuteRejectsUnreservedAndReplayedTrustedTime(t *testing.T) {
	client := newMemoryClient(t)
	store, _ := New(client, "qualification")
	trusted, _ := controlplane.NewTrustedInstant(101, "spanner-reservation-qualification", 2)
	actor := controlplane.Actor{ID: "operator-requester", AuthorityRole: profile.RoleOperator, Duties: []controlplane.Duty{controlplane.DutyRequest}}
	command, err := controlplane.NewRequestCommand(actor, publicationRequest(101), trusted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Execute(context.Background(), command); !errors.Is(err, ErrTrustedTimeMismatch) {
		t.Fatalf("unreserved trusted time accepted: %v", err)
	}

	reserved, err := store.Reserve(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	command, _ = controlplane.NewRequestCommand(actor, publicationRequest(reserved.UnixSeconds), reserved)
	if _, err := store.Execute(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Execute(context.Background(), command); !errors.Is(err, ErrTrustedTimeMismatch) {
		t.Fatalf("trusted reservation replay accepted: %v", err)
	}
}

func TestRetryCallbackIsDeterministic(t *testing.T) {
	leftClient := newMemoryClient(t)
	rightClient := newMemoryClient(t)
	leftClient.retryCallback = true
	left, _ := New(leftClient, "qualification")
	right, _ := New(rightClient, "qualification")
	leftTrusted, _ := left.Reserve(context.Background(), 100)
	rightTrusted, _ := right.Reserve(context.Background(), 100)
	actor := controlplane.Actor{ID: "operator-requester", AuthorityRole: profile.RoleOperator, Duties: []controlplane.Duty{controlplane.DutyRequest}}
	leftCommand, _ := controlplane.NewRequestCommand(actor, publicationRequest(leftTrusted.UnixSeconds), leftTrusted)
	rightCommand, _ := controlplane.NewRequestCommand(actor, publicationRequest(rightTrusted.UnixSeconds), rightTrusted)
	if _, err := left.Execute(context.Background(), leftCommand); err != nil {
		t.Fatal(err)
	}
	if _, err := right.Execute(context.Background(), rightCommand); err != nil {
		t.Fatal(err)
	}
	leftState, _ := left.Snapshot(context.Background())
	rightState, _ := right.Snapshot(context.Background())
	if !reflect.DeepEqual(leftState, rightState) {
		t.Fatal("transaction callback retry changed authority state")
	}
}

func publicationRequest(createdAt int64) controlplane.RequestInput {
	return controlplane.RequestInput{
		ID: "operation-publication-001", Action: controlplane.ActionPublishSnapshot,
		TargetID: "publication-primary", SubjectDigest: controlplane.DigestLabel("publication-subject"),
		ScopeDigest: controlplane.DigestLabel("publication-scope"), ExpectedRevision: 0,
		ExpectedEpoch: 0, ResultEpoch: 0, CreatedAt: createdAt, ExpiresAt: createdAt + 600,
		IdempotencyKey: "idempotency-publication-001",
		Publication: &controlplane.PublicationInput{Version: 1, RootVersion: 1,
			SnapshotDigest: controlplane.DigestLabel("snapshot"), TargetsDigest: controlplane.DigestLabel("targets"),
			ValidUntil: createdAt + 3600},
	}
}
