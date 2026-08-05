// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package outbox

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type fakeRepository struct {
	events      []Event
	completed   []string
	retried     []string
	terminal    bool
	completeErr error
}

func (repo *fakeRepository) Lease(context.Context, string, time.Time, time.Duration, int) ([]Event, error) {
	return append([]Event(nil), repo.events...), nil
}
func (repo *fakeRepository) Complete(_ context.Context, id string, token uint64, _ Outcome) error {
	if token != 7 {
		return ErrLeaseLost
	}
	repo.completed = append(repo.completed, id)
	return repo.completeErr
}
func (repo *fakeRepository) Retry(_ context.Context, id string, token uint64, reason string, terminal bool) error {
	if token != 7 || reason == "" {
		return ErrLeaseLost
	}
	repo.retried = append(repo.retried, id)
	repo.terminal = terminal
	return nil
}

type fakeHandler struct {
	order []string
	fail  string
}

func (handler *fakeHandler) Deliver(_ context.Context, event Event, effectID string) (Outcome, error) {
	handler.order = append(handler.order, event.ID)
	if event.ID == handler.fail {
		return Outcome{}, errors.New("unavailable")
	}
	return Outcome{EffectID: effectID, Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
}

func TestWorkerPrioritizesEmergencyAndFencesCompletion(t *testing.T) {
	now := time.Unix(100, 0)
	repo := &fakeRepository{events: []Event{
		{ID: "ordinary", Kind: "publish", OperationID: "operation-1", SubjectDigest: digest(), Sequence: 1, LeaseToken: 7, LeaseUntil: now.Add(time.Minute)},
		{ID: "emergency", Kind: "deny", OperationID: "operation-2", SubjectDigest: digest(), Sequence: 2, Emergency: true, LeaseToken: 7, LeaseUntil: now.Add(time.Minute)},
	}}
	handler := &fakeHandler{}
	worker, err := New(repo, handler, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := worker.RunOnce(context.Background(), now, 2)
	if err != nil || completed != 2 {
		t.Fatalf("completed=%d err=%v", completed, err)
	}
	if !reflect.DeepEqual(handler.order, []string{"emergency", "ordinary"}) {
		t.Fatalf("order=%v", handler.order)
	}

	repo.completeErr = ErrLeaseLost
	if _, err := worker.RunOnce(context.Background(), now, 2); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale lease error=%v", err)
	}
}

func TestWorkerRetriesAndTerminatesAtBound(t *testing.T) {
	now := time.Unix(100, 0)
	repo := &fakeRepository{events: []Event{{ID: "event-1", Kind: "publish", OperationID: "operation-1", SubjectDigest: digest(), Sequence: 1, Attempts: MaxAttempts - 1, LeaseToken: 7, LeaseUntil: now.Add(time.Minute)}}}
	handler := &fakeHandler{fail: "event-1"}
	worker, _ := New(repo, handler, "worker-a", time.Minute)
	if completed, err := worker.RunOnce(context.Background(), now, 1); err != nil || completed != 0 || !repo.terminal {
		t.Fatalf("completed=%d terminal=%v err=%v", completed, repo.terminal, err)
	}
}

func digest() string { return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
