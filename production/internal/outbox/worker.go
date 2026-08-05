// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package outbox

import (
	"context"
	"errors"
	"sort"
	"time"
)

const (
	MaxBatchSize = 32
	MaxAttempts  = 5
)

var (
	ErrInvalid   = errors.New("outbox: invalid input")
	ErrLeaseLost = errors.New("outbox: lease lost")
)

type Event struct {
	ID            string
	Kind          string
	OperationID   string
	SubjectDigest string
	Sequence      uint64
	Attempts      uint32
	Emergency     bool
	LeaseToken    uint64
	LeaseUntil    time.Time
}

type Outcome struct {
	EffectID string
	Digest   string
}

type Repository interface {
	Lease(context.Context, string, time.Time, time.Duration, int) ([]Event, error)
	Complete(context.Context, string, uint64, Outcome) error
	Retry(context.Context, string, uint64, string, bool) error
}

type Handler interface {
	Deliver(context.Context, Event, string) (Outcome, error)
}

type Worker struct {
	repository Repository
	handler    Handler
	identity   string
	lease      time.Duration
}

func New(repository Repository, handler Handler, identity string, lease time.Duration) (*Worker, error) {
	if repository == nil || handler == nil || len(identity) < 3 || len(identity) > 128 || lease < 5*time.Second || lease > 5*time.Minute {
		return nil, ErrInvalid
	}
	return &Worker{repository: repository, handler: handler, identity: identity, lease: lease}, nil
}

func (worker *Worker) RunOnce(ctx context.Context, now time.Time, limit int) (int, error) {
	if ctx == nil || now.IsZero() || limit < 1 || limit > MaxBatchSize {
		return 0, ErrInvalid
	}
	events, err := worker.repository.Lease(ctx, worker.identity, now, worker.lease, limit)
	if err != nil {
		return 0, err
	}
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Emergency != events[j].Emergency {
			return events[i].Emergency
		}
		return events[i].Sequence < events[j].Sequence
	})
	completed := 0
	for _, event := range events {
		if err := validateEvent(event, now); err != nil {
			return completed, err
		}
		effectID := "phase16-effect-" + event.ID
		outcome, deliverErr := worker.handler.Deliver(ctx, event, effectID)
		if deliverErr != nil {
			terminal := event.Attempts+1 >= MaxAttempts
			if err := worker.repository.Retry(ctx, event.ID, event.LeaseToken, classify(deliverErr), terminal); err != nil {
				return completed, err
			}
			continue
		}
		if outcome.EffectID != effectID || len(outcome.Digest) != 64 {
			return completed, ErrInvalid
		}
		if err := worker.repository.Complete(ctx, event.ID, event.LeaseToken, outcome); err != nil {
			return completed, err
		}
		completed++
	}
	return completed, nil
}

func validateEvent(event Event, now time.Time) error {
	if len(event.ID) < 3 || len(event.ID) > 128 || len(event.Kind) == 0 || len(event.Kind) > 64 ||
		len(event.OperationID) < 3 || len(event.OperationID) > 128 || len(event.SubjectDigest) != 64 ||
		event.Sequence == 0 || event.Attempts >= MaxAttempts || event.LeaseToken == 0 || !event.LeaseUntil.After(now) {
		return ErrInvalid
	}
	return nil
}

func classify(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "cancelled"
	}
	return "delivery-failed"
}
