// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package trustedtime

import (
	"context"
	"errors"
	"testing"

	"kurdistan/internal/operator/controlplane"
)

type scriptedReservoir struct {
	values []controlplane.TrustedInstant
	index  int
}

func (reservoir *scriptedReservoir) Reserve(context.Context, int64) (controlplane.TrustedInstant, error) {
	if reservoir.index >= len(reservoir.values) {
		return controlplane.TrustedInstant{}, errors.New("empty")
	}
	value := reservoir.values[reservoir.index]
	reservoir.index++
	return value, nil
}

func TestSourceRejectsTimeAndSequenceRollback(t *testing.T) {
	reservoir := &scriptedReservoir{values: []controlplane.TrustedInstant{
		{UnixSeconds: 101, Source: "spanner-reservation-qualification", Sequence: 2},
		{UnixSeconds: 102, Source: "spanner-reservation-qualification", Sequence: 2},
	}}
	source, err := New(reservoir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Reserve(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Reserve(context.Background(), 100); !errors.Is(err, ErrRollback) {
		t.Fatalf("sequence rollback accepted: %v", err)
	}
}
