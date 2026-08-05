// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package trustedtime

import (
	"context"
	"errors"
	"sync"

	"kurdistan/internal/operator/controlplane"
)

var ErrRollback = errors.New("trustedtime: rollback or fork")

type Reservoir interface {
	Reserve(context.Context, int64) (controlplane.TrustedInstant, error)
}

type Source struct {
	reservoir Reservoir
	mu        sync.Mutex
	last      controlplane.TrustedInstant
}

func New(reservoir Reservoir) (*Source, error) {
	if reservoir == nil {
		return nil, ErrRollback
	}
	return &Source{reservoir: reservoir}, nil
}

func (source *Source) Reserve(ctx context.Context, minimumExclusive int64) (controlplane.TrustedInstant, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.last.UnixSeconds > minimumExclusive {
		minimumExclusive = source.last.UnixSeconds
	}
	next, err := source.reservoir.Reserve(ctx, minimumExclusive)
	if err != nil {
		return controlplane.TrustedInstant{}, err
	}
	if err := next.Validate(); err != nil || next.UnixSeconds <= minimumExclusive ||
		(source.last.Sequence != 0 && next.Sequence <= source.last.Sequence) {
		return controlplane.TrustedInstant{}, ErrRollback
	}
	source.last = next
	return next, nil
}

var _ controlplane.TrustedTimeSource = (*Source)(nil)
