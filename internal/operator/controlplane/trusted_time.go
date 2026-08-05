// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"context"
	"fmt"
)

const MaxTrustedTimeSourceBytes = 128

// TrustedInstant is an instant obtained from an authority-owned time source.
// Local wall-clock time must not be converted to TrustedInstant by production
// request handlers.
type TrustedInstant struct {
	UnixSeconds int64
	Source      string
	Sequence    uint64
}

func NewTrustedInstant(unixSeconds int64, source string, sequence uint64) (TrustedInstant, error) {
	instant := TrustedInstant{UnixSeconds: unixSeconds, Source: source, Sequence: sequence}
	if err := instant.Validate(); err != nil {
		return TrustedInstant{}, err
	}
	return instant, nil
}

func (instant TrustedInstant) Validate() error {
	if instant.UnixSeconds <= 0 || instant.Sequence == 0 ||
		len(instant.Source) == 0 || len(instant.Source) > MaxTrustedTimeSourceBytes ||
		containsForbiddenText(instant.Source) {
		return fmt.Errorf("%w: trusted time", ErrInvalidInput)
	}
	return nil
}

// TrustedTimeSource reserves monotonically increasing instants. Production
// implementations must obtain them from the authority database or an equally
// strong trusted service, never from the application process clock.
type TrustedTimeSource interface {
	Reserve(ctx context.Context, minimumExclusive int64) (TrustedInstant, error)
}
