// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

import "errors"

var (
	ErrInvalidCandidate     = errors.New("invalid adaptive path candidate")
	ErrInvalidFamily        = errors.New("invalid adaptive path family")
	ErrInvalidCondition     = errors.New("invalid adaptive path condition")
	ErrInvalidObservation   = errors.New("invalid adaptive path observation")
	ErrInvalidFreshness     = errors.New("invalid adaptive path freshness")
	ErrInvalidViability     = errors.New("invalid adaptive path viability")
	ErrInvalidDecisionInput = errors.New("invalid adaptive path decision input")
	ErrInvalidFixture       = errors.New("invalid adaptive path fixture")
	ErrUnsafeAdaptivePath   = errors.New("unsafe adaptive path metadata")
	ErrRefuseOverwrite      = errors.New("refusing to overwrite adaptive path fixture")
)
