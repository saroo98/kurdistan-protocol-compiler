// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

import "errors"

var (
	ErrInvalidHealth     = errors.New("invalid pathhealth fixture")
	ErrNoRaceWinner      = errors.New("pathhealth requires verified race winner")
	ErrDuplicateEvent    = errors.New("duplicate pathhealth event")
	ErrInvalidTransition = errors.New("invalid pathhealth transition")
	ErrUnsafeMetadata    = errors.New("unsafe pathhealth metadata")
	ErrRefuseOverwrite   = errors.New("refusing to overwrite existing pathhealth output without force")
)
