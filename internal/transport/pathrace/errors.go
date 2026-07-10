// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import "errors"

var (
	ErrInvalidRace       = errors.New("invalid pathrace input")
	ErrUnsafeMetadata    = errors.New("pathrace trace hygiene failure")
	ErrBaselineDrift     = errors.New("pathrace baseline drift")
	ErrRefuseOverwrite   = errors.New("refusing to overwrite existing pathrace fixture")
	ErrNoUsableCandidate = errors.New("no usable synthetic pathrace candidate")
)
