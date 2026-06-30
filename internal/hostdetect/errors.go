// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import "errors"

var (
	ErrInvalidObservation = errors.New("invalid hostdetect observation")
	ErrInvalidAssignment  = errors.New("invalid hostdetect assignment")
	ErrInvalidReport      = errors.New("invalid hostdetect report")
	ErrTraceLeak          = errors.New("hostdetect trace hygiene violation")
	ErrRefuseOverwrite    = errors.New("refusing to overwrite hostdetect output")
)
