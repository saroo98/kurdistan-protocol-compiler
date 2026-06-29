// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

import "errors"

var (
	ErrInvalidFeature  = errors.New("invalid wire feature")
	ErrMissingPath     = errors.New("missing wire feature path")
	ErrRefuseOverwrite = errors.New("refusing to overwrite existing wire feature file without force")
	ErrTraceLeak       = errors.New("wire feature trace hygiene failure")
	ErrBaselineDrift   = errors.New("wire feature baseline drift")
)
