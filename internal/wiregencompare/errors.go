// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregencompare

import "errors"

var (
	ErrBaselineDrift   = errors.New("wiregen baseline drift")
	ErrInvalidBaseline = errors.New("invalid wiregen baseline")
	ErrMissingPath     = errors.New("wiregen path required")
	ErrRefuseOverwrite = errors.New("refusing to overwrite wiregen output without force")
)
