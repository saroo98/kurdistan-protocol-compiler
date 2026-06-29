// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

import "errors"

var (
	ErrInvalidDataset  = errors.New("invalid wireeval dataset")
	ErrInvalidRecord   = errors.New("invalid wireeval record")
	ErrTraceLeak       = errors.New("wireeval trace hygiene failure")
	ErrBaselineDrift   = errors.New("wireeval baseline drift")
	ErrRefuseOverwrite = errors.New("refusing to overwrite existing wireeval output")
)
