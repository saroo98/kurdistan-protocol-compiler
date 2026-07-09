// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

import "errors"

var (
	ErrInvalidCorpus   = errors.New("invalid protocol corpus")
	ErrMissingPath     = errors.New("missing corpus path")
	ErrRefuseOverwrite = errors.New("refusing to overwrite existing corpus without force")
	ErrTraceLeak       = errors.New("protocol corpus trace hygiene failure")
)
