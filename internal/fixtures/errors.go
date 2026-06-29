// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import "errors"

var (
	ErrFixtureDrift    = errors.New("fixture drift")
	ErrFixtureInvalid  = errors.New("fixture invalid")
	ErrMissingPath     = errors.New("fixture path required")
	ErrRefuseOverwrite = errors.New("refusing to overwrite fixture")
	ErrTraceLeak       = errors.New("fixture trace hygiene leak")
)
