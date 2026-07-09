// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

import "errors"

var (
	ErrInvalidRelay      = errors.New("invalid relay")
	ErrInvalidFleet      = errors.New("invalid relay fleet")
	ErrInvalidPolicy     = errors.New("invalid fleet policy")
	ErrInvalidTransition = errors.New("invalid relay lifecycle transition")
	ErrInvalidReport     = errors.New("invalid relay fleet report")
	ErrTraceLeak         = errors.New("relay fleet trace hygiene violation")
	ErrRefuseOverwrite   = errors.New("refusing to overwrite existing relayfleet fixture")
)
