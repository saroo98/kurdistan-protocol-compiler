// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import "errors"

var (
	ErrInvalidPolicy   = errors.New("invalid transport bundle policy")
	ErrInvalidBundle   = errors.New("invalid transport bundle")
	ErrUnsafeBundle    = errors.New("unsafe transport bundle metadata")
	ErrRefuseOverwrite = errors.New("refusing to overwrite existing transport bundle fixture")
)
