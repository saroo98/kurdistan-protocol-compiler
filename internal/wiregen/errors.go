// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import "errors"

var (
	ErrInvalidPolicy   = errors.New("invalid wire-shape policy")
	ErrMissingCorpus   = errors.New("missing protocol feature corpus")
	ErrPolicyDrift     = errors.New("wire-shape policy fixture drift")
	ErrTraceLeak       = errors.New("wire-shape policy contains unsafe trace material")
	ErrRefuseOverwrite = errors.New("refusing to overwrite wiregen fixture")
)
