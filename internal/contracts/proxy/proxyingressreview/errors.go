// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingressreview

import "errors"

var (
	ErrInvalidReview       = errors.New("invalid proxy ingress design review")
	ErrInvalidFailureMode  = errors.New("invalid proxy ingress failure mode")
	ErrInvalidParity       = errors.New("invalid proxy ingress parity")
	ErrInvalidMisuseReport = errors.New("invalid proxy ingress misuse report")
)
