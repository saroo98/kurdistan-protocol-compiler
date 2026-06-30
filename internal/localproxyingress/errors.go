// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import "errors"

var (
	ErrInvalidConfig      = errors.New("invalid local proxy ingress config")
	ErrInvalidEvent       = errors.New("invalid local proxy ingress event")
	ErrQueueOverflow      = errors.New("local proxy ingress queue overflow")
	ErrDuplicateEvent     = errors.New("duplicate local proxy ingress event")
	ErrLifecycleViolation = errors.New("local proxy ingress lifecycle violation")
	ErrInvalidBinding     = errors.New("invalid local proxy ingress target binding")
	ErrInvalidSummary     = errors.New("invalid local proxy ingress summary")
	ErrRefuseOverwrite    = errors.New("refusing to overwrite local proxy ingress fixture")
)
