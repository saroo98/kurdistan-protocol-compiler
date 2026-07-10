// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxysem

import "errors"

var (
	ErrInvalidIntent     = errors.New("invalid relay intent")
	ErrUnknownTarget     = errors.New("unknown synthetic target")
	ErrInvalidDescriptor = errors.New("invalid target descriptor")
	ErrOversizedTarget   = errors.New("oversized synthetic target")
)

const (
	DefaultMaxRequestBytes  = 512 * 1024
	DefaultMaxResponseBytes = 2 * 1024 * 1024
)
