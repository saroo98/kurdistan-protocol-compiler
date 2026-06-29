// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import "errors"

var (
	ErrInvalidConfig = errors.New("invalid runtime config")
	ErrInvalidRole   = errors.New("invalid runtime role")
	ErrProfileLoad   = errors.New("runtime profile load failed")
	ErrNegotiation   = errors.New("runtime negotiation failed")
	ErrCompatibility = errors.New("runtime compatibility failed")
	ErrLifecycle     = errors.New("runtime lifecycle error")
	ErrLinkClosed    = errors.New("runtime link closed")
	ErrLinkQueueFull = errors.New("runtime link queue full")
	ErrLinkFailure   = errors.New("runtime link failure")
	ErrSessionLimit  = errors.New("runtime session limit reached")
	ErrStreamLimit   = errors.New("runtime stream limit reached")
	ErrSecureChannel = errors.New("runtime secure channel error")
	ErrTraceHygiene  = errors.New("runtime trace hygiene error")
)
