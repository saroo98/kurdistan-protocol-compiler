// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

import "errors"

var (
	ErrInvalidConfig        = errors.New("invalid adapter config")
	ErrInvalidFlow          = errors.New("invalid adapter flow")
	ErrInvalidTransition    = errors.New("invalid adapter flow transition")
	ErrFlowExists           = errors.New("adapter flow already exists")
	ErrFlowNotFound         = errors.New("adapter flow not found")
	ErrFlowTerminal         = errors.New("adapter flow is terminal")
	ErrBackpressure         = errors.New("adapter backpressure")
	ErrCapabilityMismatch   = errors.New("adapter capability mismatch")
	ErrResourceLimit        = errors.New("adapter resource limit")
	ErrTraceHygiene         = errors.New("adapter trace hygiene")
	ErrUnsupportedOperation = errors.New("adapter operation unsupported")
)
