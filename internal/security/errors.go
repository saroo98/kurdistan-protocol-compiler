// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import "errors"

var (
	ErrInvalidConfig       = errors.New("invalid security config")
	ErrInvalidSuite        = errors.New("invalid security suite")
	ErrInvalidTranscript   = errors.New("invalid transcript")
	ErrReplay              = errors.New("replay rejected")
	ErrDowngrade           = errors.New("downgrade rejected")
	ErrCompatibility       = errors.New("profile compatibility rejected")
	ErrNonceOverflow       = errors.New("nonce counter overflow")
	ErrEnvelopeRejected    = errors.New("secure envelope rejected")
	ErrCapabilityMismatch  = errors.New("capability mismatch")
	ErrTranscriptMismatch  = errors.New("transcript mismatch")
	ErrSecretLeakCandidate = errors.New("secret leak candidate")
)
