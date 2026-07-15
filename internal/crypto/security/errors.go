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

// strictSentinel keeps the v1 public string constant while retaining broad
// errors.Is classification for the legacy package categories.
type strictSentinel struct {
	text    string
	classes []error
}

func (e *strictSentinel) Error() string {
	return e.text
}

func (e *strictSentinel) GoString() string {
	return e.text
}

func (e *strictSentinel) Is(target error) bool {
	if target == e {
		return true
	}
	for _, class := range e.classes {
		if target == class {
			return true
		}
	}
	return false
}

func newStrictSentinel(text string, classes ...error) error {
	return &strictSentinel{text: text, classes: classes}
}

var (
	ErrPolicyInvalid          = newStrictSentinel("policy_invalid", ErrInvalidConfig)
	ErrNonceExhausted         = newStrictSentinel("nonce_exhausted", ErrNonceOverflow)
	ErrNonceMismatch          = newStrictSentinel("nonce_mismatch")
	ErrAuthenticationFailed   = newStrictSentinel("authentication_failed")
	ErrReplayDuplicate        = newStrictSentinel("replay_duplicate", ErrReplay)
	ErrReplayStale            = newStrictSentinel("replay_stale", ErrReplay)
	ErrReplayOutOfOrder       = newStrictSentinel("replay_out_of_order", ErrReplay)
	ErrReplayTooFarFuture     = newStrictSentinel("replay_too_far_future", ErrReplay)
	ErrReplayExhausted        = newStrictSentinel("replay_exhausted", ErrReplay)
	ErrAEADInvalid            = newStrictSentinel("aead_invalid", ErrInvalidConfig)
	ErrEnvelopeContextInvalid = newStrictSentinel("envelope_context_invalid", ErrInvalidConfig)
	ErrEnvelopeModeRejected   = newStrictSentinel("envelope_mode_rejected", ErrEnvelopeRejected)
)
