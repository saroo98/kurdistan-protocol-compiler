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

type profileLoadFailureV1 struct{ cause error }

func (profileLoadFailureV1) Error() string { return ErrProfileLoad.Error() }
func (e profileLoadFailureV1) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrProfileLoad}
	}
	return []error{ErrProfileLoad, e.cause}
}

func newProfileLoadFailureV1(cause error) error { return profileLoadFailureV1{cause: cause} }

var (
	ErrRecordInvalid           = errors.New("record_invalid")
	ErrOperationAckInvalid     = errors.New("operation_ack_invalid")
	ErrKeyLifetimeExhausted    = errors.New("key_lifetime_exhausted")
	ErrRekeyFailed             = errors.New("rekey_failed")
	ErrProfileRotationRequired = errors.New("profile_rotation_required")
	ErrSessionMessageLimit     = errors.New("session_message_limit")
)
