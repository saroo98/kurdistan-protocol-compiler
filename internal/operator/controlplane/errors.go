// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import "errors"

var (
	ErrInvalidInput       = errors.New("controlplane: invalid input")
	ErrUnauthorized       = errors.New("controlplane: unauthorized")
	ErrConflict           = errors.New("controlplane: revision or state conflict")
	ErrInsufficientQuorum = errors.New("controlplane: approval quorum not met")
	ErrExpired            = errors.New("controlplane: operation expired")
	ErrIdempotency        = errors.New("controlplane: idempotency conflict")
	ErrAuditChain         = errors.New("controlplane: audit chain invalid")
	ErrJournal            = errors.New("controlplane: journal invalid")
)
