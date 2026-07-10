// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

import "errors"

var (
	ErrInvalidContract    = errors.New("invalid proxy ingress contract")
	ErrInvalidRequest     = errors.New("invalid proxy ingress request")
	ErrInvalidTarget      = errors.New("invalid target descriptor")
	ErrInvalidLifecycle   = errors.New("invalid proxy ingress lifecycle transition")
	ErrInvalidMapping     = errors.New("invalid proxy ingress mapping")
	ErrUnsafeMetadata     = errors.New("unsafe proxy ingress metadata")
	ErrRefuseOverwrite    = errors.New("refusing to overwrite existing proxy ingress fixture")
	ErrInvalidComparison  = errors.New("invalid proxy ingress comparison")
	ErrMissingCapability  = errors.New("missing proxy ingress capability")
	ErrUnsupportedIngress = errors.New("unsupported proxy ingress kind")
)
