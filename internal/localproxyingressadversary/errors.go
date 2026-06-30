// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

import "errors"

var (
	ErrInvalidCorpus     = errors.New("invalid local proxy ingress adversarial corpus")
	ErrInvalidDescriptor = errors.New("invalid local proxy ingress adversarial descriptor case")
	ErrInvalidReport     = errors.New("invalid local proxy ingress adversarial report")
	ErrUnsafeFixture     = errors.New("unsafe local proxy ingress adversarial fixture")
	ErrRefuseOverwrite   = errors.New("refusing to overwrite existing local proxy ingress adversarial fixture")
)
