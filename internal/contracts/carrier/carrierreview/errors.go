// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrierreview

import "errors"

var (
	ErrInvalidCarrierReview = errors.New("invalid carrier review")
	ErrUnsafeMetadata       = errors.New("unsafe carrier review metadata")
	ErrRefuseOverwrite      = errors.New("refusing to overwrite existing carrier review fixture")
)
