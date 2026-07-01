// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

import "errors"

var (
	ErrInvalidMeasurementReview = errors.New("invalid measurement review")
	ErrUnsafeMetadata           = errors.New("unsafe measurement metadata")
	ErrRefuseOverwrite          = errors.New("refusing to overwrite existing measurement review fixture")
)
