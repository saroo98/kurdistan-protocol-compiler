// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

func RequiresManualReview(field ObservationField) bool {
	return field.RedactionClass == RedactionManualReviewRequired || field.RedactionClass == RedactionHashWithLocalSalt
}
