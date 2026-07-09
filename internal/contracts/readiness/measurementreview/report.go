// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

func ComparisonPassed(report MeasurementReviewComparisonReport) bool {
	return report.Conclusion == "passed" && len(report.UnexpectedDrift) == 0 && !report.PayloadLogged && !report.SecretLogged
}
