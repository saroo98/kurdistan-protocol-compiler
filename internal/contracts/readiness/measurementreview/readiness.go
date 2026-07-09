// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

func ReadyForLocalSyntheticDiagnostics(report MeasurementReadinessReport) bool {
	return report.Conclusion == "passed" && len(report.BlockingIssues) == 0
}
