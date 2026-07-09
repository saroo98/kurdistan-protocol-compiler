// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

func LocalReportIsTraceSafe(report LocalDiagnosticReport) bool {
	return report.LocalOnly && !report.PayloadLogged && !report.SecretLogged && report.Conclusion == "passed"
}
