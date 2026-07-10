// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

func ValidateReport(report Report) bool {
	return report.ScenariosRun == len(report.Runs)
}
