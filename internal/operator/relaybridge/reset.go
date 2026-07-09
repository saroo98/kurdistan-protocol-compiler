// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

func ResetEvents(reports []RelayBridgeReport) int {
	total := 0
	for _, report := range reports {
		total += report.ResetRequests
	}
	return total
}
