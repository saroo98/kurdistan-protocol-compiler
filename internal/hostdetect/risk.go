// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

func RiskBucket(score float64, observations int) string {
	if observations < 3 {
		return "unknown"
	}
	switch {
	case score >= 0.92:
		return "critical"
	case score >= 0.78:
		return "high"
	case score >= 0.55:
		return "medium"
	default:
		return "low"
	}
}
