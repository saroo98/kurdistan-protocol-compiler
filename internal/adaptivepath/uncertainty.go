// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

const (
	LowUncertainty     = "low_uncertainty"
	MediumUncertainty  = "medium_uncertainty"
	HighUncertainty    = "high_uncertainty"
	UnknownUncertainty = "unknown_uncertainty"
)

func UncertaintyBucket(successes, failures, expired int) string {
	if successes == 0 && failures == 0 {
		return UnknownUncertainty
	}
	if failures >= 2 || expired > successes+failures {
		return HighUncertainty
	}
	if failures == 1 || successes == 0 {
		return MediumUncertainty
	}
	return LowUncertainty
}
