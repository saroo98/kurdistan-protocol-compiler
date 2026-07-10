// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

func DecayScoreBucket(initial string, degradation DegradationReport) string {
	return ScoreActivePath(ActivePath{InitialScoreBucket: initial}, degradation, nil).FinalScoreBucket
}
