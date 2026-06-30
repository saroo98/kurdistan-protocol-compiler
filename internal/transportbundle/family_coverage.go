// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import "kurdistan/internal/adaptivepath"

func FamilyCoverage(manifest TransportBundleManifest, required []adaptivepath.CandidateFamily) []string {
	failures := []string{}
	for _, family := range required {
		if manifest.FamilyCounts[string(family)] == 0 {
			failures = append(failures, "missing_required_family:"+string(family))
		}
	}
	return failures
}
