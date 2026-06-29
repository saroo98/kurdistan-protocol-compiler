// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

func PhaseNames() []string {
	out := make([]string, 0, len(SupportedPhases()))
	for _, phase := range SupportedPhases() {
		out = append(out, string(phase))
	}
	return out
}
