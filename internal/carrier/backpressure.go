// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrier

func BackpressureCount(envelopes []Envelope) int {
	count := 0
	for _, env := range envelopes {
		if env.Backpressure {
			count++
		}
	}
	return count
}
