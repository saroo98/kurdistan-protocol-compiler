// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrier

func ReliabilityStats(envelopes []Envelope) (acks, retries, reordered, dropped int) {
	for _, env := range envelopes {
		if env.Reliability.AckRequired {
			acks++
		}
		if env.Reliability.RetryCount > 0 {
			retries += env.Reliability.RetryCount
		}
		if env.Reliability.Reordered {
			reordered++
		}
		if env.Reliability.Dropped {
			dropped++
		}
	}
	return acks, retries, reordered, dropped
}
