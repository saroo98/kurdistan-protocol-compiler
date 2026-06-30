// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

func isFailureObservation(kind PathObservationKind) bool {
	switch kind {
	case ObservationHandshakeFailed, ObservationStallAfterHandshake, ObservationStallAfterData, ObservationResetLikeFailure, ObservationBlackholeLikeFailure, ObservationPoisoningLikeSignal, ObservationTruncationLikeSignal, ObservationRelayBurnRisk, ObservationShortFailure:
		return true
	default:
		return false
	}
}

func lastFailureBucket(observations []PathObservation) string {
	last := "none"
	for _, obs := range observations {
		if isFailureObservation(obs.Kind) && obs.FailureBucket != "" {
			last = obs.FailureBucket
		}
	}
	return last
}
