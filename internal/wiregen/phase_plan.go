// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import "kurdistan/internal/protocorpus"

func phasePlan(entry protocorpus.ProtocolShapeEntry) PhasePlan {
	plan := PhasePlan{HandshakeRTTBucket: "unknown", DirectionPattern: "unknown"}
	for _, phase := range entry.Phases {
		plan.PhaseSequence = append(plan.PhaseSequence, phase.Phase)
		if phase.Phase == protocorpus.PhaseHandshake && plan.HandshakeRTTBucket == "unknown" {
			plan.HandshakeRTTBucket = phase.RoundTripBucket
		}
		if plan.DirectionPattern == "unknown" {
			plan.DirectionPattern = phase.DirectionPattern
		}
		if phase.Phase == protocorpus.PhaseControl {
			plan.ControlPhaseEnabled = true
		}
	}
	if plan.HandshakeRTTBucket == "unknown" && len(entry.Phases) > 0 {
		plan.HandshakeRTTBucket = entry.Phases[0].RoundTripBucket
	}
	return plan
}

func phaseShape(plan PhasePlan) string {
	if len(plan.PhaseSequence) == 0 {
		return "unknown"
	}
	out := ""
	for i, phase := range plan.PhaseSequence {
		if i > 0 {
			out += "-"
		}
		out += string(phase)
	}
	return out
}

func hasPhase(entry protocorpus.ProtocolShapeEntry, target protocorpus.ProtocolPhase) bool {
	for _, phase := range entry.Phases {
		if phase.Phase == target {
			return true
		}
	}
	return false
}
