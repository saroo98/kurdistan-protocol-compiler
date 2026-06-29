// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimeadversary

import "kurdistan/internal/proxyadversary"

const (
	ScenarioHappyPathSession       = "happy_path_session"
	ScenarioCapabilityDowngrade    = "capability_downgrade_attempt"
	ScenarioProfileMismatchSession = "profile_mismatch_session"
	ScenarioReplayInjection        = "replay_injection"
	ScenarioCarrierQueuePressure   = "carrier_queue_pressure"
	ScenarioTargetErrorIsolation   = "target_error_runtime_isolation"
	ScenarioTargetResetIsolation   = "target_reset_runtime_isolation"
	ScenarioLargeObjectRuntime     = "large_object_runtime"
	ScenarioMalformedLinkFrame     = "malformed_link_frame"
	ScenarioCloseRace              = "close_race"
)

type Scenario struct {
	Type          string `json:"type"`
	StreamCount   int    `json:"stream_count"`
	CarrierFamily string `json:"carrier_family,omitempty"`
	QueueDepth    int    `json:"queue_depth,omitempty"`
}

func QuickScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioHappyPathSession),
		DefaultScenario(ScenarioReplayInjection),
		DefaultScenario(ScenarioTargetErrorIsolation),
	}
}

func FullScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioHappyPathSession),
		DefaultScenario(ScenarioCapabilityDowngrade),
		DefaultScenario(ScenarioProfileMismatchSession),
		DefaultScenario(ScenarioReplayInjection),
		DefaultScenario(ScenarioCarrierQueuePressure),
		DefaultScenario(ScenarioTargetErrorIsolation),
		DefaultScenario(ScenarioTargetResetIsolation),
		DefaultScenario(ScenarioLargeObjectRuntime),
		DefaultScenario(ScenarioMalformedLinkFrame),
		DefaultScenario(ScenarioCloseRace),
	}
}

func DefaultScenario(kind string) Scenario {
	s := Scenario{Type: kind, StreamCount: 4, QueueDepth: 16}
	switch kind {
	case ScenarioCarrierQueuePressure:
		s.QueueDepth = 1
	case ScenarioLargeObjectRuntime:
		s.StreamCount = 3
	case ScenarioMalformedLinkFrame:
		s.StreamCount = 1
	}
	return s
}

func ProxyScenarioFor(kind string) proxyadversary.Scenario {
	switch kind {
	case ScenarioTargetErrorIsolation:
		return proxyadversary.DefaultScenario(proxyadversary.ScenarioErrorTargetIsolation)
	case ScenarioTargetResetIsolation:
		return proxyadversary.DefaultScenario(proxyadversary.ScenarioTargetResetMidstream)
	case ScenarioLargeObjectRuntime, ScenarioCarrierQueuePressure:
		return proxyadversary.DefaultScenario(proxyadversary.ScenarioLargeResponseBackpressure)
	default:
		return proxyadversary.DefaultScenario(proxyadversary.ScenarioMixedTargets)
	}
}
