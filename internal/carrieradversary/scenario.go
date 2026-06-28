// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrieradversary

import "kurdistan/internal/carrier"

const (
	ScenarioStreamVsMessageEquivalence = "stream_vs_message_equivalence"
	ScenarioBatchingPressure           = "batching_pressure"
	ScenarioChunkedLargeResponse       = "chunked_large_response"
	ScenarioInteractiveVsBulk          = "interactive_vs_bulk"
	ScenarioLongPollQueuePressure      = "long_poll_queue_pressure"
	ScenarioDatagramReorderRecovery    = "datagram_reorder_recovery"
	ScenarioLossyRetryRecovery         = "lossy_retry_recovery"
	ScenarioCarrierBackpressureChain   = "carrier_backpressure_chain"
	ScenarioMixedCarrierMatrix         = "mixed_carrier_matrix"
	ScenarioMalformedCarrierEnvelope   = "malformed_carrier_envelope"
)

type Scenario struct {
	Type           string `json:"type"`
	CarrierFamily  string `json:"carrier_family,omitempty"`
	ProxyScenario  string `json:"proxy_scenario"`
	StreamCount    int    `json:"stream_count"`
	ExpectPressure bool   `json:"expect_pressure,omitempty"`
	ExpectReorder  bool   `json:"expect_reorder,omitempty"`
}

func RequiredScenarioTypes() []string {
	return []string{
		ScenarioStreamVsMessageEquivalence,
		ScenarioBatchingPressure,
		ScenarioChunkedLargeResponse,
		ScenarioInteractiveVsBulk,
		ScenarioLongPollQueuePressure,
		ScenarioDatagramReorderRecovery,
		ScenarioLossyRetryRecovery,
		ScenarioCarrierBackpressureChain,
		ScenarioMixedCarrierMatrix,
		ScenarioMalformedCarrierEnvelope,
	}
}

func QuickScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioStreamVsMessageEquivalence),
		DefaultScenario(ScenarioBatchingPressure),
		DefaultScenario(ScenarioLossyRetryRecovery),
	}
}

func FullScenarios() []Scenario {
	out := make([]Scenario, 0, len(RequiredScenarioTypes()))
	for _, kind := range RequiredScenarioTypes() {
		out = append(out, DefaultScenario(kind))
	}
	return out
}

func DefaultScenario(kind string) Scenario {
	scenario := Scenario{Type: kind, ProxyScenario: "mixed_targets", StreamCount: 4}
	switch kind {
	case ScenarioStreamVsMessageEquivalence:
		scenario.CarrierFamily = carrier.FamilyStream
	case ScenarioBatchingPressure:
		scenario.CarrierFamily = carrier.FamilyBatch
		scenario.ProxyScenario = "many_small_requests"
	case ScenarioChunkedLargeResponse:
		scenario.CarrierFamily = carrier.FamilyChunked
		scenario.ProxyScenario = "large_response_backpressure"
		scenario.ExpectPressure = true
	case ScenarioInteractiveVsBulk:
		scenario.CarrierFamily = carrier.FamilyInteractive
		scenario.ProxyScenario = "one_large_object_plus_small_requests"
	case ScenarioLongPollQueuePressure:
		scenario.CarrierFamily = carrier.FamilyLongPollStyle
		scenario.ProxyScenario = "slow_target_backpressure"
		scenario.ExpectPressure = true
	case ScenarioDatagramReorderRecovery:
		scenario.CarrierFamily = carrier.FamilyDatagramLike
		scenario.ExpectReorder = true
	case ScenarioLossyRetryRecovery:
		scenario.CarrierFamily = carrier.FamilyLossyReordered
		scenario.ExpectReorder = true
	case ScenarioCarrierBackpressureChain:
		scenario.CarrierFamily = carrier.FamilyLongPollStyle
		scenario.ProxyScenario = "slow_target_backpressure"
		scenario.ExpectPressure = true
	case ScenarioMalformedCarrierEnvelope:
		scenario.CarrierFamily = carrier.FamilyStream
	default:
		scenario.CarrierFamily = ""
	}
	return scenario
}
