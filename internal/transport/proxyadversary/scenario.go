// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyadversary

const (
	ScenarioManySmallRequests         = "many_small_requests"
	ScenarioOneLargeObjectPlusSmall   = "one_large_object_plus_small_requests"
	ScenarioSlowTargetBackpressure    = "slow_target_backpressure"
	ScenarioChunkedResponseMix        = "chunked_response_mix"
	ScenarioErrorTargetIsolation      = "error_target_isolation"
	ScenarioTargetResetMidstream      = "target_reset_midstream"
	ScenarioMixedTargets              = "mixed_targets"
	ScenarioDescriptorProbe           = "descriptor_probe"
	ScenarioLargeResponseBackpressure = "large_response_backpressure"
	ScenarioDripResponsePriority      = "drip_response_priority"
)

type Scenario struct {
	Type              string `json:"type"`
	StreamCount       int    `json:"stream_count"`
	RequestBytes      int    `json:"request_bytes"`
	ResponseBytes     int    `json:"response_bytes"`
	ResponseChunks    int    `json:"response_chunks"`
	DescriptorInvalid bool   `json:"descriptor_invalid,omitempty"`
}

func RequiredScenarioTypes() []string {
	return []string{
		ScenarioManySmallRequests,
		ScenarioOneLargeObjectPlusSmall,
		ScenarioSlowTargetBackpressure,
		ScenarioChunkedResponseMix,
		ScenarioErrorTargetIsolation,
		ScenarioTargetResetMidstream,
		ScenarioMixedTargets,
		ScenarioDescriptorProbe,
		ScenarioLargeResponseBackpressure,
		ScenarioDripResponsePriority,
	}
}

func QuickScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioManySmallRequests),
		DefaultScenario(ScenarioSlowTargetBackpressure),
		DefaultScenario(ScenarioErrorTargetIsolation),
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
	scenario := Scenario{
		Type:           kind,
		StreamCount:    4,
		RequestBytes:   512,
		ResponseBytes:  4096,
		ResponseChunks: 3,
	}
	switch kind {
	case ScenarioOneLargeObjectPlusSmall:
		scenario.ResponseBytes = 128 * 1024
	case ScenarioSlowTargetBackpressure:
		scenario.StreamCount = 3
		scenario.ResponseBytes = 8192
		scenario.ResponseChunks = 4
	case ScenarioChunkedResponseMix:
		scenario.ResponseBytes = 12 * 1024
		scenario.ResponseChunks = 6
	case ScenarioErrorTargetIsolation:
		scenario.StreamCount = 3
	case ScenarioTargetResetMidstream:
		scenario.StreamCount = 3
	case ScenarioDescriptorProbe:
		scenario.StreamCount = 1
		scenario.DescriptorInvalid = true
	case ScenarioLargeResponseBackpressure:
		scenario.StreamCount = 2
		scenario.ResponseBytes = 256 * 1024
	case ScenarioDripResponsePriority:
		scenario.StreamCount = 4
		scenario.ResponseBytes = 4096
		scenario.ResponseChunks = 16
	}
	return scenario
}

func ScenarioPayloadMarkers(kind string) []string {
	return []string{
		"proxyadv:" + kind,
		"target-request:" + kind,
		"target-response:" + kind,
	}
}
