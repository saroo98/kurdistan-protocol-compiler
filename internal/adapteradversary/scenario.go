// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapteradversary

const (
	ScenarioSingleFlowHappyPath     = "single_flow_happy_path"
	ScenarioManySmallFlows          = "many_small_flows"
	ScenarioLargeFlowBackpressure   = "large_flow_backpressure"
	ScenarioFlowResetIsolation      = "flow_reset_isolation"
	ScenarioTargetErrorToFlowError  = "target_error_to_flow_error"
	ScenarioTargetResetToFlowReset  = "target_reset_to_flow_reset"
	ScenarioHalfCloseBehavior       = "half_close_behavior"
	ScenarioCapabilityDowngrade     = "adapter_capability_downgrade"
	ScenarioMalformedFlowDescriptor = "malformed_flow_descriptor"
	ScenarioAdapterQueuePressure    = "adapter_queue_pressure"
)

type Scenario struct {
	Type               string `json:"type"`
	FlowCount          int    `json:"flow_count"`
	BytesPerFlow       int    `json:"bytes_per_flow"`
	LargeFlowBytes     int    `json:"large_flow_bytes,omitempty"`
	ExpectBackpressure bool   `json:"expect_backpressure,omitempty"`
	ExpectReset        bool   `json:"expect_reset,omitempty"`
	ExpectTargetError  bool   `json:"expect_target_error,omitempty"`
	ExpectTargetReset  bool   `json:"expect_target_reset,omitempty"`
	ExpectFailure      bool   `json:"expect_failure,omitempty"`
	HalfClose          bool   `json:"half_close,omitempty"`
}

func DefaultScenario(kind string) Scenario {
	switch kind {
	case ScenarioManySmallFlows:
		return Scenario{Type: kind, FlowCount: 4, BytesPerFlow: 96}
	case ScenarioLargeFlowBackpressure:
		return Scenario{Type: kind, FlowCount: 3, BytesPerFlow: 256, LargeFlowBytes: 128 * 1024, ExpectBackpressure: true}
	case ScenarioFlowResetIsolation:
		return Scenario{Type: kind, FlowCount: 3, BytesPerFlow: 128, ExpectReset: true}
	case ScenarioTargetErrorToFlowError:
		return Scenario{Type: kind, FlowCount: 3, BytesPerFlow: 128, ExpectTargetError: true}
	case ScenarioTargetResetToFlowReset:
		return Scenario{Type: kind, FlowCount: 3, BytesPerFlow: 128, ExpectTargetReset: true}
	case ScenarioHalfCloseBehavior:
		return Scenario{Type: kind, FlowCount: 2, BytesPerFlow: 128, HalfClose: true}
	case ScenarioCapabilityDowngrade:
		return Scenario{Type: kind, FlowCount: 1, BytesPerFlow: 64, ExpectFailure: true}
	case ScenarioMalformedFlowDescriptor:
		return Scenario{Type: kind, FlowCount: 1, BytesPerFlow: 64, ExpectFailure: true}
	case ScenarioAdapterQueuePressure:
		return Scenario{Type: kind, FlowCount: 4, BytesPerFlow: 4096, ExpectBackpressure: true}
	default:
		return Scenario{Type: ScenarioSingleFlowHappyPath, FlowCount: 1, BytesPerFlow: 128}
	}
}

func QuickScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioSingleFlowHappyPath),
		DefaultScenario(ScenarioManySmallFlows),
		DefaultScenario(ScenarioLargeFlowBackpressure),
	}
}

func FullScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioSingleFlowHappyPath),
		DefaultScenario(ScenarioManySmallFlows),
		DefaultScenario(ScenarioLargeFlowBackpressure),
		DefaultScenario(ScenarioFlowResetIsolation),
		DefaultScenario(ScenarioTargetErrorToFlowError),
		DefaultScenario(ScenarioTargetResetToFlowReset),
		DefaultScenario(ScenarioHalfCloseBehavior),
		DefaultScenario(ScenarioCapabilityDowngrade),
		DefaultScenario(ScenarioMalformedFlowDescriptor),
		DefaultScenario(ScenarioAdapterQueuePressure),
	}
}
