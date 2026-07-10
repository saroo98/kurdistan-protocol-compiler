// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

const (
	ScenarioSingleFlowEcho     = "single_flow_echo"
	ScenarioManySmallFlows     = "many_small_flows"
	ScenarioLargeBackpressure  = "large_flow_backpressure"
	ScenarioSlowDrip           = "slow_drip_flow"
	ScenarioMixedFlows         = "mixed_flows"
	ScenarioResetIsolation     = "reset_flow_isolation"
	ScenarioTargetErrorMapping = "target_error_mapping"
	ScenarioTargetResetMapping = "target_reset_mapping"
	ScenarioHalfClose          = "half_close_flow"
	ScenarioQueuePressure      = "queue_pressure"
	ScenarioMalformedSource    = "malformed_source_chunk"
)

type Scenario struct {
	Name               string `json:"name"`
	SourceModel        string `json:"source_model"`
	FlowCount          int    `json:"flow_count"`
	ExpectBackpressure bool   `json:"expect_backpressure,omitempty"`
	ExpectReset        bool   `json:"expect_reset,omitempty"`
	ExpectTargetError  bool   `json:"expect_target_error,omitempty"`
	ExpectTargetReset  bool   `json:"expect_target_reset,omitempty"`
	ExpectFailure      bool   `json:"expect_failure,omitempty"`
	HalfClose          bool   `json:"half_close,omitempty"`
}

func DefaultScenario(name string) Scenario {
	switch name {
	case ScenarioManySmallFlows:
		return Scenario{Name: name, SourceModel: SourceSmallBurst, FlowCount: 4}
	case ScenarioLargeBackpressure:
		return Scenario{Name: name, SourceModel: SourceLargeObject, FlowCount: 2, ExpectBackpressure: true}
	case ScenarioSlowDrip:
		return Scenario{Name: name, SourceModel: SourceSlowDrip, FlowCount: 1}
	case ScenarioMixedFlows:
		return Scenario{Name: name, SourceModel: SourceMixedFlow, FlowCount: 4, ExpectReset: true}
	case ScenarioResetIsolation:
		return Scenario{Name: name, SourceModel: SourceResetting, FlowCount: 3, ExpectReset: true}
	case ScenarioTargetErrorMapping:
		return Scenario{Name: name, SourceModel: SourceSmallBurst, FlowCount: 3, ExpectTargetError: true}
	case ScenarioTargetResetMapping:
		return Scenario{Name: name, SourceModel: SourceSmallBurst, FlowCount: 3, ExpectTargetReset: true}
	case ScenarioHalfClose:
		return Scenario{Name: name, SourceModel: SourceHalfClose, FlowCount: 1, HalfClose: true}
	case ScenarioQueuePressure:
		return Scenario{Name: name, SourceModel: SourceLargeObject, FlowCount: 2, ExpectBackpressure: true}
	case ScenarioMalformedSource:
		return Scenario{Name: name, SourceModel: SourceSmallBurst, FlowCount: 1, ExpectFailure: true}
	default:
		return Scenario{Name: ScenarioSingleFlowEcho, SourceModel: SourceSmallBurst, FlowCount: 1}
	}
}

func QuickScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioSingleFlowEcho),
		DefaultScenario(ScenarioManySmallFlows),
		DefaultScenario(ScenarioLargeBackpressure),
	}
}

func FullScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioSingleFlowEcho),
		DefaultScenario(ScenarioManySmallFlows),
		DefaultScenario(ScenarioLargeBackpressure),
		DefaultScenario(ScenarioSlowDrip),
		DefaultScenario(ScenarioMixedFlows),
		DefaultScenario(ScenarioResetIsolation),
		DefaultScenario(ScenarioTargetErrorMapping),
		DefaultScenario(ScenarioTargetResetMapping),
		DefaultScenario(ScenarioHalfClose),
		DefaultScenario(ScenarioQueuePressure),
		DefaultScenario(ScenarioMalformedSource),
	}
}
