// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapteradversary

import "kurdistan/internal/localadapter"

const (
	ScenarioHappyPath         = "local_single_flow_happy_path"
	ScenarioManySmall         = "local_many_small_flows"
	ScenarioLargeBackpressure = "local_large_flow_backpressure"
	ScenarioSlowDrip          = "local_slow_drip_flow"
	ScenarioMixed             = "local_mixed_flows"
	ScenarioResetIsolation    = "local_reset_isolation"
	ScenarioTargetError       = "local_target_error_mapping"
	ScenarioTargetReset       = "local_target_reset_mapping"
	ScenarioHalfClose         = "local_half_close"
	ScenarioQueuePressure     = "local_queue_pressure"
	ScenarioMalformedChunk    = "local_malformed_source_chunk"
)

type Scenario struct {
	Name          string                `json:"name"`
	LocalScenario localadapter.Scenario `json:"local_scenario"`
}

func DefaultScenario(name string) Scenario {
	switch name {
	case ScenarioManySmall:
		return Scenario{Name: name, LocalScenario: localadapter.DefaultScenario(localadapter.ScenarioManySmallFlows)}
	case ScenarioLargeBackpressure:
		return Scenario{Name: name, LocalScenario: localadapter.DefaultScenario(localadapter.ScenarioLargeBackpressure)}
	case ScenarioSlowDrip:
		return Scenario{Name: name, LocalScenario: localadapter.DefaultScenario(localadapter.ScenarioSlowDrip)}
	case ScenarioMixed:
		return Scenario{Name: name, LocalScenario: localadapter.DefaultScenario(localadapter.ScenarioMixedFlows)}
	case ScenarioResetIsolation:
		return Scenario{Name: name, LocalScenario: localadapter.DefaultScenario(localadapter.ScenarioResetIsolation)}
	case ScenarioTargetError:
		return Scenario{Name: name, LocalScenario: localadapter.DefaultScenario(localadapter.ScenarioTargetErrorMapping)}
	case ScenarioTargetReset:
		return Scenario{Name: name, LocalScenario: localadapter.DefaultScenario(localadapter.ScenarioTargetResetMapping)}
	case ScenarioHalfClose:
		return Scenario{Name: name, LocalScenario: localadapter.DefaultScenario(localadapter.ScenarioHalfClose)}
	case ScenarioQueuePressure:
		return Scenario{Name: name, LocalScenario: localadapter.DefaultScenario(localadapter.ScenarioQueuePressure)}
	case ScenarioMalformedChunk:
		return Scenario{Name: name, LocalScenario: localadapter.DefaultScenario(localadapter.ScenarioMalformedSource)}
	default:
		return Scenario{Name: ScenarioHappyPath, LocalScenario: localadapter.DefaultScenario(localadapter.ScenarioSingleFlowEcho)}
	}
}

func QuickScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioHappyPath),
		DefaultScenario(ScenarioManySmall),
		DefaultScenario(ScenarioLargeBackpressure),
	}
}

func FullScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioHappyPath),
		DefaultScenario(ScenarioManySmall),
		DefaultScenario(ScenarioLargeBackpressure),
		DefaultScenario(ScenarioSlowDrip),
		DefaultScenario(ScenarioMixed),
		DefaultScenario(ScenarioResetIsolation),
		DefaultScenario(ScenarioTargetError),
		DefaultScenario(ScenarioTargetReset),
		DefaultScenario(ScenarioHalfClose),
		DefaultScenario(ScenarioQueuePressure),
		DefaultScenario(ScenarioMalformedChunk),
	}
}
