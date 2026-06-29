// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransportadversary

import "kurdistan/internal/bytetransport"

const (
	ScenarioHappyPath         = "byte_single_flow_happy_path"
	ScenarioManySmall         = "byte_many_small_flows"
	ScenarioLargeFragmented   = "byte_large_fragmented_flow"
	ScenarioSlowDrip          = "byte_slow_drip_flow"
	ScenarioMixed             = "byte_mixed_flows"
	ScenarioReorderReassembly = "byte_reorder_reassembly"
	ScenarioDropIncomplete    = "byte_drop_incomplete_reassembly"
	ScenarioCorruption        = "byte_corruption_rejection"
	ScenarioReplay            = "byte_replay_injection"
	ScenarioBackpressureChain = "byte_backpressure_chain"
	ScenarioMalformedFrame    = "byte_malformed_frame"
)

type Scenario struct {
	Name         string                 `json:"name"`
	ByteScenario bytetransport.Scenario `json:"byte_scenario"`
}

func DefaultScenario(name string) Scenario {
	switch name {
	case ScenarioManySmall:
		return Scenario{Name: name, ByteScenario: bytetransport.DefaultScenario(bytetransport.ScenarioManySmall)}
	case ScenarioLargeFragmented:
		return Scenario{Name: name, ByteScenario: bytetransport.DefaultScenario(bytetransport.ScenarioLargeFragmented)}
	case ScenarioSlowDrip:
		return Scenario{Name: name, ByteScenario: bytetransport.DefaultScenario(bytetransport.ScenarioSlowDrip)}
	case ScenarioMixed:
		return Scenario{Name: name, ByteScenario: bytetransport.DefaultScenario(bytetransport.ScenarioMixed)}
	case ScenarioReorderReassembly:
		s := bytetransport.DefaultScenario(bytetransport.ScenarioLargeFragmented)
		s.AllowOutOfOrder = true
		return Scenario{Name: name, ByteScenario: s}
	case ScenarioDropIncomplete:
		s := bytetransport.DefaultScenario(bytetransport.ScenarioLargeFragmented)
		s.DropFragment = true
		return Scenario{Name: name, ByteScenario: s}
	case ScenarioCorruption:
		return Scenario{Name: name, ByteScenario: bytetransport.DefaultScenario(bytetransport.ScenarioCorruption)}
	case ScenarioReplay:
		return Scenario{Name: name, ByteScenario: bytetransport.DefaultScenario(bytetransport.ScenarioReplay)}
	case ScenarioBackpressureChain:
		return Scenario{Name: name, ByteScenario: bytetransport.DefaultScenario(bytetransport.ScenarioQueueBackpressure)}
	case ScenarioMalformedFrame:
		s := bytetransport.DefaultScenario(bytetransport.ScenarioCorruption)
		return Scenario{Name: name, ByteScenario: s}
	default:
		return Scenario{Name: ScenarioHappyPath, ByteScenario: bytetransport.DefaultScenario(bytetransport.ScenarioSingleFlow)}
	}
}

func QuickScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioHappyPath),
		DefaultScenario(ScenarioManySmall),
		DefaultScenario(ScenarioLargeFragmented),
	}
}

func FullScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioHappyPath),
		DefaultScenario(ScenarioManySmall),
		DefaultScenario(ScenarioLargeFragmented),
		DefaultScenario(ScenarioSlowDrip),
		DefaultScenario(ScenarioMixed),
		DefaultScenario(ScenarioReorderReassembly),
		DefaultScenario(ScenarioDropIncomplete),
		DefaultScenario(ScenarioCorruption),
		DefaultScenario(ScenarioReplay),
		DefaultScenario(ScenarioBackpressureChain),
		DefaultScenario(ScenarioMalformedFrame),
	}
}
