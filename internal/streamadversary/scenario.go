// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package streamadversary

const (
	ScenarioBalancedInterleave      = "balanced_interleave"
	ScenarioBulkVsInteractive       = "bulk_vs_interactive"
	ScenarioBlockedStream           = "blocked_stream"
	ScenarioSessionWindowExhaustion = "session_window_exhaustion"
	ScenarioResetMidstream          = "reset_midstream"
	ScenarioCloseRace               = "close_race"
	ScenarioUnevenStreamSizes       = "uneven_stream_sizes"
)

type Scenario struct {
	Type              string `json:"type"`
	StreamCount       int    `json:"stream_count"`
	ChunkSizeBytes    int    `json:"chunk_size_bytes"`
	BulkPayloadBytes  int    `json:"bulk_payload_bytes"`
	SmallPayloadBytes int    `json:"small_payload_bytes"`
}

func RequiredScenarioTypes() []string {
	return []string{
		ScenarioBalancedInterleave,
		ScenarioBulkVsInteractive,
		ScenarioBlockedStream,
		ScenarioSessionWindowExhaustion,
		ScenarioResetMidstream,
		ScenarioCloseRace,
		ScenarioUnevenStreamSizes,
	}
}

func QuickScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioBalancedInterleave),
		DefaultScenario(ScenarioBulkVsInteractive),
		DefaultScenario(ScenarioBlockedStream),
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
		Type:              kind,
		StreamCount:       4,
		ChunkSizeBytes:    1024,
		BulkPayloadBytes:  24 * 1024,
		SmallPayloadBytes: 512,
	}
	switch kind {
	case ScenarioBulkVsInteractive:
		scenario.BulkPayloadBytes = 64 * 1024
		scenario.SmallPayloadBytes = 256
	case ScenarioBlockedStream:
		scenario.StreamCount = 3
	case ScenarioSessionWindowExhaustion:
		scenario.StreamCount = 4
	case ScenarioResetMidstream:
		scenario.StreamCount = 4
	case ScenarioCloseRace:
		scenario.StreamCount = 3
	case ScenarioUnevenStreamSizes:
		scenario.StreamCount = 4
		scenario.SmallPayloadBytes = 128
		scenario.BulkPayloadBytes = 48 * 1024
	}
	return scenario
}

func ScenarioPayloadMarkers(kind string) []string {
	return []string{
		"streamadv:" + kind,
		"bulk:" + kind,
		"interactive:" + kind,
	}
}
