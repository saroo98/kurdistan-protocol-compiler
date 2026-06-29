// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import (
	"context"
	"errors"

	"kurdistan/internal/ir"
	"kurdistan/internal/localadapter"
	ktrace "kurdistan/internal/trace"
)

type Scenario struct {
	Name               string `json:"name"`
	LocalScenario      string `json:"local_scenario"`
	FragmentPolicy     string `json:"fragment_policy"`
	FlowCount          int    `json:"flow_count"`
	ExpectBackpressure bool   `json:"expect_backpressure,omitempty"`
	ExpectReset        bool   `json:"expect_reset,omitempty"`
	ExpectTargetError  bool   `json:"expect_target_error,omitempty"`
	ExpectTargetReset  bool   `json:"expect_target_reset,omitempty"`
	CorruptFrame       bool   `json:"corrupt_frame,omitempty"`
	ReplayFrame        bool   `json:"replay_frame,omitempty"`
	DropFragment       bool   `json:"drop_fragment,omitempty"`
	AllowOutOfOrder    bool   `json:"allow_out_of_order,omitempty"`
}

const (
	ScenarioSingleFlow        = "byte_single_flow_echo"
	ScenarioManySmall         = "byte_many_small_flows"
	ScenarioLargeFragmented   = "byte_large_flow_fragmented"
	ScenarioSlowDrip          = "byte_slow_drip_flow"
	ScenarioMixed             = "byte_mixed_flows"
	ScenarioResetIsolation    = "byte_reset_isolation"
	ScenarioTargetError       = "byte_target_error_mapping"
	ScenarioTargetReset       = "byte_target_reset_mapping"
	ScenarioQueueBackpressure = "byte_queue_backpressure"
	ScenarioCorruption        = "byte_corruption_rejection"
	ScenarioReplay            = "byte_replay_rejection"
)

type RunResult struct {
	Summary ByteTransportSummary `json:"summary"`
	Events  []ktrace.Event       `json:"events,omitempty"`
}

func DefaultScenario(name string) Scenario {
	switch name {
	case ScenarioManySmall:
		return Scenario{Name: name, LocalScenario: localadapter.ScenarioManySmallFlows, FragmentPolicy: FragmentFixed, FlowCount: 4}
	case ScenarioLargeFragmented:
		return Scenario{Name: name, LocalScenario: localadapter.ScenarioLargeBackpressure, FragmentPolicy: FragmentCarrierAware, FlowCount: 2, ExpectBackpressure: true}
	case ScenarioSlowDrip:
		return Scenario{Name: name, LocalScenario: localadapter.ScenarioSlowDrip, FragmentPolicy: FragmentFixed, FlowCount: 1}
	case ScenarioMixed:
		return Scenario{Name: name, LocalScenario: localadapter.ScenarioMixedFlows, FragmentPolicy: FragmentProfileBucket, FlowCount: 4, ExpectReset: true}
	case ScenarioResetIsolation:
		return Scenario{Name: name, LocalScenario: localadapter.ScenarioResetIsolation, FragmentPolicy: FragmentFixed, FlowCount: 3, ExpectReset: true}
	case ScenarioTargetError:
		return Scenario{Name: name, LocalScenario: localadapter.ScenarioTargetErrorMapping, FragmentPolicy: FragmentFixed, FlowCount: 3, ExpectTargetError: true}
	case ScenarioTargetReset:
		return Scenario{Name: name, LocalScenario: localadapter.ScenarioTargetResetMapping, FragmentPolicy: FragmentFixed, FlowCount: 3, ExpectTargetReset: true}
	case ScenarioQueueBackpressure:
		return Scenario{Name: name, LocalScenario: localadapter.ScenarioQueuePressure, FragmentPolicy: FragmentBackpressureAware, FlowCount: 2, ExpectBackpressure: true}
	case ScenarioCorruption:
		return Scenario{Name: name, LocalScenario: localadapter.ScenarioSingleFlowEcho, FragmentPolicy: FragmentFixed, FlowCount: 1, CorruptFrame: true}
	case ScenarioReplay:
		return Scenario{Name: name, LocalScenario: localadapter.ScenarioSingleFlowEcho, FragmentPolicy: FragmentFixed, FlowCount: 1, ReplayFrame: true}
	default:
		return Scenario{Name: ScenarioSingleFlow, LocalScenario: localadapter.ScenarioSingleFlowEcho, FragmentPolicy: FragmentFixed, FlowCount: 1}
	}
}

func QuickScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioSingleFlow),
		DefaultScenario(ScenarioManySmall),
		DefaultScenario(ScenarioLargeFragmented),
	}
}

func FullScenarios() []Scenario {
	return []Scenario{
		DefaultScenario(ScenarioSingleFlow),
		DefaultScenario(ScenarioManySmall),
		DefaultScenario(ScenarioLargeFragmented),
		DefaultScenario(ScenarioSlowDrip),
		DefaultScenario(ScenarioMixed),
		DefaultScenario(ScenarioResetIsolation),
		DefaultScenario(ScenarioTargetError),
		DefaultScenario(ScenarioTargetReset),
		DefaultScenario(ScenarioQueueBackpressure),
		DefaultScenario(ScenarioCorruption),
		DefaultScenario(ScenarioReplay),
	}
}

func RunScenario(ctx context.Context, p *ir.Profile, scenario Scenario, cfg ByteTransportConfig) (RunResult, error) {
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	if cfg.Name == "" {
		cfg = DefaultConfig("byte-transport")
	}
	cfg.AllowOutOfOrder = cfg.AllowOutOfOrder || scenario.AllowOutOfOrder
	if scenario.ExpectBackpressure {
		cfg.MaxPipeQueueDepth = minInt(cfg.MaxPipeQueueDepth, 2)
		cfg.MaxBufferedBytes = minInt(cfg.MaxBufferedBytes, cfg.MaxFrameBytes*2)
	}
	if err := ValidateConfig(cfg); err != nil {
		return RunResult{}, err
	}
	localCfg := localadapter.DefaultConfig("byte-local")
	localCfg.MaxFlows = minInt(8, cfg.MaxPipeQueueDepth)
	localCfg.MaxChunkBytes = minInt(4096, cfg.MaxPayloadBytes)
	localCfg.MaxBufferedBytes = maxInt(128, cfg.MaxBufferedBytes/2)
	localCfg.DeterministicSeed = cfg.DeterministicSeed
	localRun, err := localadapter.RunScenario(ctx, p, localadapter.DefaultScenario(scenario.LocalScenario), localCfg)
	if err != nil {
		return RunResult{}, err
	}
	pipe, err := NewBytePipe(cfg)
	if err != nil {
		return RunResult{}, err
	}
	reassembler, err := NewReassembler(cfg)
	if err != nil {
		return RunResult{}, err
	}
	seq := NewSequenceValidator(1024)
	summary := ByteTransportSummary{Scenario: scenario.Name, RuntimeStreamsMapped: localRun.Summary.RuntimeStreamsOpened, TargetErrors: localRun.Summary.TargetErrors, TargetResets: localRun.Summary.TargetResets}
	frameCount := maxInt(1, localRun.Summary.SourceChunks)
	for i := 0; i < frameCount; i++ {
		kind := FrameData
		if scenario.ExpectReset && i == frameCount-1 {
			kind = FrameReset
		}
		byteCount := maxInt(1, localRun.Summary.SourceBytes/maxInt(1, frameCount))
		if scenario.Name == ScenarioLargeFragmented {
			byteCount = minInt(cfg.MaxPayloadBytes*2, cfg.MaxReassemblyBytes/2)
		}
		if scenario.Name != ScenarioLargeFragmented {
			byteCount = minInt(byteCount, cfg.MaxPayloadBytes)
		}
		base := ByteFrame{SessionID: cfg.RuntimeID, StreamID: uint64(i%maxInt(1, scenario.FlowCount)) + 1, Sequence: uint64(i + 1), Kind: kind, ByteCount: byteCount, Final: i == frameCount-1, Reset: kind == FrameReset, MetadataClass: scenario.Name, ChecksumClass: "fnv32a"}
		fragments, err := FragmentFrame(cfg, base, scenario.FragmentPolicy)
		if err != nil {
			return RunResult{Summary: summary}, err
		}
		if scenario.DropFragment && len(fragments) > 1 {
			fragments = fragments[:len(fragments)-1]
		}
		for _, fragment := range fragments {
			encoded, err := EncodeFrame(cfg, fragment)
			if err != nil {
				return RunResult{Summary: summary}, err
			}
			if scenario.CorruptFrame && summary.FramesEncoded == 0 && len(encoded.Bytes) > 8 {
				encoded.Bytes[8] ^= 0x7f
			}
			summary.FramesEncoded++
			summary.FragmentsCreated++
			summary.BytesWritten += len(encoded.Bytes)
			if err := pipe.Write(encoded); err != nil {
				if errors.Is(err, ErrBackpressure) {
					summary.BackpressureEvents++
					continue
				}
				return RunResult{Summary: summary}, err
			}
			if scenario.ReplayFrame && summary.FramesEncoded == 1 {
				_ = pipe.Write(encoded)
			}
		}
	}
	for {
		encoded, err := pipe.Read()
		if err != nil {
			break
		}
		summary.BytesRead += len(encoded.Bytes)
		decoded, err := DecodeFrameBytes(cfg, encoded.Bytes)
		if err != nil {
			if errors.Is(err, ErrChecksumMismatch) {
				summary.CorruptionRejected++
			} else {
				summary.MalformedRejected++
			}
			continue
		}
		if err := seq.Accept(decoded.Frame); err != nil {
			summary.SequenceRejected++
			if errors.Is(err, ErrSequenceRejected) {
				summary.ReplayRejected++
			}
			continue
		}
		summary.FramesDecoded++
		result, err := reassembler.Add(decoded.Frame)
		if err != nil {
			summary.ReassemblyRejected++
			continue
		}
		if result.Reassembled {
			summary.FragmentsReassembled++
		}
	}
	summary.BackpressureEvents += pipe.BackpressureEvents() + localRun.Summary.BackpressureEvents
	summary.PayloadLogged = localRun.Summary.PayloadLogged
	summary.SecretLogged = localRun.Summary.SecretLogged
	summary.Completed = !summary.PayloadLogged && !summary.SecretLogged && summary.FramesEncoded > 0 && (summary.FramesDecoded > 0 || scenario.CorruptFrame || scenario.ReplayFrame)
	events := append([]ktrace.Event{}, localRun.Events...)
	events = append(events, TraceEvent(p, scenario.Name, summary))
	return RunResult{Summary: summary, Events: events}, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
