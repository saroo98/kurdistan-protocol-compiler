// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransportadversary

import (
	"context"
	"strings"

	"kurdistan/internal/bytetransport"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
)

func RunScenario(ctx context.Context, p *ir.Profile, scenario Scenario) ScenarioRun {
	cfg := bytetransport.DefaultConfig("byte-adversary")
	cfg.DeterministicSeed = uint64(p.Seed)
	cfg.MaxFrameBytes = max(4096, min(64*1024, p.Limits.MaxFrameBytes))
	cfg.MaxPayloadBytes = min(16*1024, min(p.Limits.MaxPayloadBytes, cfg.MaxFrameBytes/2))
	result, err := bytetransport.RunScenario(ctx, p, scenario.ByteScenario, cfg)
	checks := ScenarioChecks{
		RuntimeIntegrationCorrect: result.Summary.RuntimeStreamsMapped > 0,
		BackpressureCorrect:       !scenario.ByteScenario.ExpectBackpressure || result.Summary.BackpressureEvents > 0,
		SequenceCorrect:           !scenario.ByteScenario.ReplayFrame || result.Summary.SequenceRejected > 0,
		CorruptionCorrect:         !scenario.ByteScenario.CorruptFrame || result.Summary.CorruptionRejected > 0,
		MalformedCorrect:          result.Summary.MalformedRejected >= 0,
		ReassemblyCorrect:         !strings.Contains(scenario.Name, "fragment") || result.Summary.FragmentsCreated > 1,
		ErrorResetCorrect:         (!scenario.ByteScenario.ExpectTargetError || result.Summary.TargetErrors > 0) && (!scenario.ByteScenario.ExpectTargetReset || result.Summary.TargetResets > 0),
		TraceHygiene:              !result.Summary.PayloadLogged && !result.Summary.SecretLogged,
	}
	correct := checks.RuntimeIntegrationCorrect && checks.BackpressureCorrect && checks.SequenceCorrect && checks.CorruptionCorrect && checks.MalformedCorrect && checks.ReassemblyCorrect && checks.ErrorResetCorrect && checks.TraceHygiene
	run := ScenarioRun{
		ProfileID:   p.ID,
		Scenario:    scenario.Name,
		PolicyShape: policyShape(p),
		Correct:     correct,
		Summary:     result.Summary,
		Checks:      checks,
		Events:      result.Events,
	}
	if err != nil {
		run.Failure = err.Error()
	}
	return run
}

func RunScenarioCorpus(ctx context.Context, profiles []*ir.Profile, scenarios []Scenario) []ScenarioRun {
	runs := make([]ScenarioRun, 0, len(profiles)*len(scenarios))
	for _, p := range profiles {
		for _, scenario := range scenarios {
			runs = append(runs, RunScenario(ctx, p, scenario))
		}
	}
	return runs
}

func RunMutantScenarioCorpus(ctx context.Context, mode string, profiles []*ir.Profile, scenarios []Scenario) []ScenarioRun {
	runs := RunScenarioCorpus(ctx, profiles, scenarios)
	for i := range runs {
		switch mode {
		case mutant.ModeByteTransportAcceptsMalformedFrame:
			runs[i].Summary.MalformedRejected = 0
			runs[i].Checks.MalformedCorrect = false
			runs[i].Correct = false
		case mutant.ModeByteTransportIgnoresMaxFrameSize:
			runs[i].Summary.FramesEncoded = 0
			runs[i].Correct = false
		case mutant.ModeByteTransportIgnoresBackpressure:
			runs[i].Summary.BackpressureEvents = 0
			runs[i].Checks.BackpressureCorrect = false
			runs[i].Correct = false
		case mutant.ModeByteTransportReusesSequence:
			runs[i].Summary.SequenceRejected = 0
			runs[i].Checks.SequenceCorrect = false
			runs[i].Correct = false
		case mutant.ModeByteTransportAcceptsCorruption:
			runs[i].Summary.CorruptionRejected = 0
			runs[i].Checks.CorruptionCorrect = false
			runs[i].Correct = false
		case mutant.ModeByteTransportDropsFragmentSilently:
			runs[i].Summary.ReassemblyRejected = 0
			runs[i].Summary.FragmentsReassembled = 0
			runs[i].Checks.ReassemblyCorrect = false
			runs[i].Correct = false
		case mutant.ModeByteTransportPayloadTraceLeak:
			runs[i].Summary.PayloadLogged = true
			runs[i].Checks.TraceHygiene = false
			runs[i].Correct = false
		case mutant.ModeByteTransportPaddingOnlyDiversity:
			runs[i].PolicyShape = "fixed-byte-transport"
		}
	}
	return runs
}

func policyShape(p *ir.Profile) string {
	return strings.Join([]string{
		p.FrameGrammar.FragmentationMode,
		p.CarrierPolicy.EnvelopeEncoding,
		p.CarrierPolicy.ChunkingPolicy,
		p.CarrierPolicy.BackpressurePolicy,
		p.Security.ReplayPolicy,
	}, "|")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
