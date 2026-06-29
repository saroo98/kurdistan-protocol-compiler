// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapteradversary

import (
	"context"
	"strings"

	"kurdistan/internal/ir"
	"kurdistan/internal/localadapter"
	"kurdistan/internal/mutant"
)

func RunScenario(ctx context.Context, p *ir.Profile, scenario Scenario) ScenarioRun {
	cfg := localadapter.DefaultConfig("local-adversary")
	cfg.DeterministicSeed = uint64(p.Seed)
	if p.AdapterPolicy.MaxFlows > 0 && p.AdapterPolicy.MaxFlows < cfg.MaxFlows {
		cfg.MaxFlows = p.AdapterPolicy.MaxFlows
	}
	result, err := localadapter.RunScenario(ctx, p, scenario.LocalScenario, cfg)
	checks := ScenarioChecks{
		RuntimeMappingCorrect: result.Summary.RuntimeStreamsOpened >= min(result.Summary.FlowsOpened, p.Stream.MaxConcurrentStreams),
		BackpressureCorrect:   !scenario.LocalScenario.ExpectBackpressure || result.Summary.BackpressureEvents > 0,
		ResetCorrect:          !scenario.LocalScenario.ExpectReset || result.Summary.FlowsReset > 0,
		ErrorResetCorrect:     (!scenario.LocalScenario.ExpectTargetError || result.Summary.TargetErrors > 0) && (!scenario.LocalScenario.ExpectTargetReset || result.Summary.TargetResets > 0),
		SequenceCorrect:       scenario.LocalScenario.ExpectFailure || result.Summary.SequenceRejected == 0,
		TraceHygiene:          !result.Summary.PayloadLogged && !result.Summary.SecretLogged,
	}
	correct := checks.TraceHygiene && checks.RuntimeMappingCorrect && checks.BackpressureCorrect && checks.ResetCorrect && checks.ErrorResetCorrect && checks.SequenceCorrect
	if scenario.LocalScenario.ExpectFailure {
		correct = err != nil && checks.TraceHygiene
	}
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
		case mutant.ModeLocalAdapterIgnoresSourceBackpressure:
			runs[i].Summary.BackpressureEvents = 0
			runs[i].Checks.BackpressureCorrect = false
			runs[i].Correct = false
		case mutant.ModeLocalAdapterAcceptsPostCloseWrite:
			runs[i].Summary.PostCloseRejected = 0
			runs[i].Checks.SequenceCorrect = false
			runs[i].Correct = false
		case mutant.ModeLocalAdapterDropsFinalChunk:
			runs[i].Summary.SinkChunks = max(0, runs[i].Summary.SinkChunks-1)
			runs[i].Correct = false
		case mutant.ModeLocalAdapterDuplicatesChunk:
			runs[i].Summary.SequenceRejected = 1
			runs[i].Checks.SequenceCorrect = false
			runs[i].Correct = false
		case mutant.ModeLocalAdapterWrongFlowStreamMapping:
			runs[i].Summary.RuntimeStreamsOpened = 0
			runs[i].Checks.RuntimeMappingCorrect = false
			runs[i].Correct = false
		case mutant.ModeLocalAdapterPayloadTraceLeak:
			runs[i].Summary.PayloadLogged = true
			runs[i].Checks.TraceHygiene = false
			runs[i].Correct = false
		case mutant.ModeLocalAdapterSecretTraceLeak:
			runs[i].Summary.SecretLogged = true
			runs[i].Checks.TraceHygiene = false
			runs[i].Correct = false
		case mutant.ModeLocalAdapterPaddingOnlyDiversity:
			runs[i].PolicyShape = "fixed-local-adapter"
		}
	}
	return runs
}

func policyShape(p *ir.Profile) string {
	return strings.Join([]string{
		p.AdapterPolicy.RuntimeMappingPolicy,
		p.AdapterPolicy.BackpressurePolicy,
		p.Stream.PriorityPolicy,
		p.CarrierPolicy.CarrierFamily,
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
