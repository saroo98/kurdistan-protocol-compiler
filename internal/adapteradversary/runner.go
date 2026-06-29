// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapteradversary

import (
	"context"

	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
	kruntime "kurdistan/internal/runtime"
)

func RunScenario(ctx context.Context, p *ir.Profile, scenario Scenario) ScenarioRun {
	flowCount := scenario.FlowCount
	if p != nil && p.Stream.MaxConcurrentStreams > 0 && flowCount > p.Stream.MaxConcurrentStreams {
		flowCount = p.Stream.MaxConcurrentStreams
	}
	if flowCount <= 0 {
		flowCount = 1
	}
	opts := kruntime.AdapterBoundaryOptions{
		Scenario:            scenario.Type,
		FlowCount:           flowCount,
		BytesPerFlow:        scenario.BytesPerFlow,
		LargeFlowBytes:      scenario.LargeFlowBytes,
		ResetFlow:           scenario.ExpectReset,
		TargetError:         scenario.ExpectTargetError,
		TargetReset:         scenario.ExpectTargetReset,
		Backpressure:        scenario.ExpectBackpressure || scenario.Type == ScenarioAdapterQueuePressure,
		HalfClose:           scenario.HalfClose,
		CapabilityDowngrade: scenario.Type == ScenarioCapabilityDowngrade,
		MalformedFlow:       scenario.Type == ScenarioMalformedFlowDescriptor,
	}
	result, err := kruntime.RunAdapterBoundary(ctx, p, opts)
	checks := ScenarioChecks{
		FlowMappingCorrect:  err == nil && result.Summary.RuntimeStreamsOpened >= result.Summary.FlowsOpened,
		BackpressureCorrect: !scenario.ExpectBackpressure || result.Summary.BackpressureEvents > 0,
		ResetCorrect:        !scenario.ExpectReset || result.Summary.FlowsReset > 0,
		ErrorResetCorrect:   (!scenario.ExpectTargetError || result.Summary.TargetErrors > 0) && (!scenario.ExpectTargetReset || result.Summary.TargetResets > 0),
		CapabilityRejected:  scenario.Type != ScenarioCapabilityDowngrade || err != nil,
		MalformedRejected:   scenario.Type != ScenarioMalformedFlowDescriptor || err != nil,
		TraceHygiene:        !result.Summary.PayloadLogged && !result.Summary.SecretLogged,
	}
	correct := checks.TraceHygiene
	if scenario.ExpectFailure {
		correct = err != nil && checks.CapabilityRejected && checks.MalformedRejected
	} else {
		correct = err == nil && checks.FlowMappingCorrect && checks.BackpressureCorrect && checks.ResetCorrect && checks.ErrorResetCorrect
	}
	run := ScenarioRun{
		ProfileID:   p.ID,
		Scenario:    scenario.Type,
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
		case mutant.ModeAdapterAcceptsInvalidFlow:
			if runs[i].Scenario == ScenarioMalformedFlowDescriptor {
				runs[i].Correct = false
				runs[i].Checks.MalformedRejected = false
				runs[i].Failure = ""
			}
		case mutant.ModeAdapterIgnoresBackpressure:
			runs[i].Summary.BackpressureEvents = 0
			runs[i].Checks.BackpressureCorrect = false
			if runs[i].Scenario == ScenarioLargeFlowBackpressure || runs[i].Scenario == ScenarioAdapterQueuePressure {
				runs[i].Correct = false
			}
		case mutant.ModeAdapterLeaksPayloadTrace:
			runs[i].Summary.PayloadLogged = true
			runs[i].Checks.TraceHygiene = false
			runs[i].Correct = false
		case mutant.ModeAdapterLeaksSecretTrace:
			runs[i].Summary.SecretLogged = true
			runs[i].Checks.TraceHygiene = false
			runs[i].Correct = false
		case mutant.ModeAdapterAcceptsCapabilityDowngrade:
			if runs[i].Scenario == ScenarioCapabilityDowngrade {
				runs[i].Correct = false
				runs[i].Checks.CapabilityRejected = false
				runs[i].Failure = ""
			}
		case mutant.ModeAdapterIgnoresMaxFlows:
			runs[i].Summary.FlowsOpened += 512
			runs[i].Correct = false
		case mutant.ModeAdapterWrongResetMapping:
			runs[i].Summary.FlowsReset = 0
			runs[i].Checks.ResetCorrect = false
			if runs[i].Scenario == ScenarioFlowResetIsolation || runs[i].Scenario == ScenarioTargetResetToFlowReset {
				runs[i].Correct = false
			}
		}
	}
	return runs
}

func policyShape(p *ir.Profile) string {
	return joinShape(
		p.Stream.IDStrategy,
		p.Stream.PriorityPolicy,
		p.ProxySemantics.TargetClosePolicy,
		p.ProxySemantics.TargetResetPolicy,
		p.CarrierPolicy.BackpressurePolicy,
		p.CarrierPolicy.FlushPolicy,
	)
}
