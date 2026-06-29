// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimeadversary

import (
	"context"

	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
	kruntime "kurdistan/internal/runtime"
)

func RunScenario(ctx context.Context, p *ir.Profile, scenario Scenario) ScenarioRun {
	opts := kruntime.HarnessOptions{
		Scenario:       ProxyScenarioFor(scenario.Type),
		CarrierFamily:  scenario.CarrierFamily,
		StreamCount:    scenario.StreamCount,
		ReplayInject:   scenario.Type == ScenarioReplayInjection,
		LinkQueueDepth: scenario.QueueDepth,
	}
	if scenario.Type == ScenarioCapabilityDowngrade {
		opts.ServerFeatures = []string{"multi_stream"}
	}
	if scenario.Type == ScenarioProfileMismatchSession {
		other := *p
		other.ID = p.ID + "_mismatch"
		other.GenerationHash = ""
		opts.ProfileMismatch = &other
	}
	if scenario.Type == ScenarioMalformedLinkFrame {
		opts.ReplayInject = true
	}
	summary, events, err := kruntime.RunLocalHarness(ctx, p, opts)
	run := ScenarioRun{ProfileID: p.ID, Scenario: scenario.Type, Summary: summary, Events: events, Correct: err == nil}
	if err != nil {
		run.Failure = err.Error()
	}
	switch scenario.Type {
	case ScenarioCapabilityDowngrade, ScenarioProfileMismatchSession:
		run.Correct = err != nil
	case ScenarioReplayInjection, ScenarioMalformedLinkFrame:
		run.Correct = err == nil && summary.ReplayRejected > 0
	case ScenarioTargetErrorIsolation:
		run.Correct = err == nil && summary.TargetErrors > 0 && summary.ClientState == "closed"
	case ScenarioTargetResetIsolation:
		run.Correct = err == nil && summary.TargetResets > 0 && summary.ClientState == "closed"
	case ScenarioCarrierQueuePressure, ScenarioLargeObjectRuntime:
		run.Correct = err == nil && summary.BackpressureEvents > 0
	case ScenarioCloseRace:
		run.Correct = err == nil && summary.ClientState == "closed" && summary.ServerState == "closed"
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
		case mutant.ModeRuntimeAcceptsCapabilityDowngrade:
			if runs[i].Scenario == ScenarioCapabilityDowngrade {
				runs[i].Correct = false
				runs[i].Failure = ""
			}
		case mutant.ModeRuntimeAcceptsProfileMismatch:
			if runs[i].Scenario == ScenarioProfileMismatchSession {
				runs[i].Correct = false
				runs[i].Failure = ""
			}
		case mutant.ModeRuntimeAcceptsReplay:
			runs[i].Summary.ReplayRejected = 0
			if runs[i].Scenario == ScenarioReplayInjection {
				runs[i].Correct = false
			}
		case mutant.ModeRuntimeIgnoresBackpressure:
			runs[i].Summary.BackpressureEvents = 0
			if runs[i].Scenario == ScenarioCarrierQueuePressure || runs[i].Scenario == ScenarioLargeObjectRuntime {
				runs[i].Correct = false
			}
		case mutant.ModeRuntimeLeaksSecretTrace:
			runs[i].Summary.SecretLogged = true
			runs[i].Correct = false
		case mutant.ModeRuntimeLeaksPayloadTrace:
			runs[i].Summary.PayloadLogged = true
			runs[i].Correct = false
		case mutant.ModeRuntimeNoStateValidation:
			runs[i].Summary.ClientState = "open"
			runs[i].Correct = false
		}
	}
	return runs
}
