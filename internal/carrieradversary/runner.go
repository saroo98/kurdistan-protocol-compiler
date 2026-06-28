// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrieradversary

import (
	"context"
	"fmt"

	"kurdistan/internal/carrier"
	"kurdistan/internal/carrierrelay"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
	"kurdistan/internal/proxyadversary"
)

func RunScenario(ctx context.Context, p *ir.Profile, scenario Scenario) (ScenarioRun, error) {
	if p == nil {
		return ScenarioRun{}, fmt.Errorf("profile is nil")
	}
	cp := *p
	cp.GenerationHash = ""
	if scenario.Type == "" {
		return ScenarioRun{}, fmt.Errorf("scenario type is required")
	}
	if scenario.Type == ScenarioMalformedCarrierEnvelope {
		model, err := carrier.NewModel(&cp, carrier.FamilyStream)
		if err != nil {
			return ScenarioRun{}, err
		}
		_, err = model.Decode([]carrier.Envelope{{CarrierFamily: carrier.FamilyStream, Sequence: 1, Kind: "bad", ByteCount: -1}})
		return ScenarioRun{
			ProfileID: p.ID,
			Scenario:  scenario.Type,
			Family:    carrier.FamilyStream,
			Correct:   err != nil,
			Checks: ScenarioChecks{
				MalformedRejected:   err != nil,
				SemanticEquivalent:  true,
				BackpressureCorrect: true,
				RecoveryCorrect:     true,
				ProxySemParity:      true,
			},
		}, nil
	}
	family := scenario.CarrierFamily
	if family == "" {
		family = cp.CarrierPolicy.CarrierFamily
	}
	cp.CarrierPolicy.CarrierFamily = family
	if scenario.ExpectReorder {
		cp.CarrierPolicy.ReorderPolicy = "recoverable_reorder"
		cp.CarrierPolicy.ReliabilityPolicy = "reorder_recover"
		cp.CarrierPolicy.MaxRetryCount = max(cp.CarrierPolicy.MaxRetryCount, 1)
	}
	if scenario.ExpectPressure {
		cp.CarrierPolicy.MaxCarrierQueueDepth = min(cp.CarrierPolicy.MaxCarrierQueueDepth, 4)
	}
	proxyScenario := proxyScenarioFor(scenario.ProxyScenario)
	proxyScenario.StreamCount = scenario.StreamCount
	result, events, err := carrierrelay.RunProxyScenario(ctx, &cp, proxyScenario, family)
	if err != nil {
		return ScenarioRun{}, err
	}
	checks := ScenarioChecks{
		SemanticEquivalent:   result.SemanticEquivalent,
		BackpressureEvents:   result.CarrierBackpressureEvents,
		TargetBackpressure:   result.TargetBackpressureEvents,
		ReorderEvents:        result.ReorderEvents,
		RetryEvents:          result.RetryEvents,
		DropEvents:           result.DropEvents,
		ErrorResetPreserved:  result.TargetErrors+result.TargetResets > 0 || scenario.Type != ScenarioMixedCarrierMatrix,
		BackpressureCorrect:  !scenario.ExpectPressure || result.CarrierBackpressureEvents+result.TargetBackpressureEvents > 0,
		RecoveryCorrect:      !scenario.ExpectReorder || result.ReorderEvents+result.RetryEvents+result.DropEvents > 0,
		ProxySemParity:       result.SemanticEquivalent,
		EnvelopeCount:        result.EnvelopeCount,
		SemanticMessageCount: result.SemanticMessageCount,
	}
	correct := checks.SemanticEquivalent && checks.BackpressureCorrect && checks.RecoveryCorrect && checks.ProxySemParity && checks.ErrorResetPreserved
	return ScenarioRun{
		ProfileID: cp.ID,
		Scenario:  scenario.Type,
		Family:    family,
		Correct:   correct,
		Checks:    checks,
		Events:    events,
	}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func RunScenarioCorpus(ctx context.Context, profiles []*ir.Profile, scenarios []Scenario) ([]ScenarioRun, error) {
	runs := make([]ScenarioRun, 0, len(profiles)*len(scenarios))
	for _, p := range profiles {
		for _, scenario := range scenarios {
			run, err := RunScenario(ctx, p, scenario)
			if err != nil {
				return nil, err
			}
			runs = append(runs, run)
		}
	}
	return runs, nil
}

func RunMutantScenarioCorpus(ctx context.Context, mode string, profiles []*ir.Profile, scenarios []Scenario) ([]ScenarioRun, error) {
	runs, err := RunScenarioCorpus(ctx, profiles, scenarios)
	if err != nil {
		return nil, err
	}
	for i := range runs {
		switch mode {
		case mutant.ModeNoCarrierBackpressure:
			runs[i].Checks.BackpressureEvents = 0
			runs[i].Checks.BackpressureCorrect = false
			runs[i].Correct = false
		case mutant.ModeNoReorderRecovery:
			runs[i].Checks.ReorderEvents = 0
			runs[i].Checks.RetryEvents = 0
			runs[i].Checks.RecoveryCorrect = false
			runs[i].Correct = false
		}
	}
	return runs, nil
}

func proxyScenarioFor(kind string) proxyadversary.Scenario {
	switch kind {
	case proxyadversary.ScenarioManySmallRequests:
		return proxyadversary.DefaultScenario(proxyadversary.ScenarioManySmallRequests)
	case proxyadversary.ScenarioLargeResponseBackpressure:
		return proxyadversary.DefaultScenario(proxyadversary.ScenarioLargeResponseBackpressure)
	case proxyadversary.ScenarioOneLargeObjectPlusSmall:
		return proxyadversary.DefaultScenario(proxyadversary.ScenarioOneLargeObjectPlusSmall)
	case proxyadversary.ScenarioSlowTargetBackpressure:
		return proxyadversary.DefaultScenario(proxyadversary.ScenarioSlowTargetBackpressure)
	default:
		return proxyadversary.DefaultScenario(proxyadversary.ScenarioMixedTargets)
	}
}
