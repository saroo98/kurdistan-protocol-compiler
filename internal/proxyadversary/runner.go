// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyadversary

import (
	"context"
	"fmt"

	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
	"kurdistan/internal/proxyrelay"
	"kurdistan/internal/proxysem"
)

func RunScenario(ctx context.Context, p *ir.Profile, scenario Scenario) (ScenarioRun, error) {
	if err := ctx.Err(); err != nil {
		return ScenarioRun{}, err
	}
	if err := ir.Validate(p); err != nil {
		return ScenarioRun{}, err
	}
	if scenario.Type == "" {
		return ScenarioRun{}, fmt.Errorf("scenario type is required")
	}
	if scenario.DescriptorInvalid {
		intent := proxysem.RelayIntent{
			StreamID:         1,
			Target:           proxysem.TargetDescriptor{Class: "unknown_target"},
			RequestClass:     proxysem.RequestErrorTest,
			PriorityClass:    proxysem.PriorityControl,
			ResponseMode:     proxysem.ResponseErrorable,
			MaxRequestBytes:  p.ProxySemantics.MaxRequestBytes,
			MaxResponseBytes: p.ProxySemantics.MaxResponseBytes,
		}
		err := proxysem.ValidateRelayIntent(intent)
		run := ScenarioRun{
			ProfileID:     p.ID,
			Scenario:      scenario.Type,
			Correct:       err != nil,
			TargetClasses: []string{"unknown_target"},
			Checks: ScenarioChecks{
				DescriptorProbeRejected:   err != nil,
				TargetBackpressureCorrect: true,
				ErrorResetIsolation:       true,
				FairnessCorrect:           true,
			},
		}
		return run, nil
	}
	requests := requestsForScenario(p, scenario)
	result, events, err := proxyrelay.Simulate(ctx, p, requests)
	if err != nil {
		return ScenarioRun{}, err
	}
	checks := ScenarioChecks{
		BackpressureEvents:        result.BackpressureEvents,
		WindowUpdateEvents:        result.WindowUpdateEvents,
		TargetErrorCount:          result.TargetErrors,
		TargetResetCount:          result.ResetStreams,
		TargetCloseCount:          result.ClosedStreams,
		TargetBackpressureCorrect: true,
		ErrorResetIsolation:       true,
		FairnessCorrect:           true,
	}
	switch scenario.Type {
	case ScenarioSlowTargetBackpressure:
		checks.TargetBackpressureCorrect = result.BackpressureEvents > 0
	case ScenarioLargeResponseBackpressure:
		checks.TargetBackpressureCorrect = result.BackpressureEvents > 0 && result.WindowUpdateEvents > 0
	case ScenarioErrorTargetIsolation:
		checks.ErrorResetIsolation = result.TargetErrors > 0 && result.OtherStreamsContinued
	case ScenarioTargetResetMidstream:
		checks.ErrorResetIsolation = result.ResetStreams > 0 && result.OtherStreamsContinued
	case ScenarioOneLargeObjectPlusSmall, ScenarioDripResponsePriority:
		checks.FairnessCorrect = result.ResponseBytes > 0 && result.ClosedStreams+result.ResetStreams+result.TargetErrors >= 1
	}
	classes := make([]string, 0, len(result.TargetClasses))
	for class := range result.TargetClasses {
		classes = append(classes, class)
	}
	correct := checks.TargetBackpressureCorrect && checks.ErrorResetIsolation && checks.FairnessCorrect
	return ScenarioRun{
		ProfileID:     p.ID,
		Scenario:      scenario.Type,
		Correct:       correct,
		Checks:        checks,
		TargetClasses: classes,
		Events:        events,
	}, nil
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
		case mutant.ModeNoTargetBackpressure:
			runs[i].Checks.BackpressureEvents = 0
			runs[i].Checks.WindowUpdateEvents = 0
			runs[i].Checks.TargetBackpressureCorrect = false
			runs[i].Correct = false
			for j := range runs[i].Events {
				runs[i].Events[j].Backpressure = false
				runs[i].Events[j].TargetBackpressure = false
			}
		}
	}
	return runs, nil
}

func requestsForScenario(p *ir.Profile, scenario Scenario) []proxyrelay.IntentRequest {
	if p.ProxySemantics.MaxResponseBytes > 0 && scenario.ResponseBytes > p.ProxySemantics.MaxResponseBytes {
		scenario.ResponseBytes = p.ProxySemantics.MaxResponseBytes
	}
	if p.ProxySemantics.MaxRequestBytes > 0 && scenario.RequestBytes > p.ProxySemantics.MaxRequestBytes {
		scenario.RequestBytes = p.ProxySemantics.MaxRequestBytes
	}
	count := scenario.StreamCount
	if count <= 0 {
		count = 3
	}
	if count > p.Stream.MaxConcurrentStreams {
		count = p.Stream.MaxConcurrentStreams
	}
	classes := targetClassesForScenario(scenario)
	requests := make([]proxyrelay.IntentRequest, 0, count)
	for i := 0; i < count; i++ {
		class := classes[i%len(classes)]
		params := paramsForClass(class, scenario, i)
		requestSize := scenario.RequestBytes + i*64
		if p.ProxySemantics.MaxRequestBytes > 0 && requestSize > p.ProxySemantics.MaxRequestBytes {
			requestSize = p.ProxySemantics.MaxRequestBytes
		}
		requestClass := proxysem.RequestBulk
		priority := proxysem.PriorityBulk
		if i%2 == 0 || class == proxysem.TargetDripResponse {
			requestClass = proxysem.RequestInteractive
			priority = proxysem.PriorityInteractive
		}
		mode := responseModeForClass(class)
		requests = append(requests, proxyrelay.IntentRequest{
			Label:       fmt.Sprintf("%s_%02d", scenario.Type, i+1),
			Scenario:    scenario.Type,
			RequestSize: requestSize,
			Intent: proxysem.RelayIntent{
				RelayIntentID:    uint64(i + 1),
				Target:           proxysem.TargetDescriptor{Class: class, Variant: fmt.Sprintf("v%d", i%3), Parameters: params},
				RequestClass:     requestClass,
				PriorityClass:    priority,
				ResponseMode:     mode,
				MaxRequestBytes:  p.ProxySemantics.MaxRequestBytes,
				MaxResponseBytes: p.ProxySemantics.MaxResponseBytes,
			},
		})
	}
	return requests
}

func targetClassesForScenario(scenario Scenario) []string {
	switch scenario.Type {
	case ScenarioManySmallRequests:
		return []string{proxysem.TargetEcho, proxysem.TargetFixedResponse, proxysem.TargetEcho, proxysem.TargetFixedResponse}
	case ScenarioOneLargeObjectPlusSmall:
		return []string{proxysem.TargetLargeObject, proxysem.TargetFixedResponse, proxysem.TargetEcho, proxysem.TargetFixedResponse}
	case ScenarioSlowTargetBackpressure:
		return []string{proxysem.TargetSlowResponse, proxysem.TargetEcho, proxysem.TargetFixedResponse}
	case ScenarioChunkedResponseMix:
		return []string{proxysem.TargetChunkedResponse, proxysem.TargetChunkedResponse, proxysem.TargetFixedResponse, proxysem.TargetEcho}
	case ScenarioErrorTargetIsolation:
		return []string{proxysem.TargetErrorResponse, proxysem.TargetEcho, proxysem.TargetFixedResponse}
	case ScenarioTargetResetMidstream:
		return []string{proxysem.TargetResetMidstream, proxysem.TargetEcho, proxysem.TargetFixedResponse}
	case ScenarioMixedTargets:
		return []string{proxysem.TargetErrorResponse, proxysem.TargetEcho, proxysem.TargetFixedResponse, proxysem.TargetSlowResponse, proxysem.TargetChunkedResponse, proxysem.TargetLargeObject, proxysem.TargetDripResponse, proxysem.TargetJitteryResponse}
	case ScenarioLargeResponseBackpressure:
		return []string{proxysem.TargetLargeObject, proxysem.TargetEcho}
	case ScenarioDripResponsePriority:
		return []string{proxysem.TargetDripResponse, proxysem.TargetEcho, proxysem.TargetFixedResponse, proxysem.TargetDripResponse}
	default:
		return []string{proxysem.TargetEcho, proxysem.TargetFixedResponse}
	}
}

func paramsForClass(class string, scenario Scenario, index int) map[string]string {
	params := map[string]string{}
	switch class {
	case proxysem.TargetFixedResponse:
		params["bytes"] = fmt.Sprint(max(256, scenario.ResponseBytes/2+index*128))
	case proxysem.TargetSlowResponse:
		params["bytes"] = fmt.Sprint(max(2048, scenario.ResponseBytes))
		params["ticks"] = fmt.Sprint(max(2, scenario.ResponseChunks))
	case proxysem.TargetChunkedResponse:
		params["bytes"] = fmt.Sprint(max(2048, scenario.ResponseBytes))
		params["chunks"] = fmt.Sprint(max(2, scenario.ResponseChunks))
	case proxysem.TargetLargeObject:
		params["bytes"] = fmt.Sprint(max(64*1024, scenario.ResponseBytes))
	case proxysem.TargetResetMidstream:
		params["partial"] = "256"
	case proxysem.TargetDripResponse:
		params["bytes"] = fmt.Sprint(max(1024, scenario.ResponseBytes))
		params["chunks"] = fmt.Sprint(max(8, scenario.ResponseChunks))
	case proxysem.TargetJitteryResponse:
		params["bytes"] = fmt.Sprint(max(1024, scenario.ResponseBytes))
		params["seed"] = fmt.Sprint(index + 7)
	}
	return params
}

func responseModeForClass(class string) proxysem.ResponseMode {
	switch class {
	case proxysem.TargetSlowResponse:
		return proxysem.ResponseDelayed
	case proxysem.TargetChunkedResponse, proxysem.TargetDripResponse:
		return proxysem.ResponseChunked
	case proxysem.TargetLargeObject:
		return proxysem.ResponseLargeObject
	case proxysem.TargetErrorResponse:
		return proxysem.ResponseErrorable
	case proxysem.TargetResetMidstream:
		return proxysem.ResponseResettable
	default:
		return proxysem.ResponseImmediate
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
