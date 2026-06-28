// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrierrelay

import (
	"context"
	"testing"

	"kurdistan/internal/carrier"
	"kurdistan/internal/compiler"
	"kurdistan/internal/proxyadversary"
)

func TestProxyScenarioSurvivesCarrierRoundTrip(t *testing.T) {
	p, err := compiler.Generate(11011)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"stream_carrier", "message_carrier", "chunked_carrier", "batch_carrier", "long_poll_style_carrier"} {
		t.Run(family, func(t *testing.T) {
			result, events, err := RunProxyScenario(context.Background(), p, proxyadversary.DefaultScenario(proxyadversary.ScenarioMixedTargets), family)
			if err != nil {
				t.Fatal(err)
			}
			if !result.SemanticEquivalent || result.EnvelopeCount == 0 {
				t.Fatalf("carrier did not preserve proxy semantics: %+v", result)
			}
			if result.TargetErrors == 0 || result.TargetResets == 0 {
				t.Fatalf("target error/reset semantics not preserved: %+v", result)
			}
			for _, ev := range events {
				if ev.EventType != "carrier_envelope" {
					continue
				}
				if ev.CarrierFamilyBucket != family {
					t.Fatalf("missing carrier family trace metadata: %#v", ev)
				}
			}
		})
	}
}

func TestCarrierBackpressurePlusTargetBackpressure(t *testing.T) {
	p, err := compiler.Generate(11012)
	if err != nil {
		t.Fatal(err)
	}
	p.GenerationHash = ""
	p.CarrierPolicy.CarrierFamily = carrier.FamilyLongPollStyle
	p.CarrierPolicy.MaxCarrierQueueDepth = 2
	result, _, err := RunProxyScenario(context.Background(), p, proxyadversary.DefaultScenario(proxyadversary.ScenarioSlowTargetBackpressure), carrier.FamilyLongPollStyle)
	if err != nil {
		t.Fatal(err)
	}
	if !result.SemanticEquivalent || result.CarrierBackpressureEvents == 0 || result.TargetBackpressureEvents == 0 {
		t.Fatalf("backpressure chain not represented: %+v", result)
	}
}
