// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrierrelay

import (
	"context"
	"fmt"
	"sort"

	"kurdistan/internal/carrier"
	"kurdistan/internal/ir"
	"kurdistan/internal/proxyadversary"
	ktrace "kurdistan/internal/trace"
)

type Result struct {
	Family                    string `json:"family"`
	EnvelopeCount             int    `json:"envelope_count"`
	SemanticMessageCount      int    `json:"semantic_message_count"`
	SemanticEquivalent        bool   `json:"semantic_equivalent"`
	TargetErrors              int    `json:"target_errors"`
	TargetResets              int    `json:"target_resets"`
	TargetBackpressureEvents  int    `json:"target_backpressure_events"`
	CarrierBackpressureEvents int    `json:"carrier_backpressure_events"`
	ReorderEvents             int    `json:"reorder_events"`
	RetryEvents               int    `json:"retry_events"`
	DropEvents                int    `json:"drop_events"`
}

func RunProxyScenario(ctx context.Context, p *ir.Profile, scenario proxyadversary.Scenario, family string) (Result, []ktrace.Event, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, nil, err
	}
	if p == nil {
		return Result{}, nil, fmt.Errorf("profile is nil")
	}
	run, err := proxyadversary.RunScenario(ctx, p, scenario)
	if err != nil {
		return Result{}, nil, err
	}
	messages := SemanticMessagesFromEvents(run.Events)
	roundTrip, err := carrier.RoundTrip(p, family, messages)
	if err != nil {
		return Result{}, nil, err
	}
	carrierEvents := carrier.TraceEvents(p.ID, scenario.Type, roundTrip.Envelopes, roundTrip.Reconstructed)
	events := append([]ktrace.Event{}, run.Events...)
	events = append(events, carrierEvents...)
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].CarrierFamilyBucket == events[j].CarrierFamilyBucket {
			return events[i].EventType < events[j].EventType
		}
		return events[i].CarrierFamilyBucket < events[j].CarrierFamilyBucket
	})
	_, retries, reordered, dropped := carrier.ReliabilityStats(roundTrip.Envelopes)
	return Result{
		Family:                    roundTrip.Family,
		EnvelopeCount:             roundTrip.EnvelopeCount,
		SemanticMessageCount:      len(messages),
		SemanticEquivalent:        roundTrip.Reconstructed,
		TargetErrors:              run.Checks.TargetErrorCount,
		TargetResets:              run.Checks.TargetResetCount,
		TargetBackpressureEvents:  run.Checks.BackpressureEvents,
		CarrierBackpressureEvents: roundTrip.Backpressure,
		ReorderEvents:             reordered,
		RetryEvents:               retries,
		DropEvents:                dropped,
	}, events, nil
}

func SemanticMessagesFromEvents(events []ktrace.Event) []carrier.SemanticMessage {
	messages := []carrier.SemanticMessage{}
	for _, ev := range events {
		if ev.Semantic == "" {
			continue
		}
		byteCount := ev.PayloadBytes
		if byteCount == 0 {
			byteCount = ev.FrameBytes
		}
		if byteCount == 0 {
			byteCount = 1
		}
		messages = append(messages, carrier.SemanticMessage{
			StreamID:      streamBucketID(ev.StreamLabel),
			Semantic:      ev.Semantic,
			ByteCount:     byteCount,
			PriorityClass: ev.PriorityClass,
			MetadataClass: ev.TargetEventType,
		})
	}
	return messages
}

func streamBucketID(label string) uint64 {
	if label == "" {
		return 1
	}
	var sum uint64
	for _, r := range label {
		sum += uint64(r)
	}
	return sum%16 + 1
}
