// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adversary

import (
	"fmt"
	"math/rand"

	ktrace "kurdistan/internal/trace"
)

type ControlFamily struct {
	Name     string           `json:"name"`
	Expected string           `json:"expected"`
	Traces   [][]ktrace.Event `json:"-"`
}

func DefaultControlFamilies(count int, seed int64) []ControlFamily {
	if count <= 0 {
		count = 8
	}
	return []ControlFamily{
		{Name: "fixed_protocol", Expected: "tight fixed-signature cluster", Traces: FixedProtocolTraces(count)},
		{Name: "noisy_fixed_protocol", Expected: "tight fixed-family cluster despite padding and timing noise", Traces: NoisyFixedProtocolTraces(count, seed+101)},
		{Name: "random_byte_protocol", Expected: "noisy random baseline, not structured diversity", Traces: RandomByteProtocolTraces(count, seed+202)},
		{Name: "raw_echo_baseline", Expected: "simple shape baseline only", Traces: RawEchoBaselineTraces(count)},
	}
}

func FixedProtocolTraces(count int) [][]ktrace.Event {
	traces := make([][]ktrace.Event, 0, count)
	for i := 0; i < count; i++ {
		profileID := fmt.Sprintf("fixed_protocol_%03d", i)
		traces = append(traces, []ktrace.Event{
			controlEvent(profileID, 0, "first_contact", "s0", "client_to_server", 36, 20, 0, "fixed_setup"),
			controlEvent(profileID, 1, "first_contact", "s1", "server_to_client", 32, 16, 0, "fixed_reply"),
			controlEvent(profileID, 2, "first_contact", "s2", "client_to_server", 48, 32, 0, "fixed_proof"),
			controlEvent(profileID, 3, "frame_encode", "s2", "client_to_server", 96, 64, 0, "data"),
			controlEvent(profileID, 4, "frame_decode", "s2", "server_to_client", 96, 64, 0, "data"),
			{TimeUnixNano: controlTime(5), ProfileID: profileID, EventType: "invalid_input", Note: "fixed_invalid"},
			{TimeUnixNano: controlTime(6), ProfileID: profileID, EventType: "malformed_frame", Note: "fixed_malformed"},
			{TimeUnixNano: controlTime(7), ProfileID: profileID, EventType: "close", Note: "fixed_close"},
		})
	}
	return traces
}

func NoisyFixedProtocolTraces(count int, seed int64) [][]ktrace.Event {
	rng := rand.New(rand.NewSource(seed))
	traces := make([][]ktrace.Event, 0, count)
	for i := 0; i < count; i++ {
		profileID := fmt.Sprintf("noisy_fixed_protocol_%03d", i)
		padA := rng.Intn(24)
		padB := rng.Intn(24)
		jitter := int64(rng.Intn(4))
		traces = append(traces, []ktrace.Event{
			controlEventAt(profileID, 0+jitter, "first_contact", "s0", "client_to_server", 36, 20, rng.Intn(4), "fixed_setup"),
			controlEventAt(profileID, 2+jitter, "first_contact", "s1", "server_to_client", 32, 16, rng.Intn(4), "fixed_reply"),
			controlEventAt(profileID, 4+jitter, "first_contact", "s2", "client_to_server", 48, 32, rng.Intn(4), "fixed_proof"),
			controlEventAt(profileID, 6+jitter, "frame_encode", "s2", "client_to_server", 96+padA, 64, padA, "data"),
			controlEventAt(profileID, 8+jitter, "frame_decode", "s2", "server_to_client", 96+padB, 64, padB, "data"),
			{TimeUnixNano: controlTime(10 + jitter), ProfileID: profileID, EventType: "invalid_input", Note: "fixed_invalid"},
			{TimeUnixNano: controlTime(11 + jitter), ProfileID: profileID, EventType: "malformed_frame", Note: "fixed_malformed"},
			{TimeUnixNano: controlTime(12 + jitter), ProfileID: profileID, EventType: "close", Note: "fixed_close"},
		})
	}
	return traces
}

func RandomByteProtocolTraces(count int, seed int64) [][]ktrace.Event {
	rng := rand.New(rand.NewSource(seed))
	traces := make([][]ktrace.Event, 0, count)
	directions := []string{"client_to_server", "server_to_client"}
	types := []string{"frame_encode", "frame_decode", "first_contact"}
	for i := 0; i < count; i++ {
		profileID := fmt.Sprintf("random_byte_protocol_%03d", i)
		eventCount := 3 + rng.Intn(8)
		events := make([]ktrace.Event, 0, eventCount+1)
		now := int64(0)
		for j := 0; j < eventCount; j++ {
			now += int64(1 + rng.Intn(30))
			frameBytes := 8 + rng.Intn(4096)
			payloadBytes := rng.Intn(frameBytes + 1)
			paddingBytes := frameBytes - payloadBytes
			events = append(events, ktrace.Event{
				TimeUnixNano:  controlTime(now),
				ProfileID:     profileID,
				EventType:     types[rng.Intn(len(types))],
				State:         fmt.Sprintf("r%d", rng.Intn(50)),
				Semantic:      "opaque",
				Direction:     directions[rng.Intn(len(directions))],
				FrameBytes:    frameBytes,
				PayloadBytes:  payloadBytes,
				PaddingBytes:  paddingBytes,
				SchedulerMode: "random",
			})
		}
		if rng.Intn(2) == 0 {
			events = append(events, ktrace.Event{TimeUnixNano: controlTime(now + 1), ProfileID: profileID, EventType: "close", Note: fmt.Sprintf("random_close_%d", rng.Intn(1000))})
		}
		traces = append(traces, events)
	}
	return traces
}

func RawEchoBaselineTraces(count int) [][]ktrace.Event {
	traces := make([][]ktrace.Event, 0, count)
	for i := 0; i < count; i++ {
		profileID := fmt.Sprintf("raw_echo_baseline_%03d", i)
		size := 64 + i%4
		traces = append(traces, []ktrace.Event{
			controlEvent(profileID, 0, "frame_encode", "", "client_to_server", size, size, 0, "data"),
			controlEvent(profileID, 1, "frame_decode", "", "server_to_client", size, size, 0, "data"),
			{TimeUnixNano: controlTime(2), ProfileID: profileID, EventType: "close", Note: "raw_echo_close"},
		})
	}
	return traces
}

func controlEvent(profileID string, index int64, eventType, state, direction string, frameBytes, payloadBytes, paddingBytes int, semantic string) ktrace.Event {
	return controlEventAt(profileID, index, eventType, state, direction, frameBytes, payloadBytes, paddingBytes, semantic)
}

func controlEventAt(profileID string, index int64, eventType, state, direction string, frameBytes, payloadBytes, paddingBytes int, semantic string) ktrace.Event {
	return ktrace.Event{
		TimeUnixNano:  controlTime(index),
		ProfileID:     profileID,
		EventType:     eventType,
		State:         state,
		Semantic:      semantic,
		Direction:     direction,
		FrameBytes:    frameBytes,
		PayloadBytes:  payloadBytes,
		PaddingBytes:  paddingBytes,
		SchedulerMode: "fixed_flush",
	}
}

func controlTime(index int64) int64 {
	return 1_700_000_000_000_000_000 + index*1_000_000
}
