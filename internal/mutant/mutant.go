package mutant

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	ktrace "kurdistan/internal/trace"
)

const (
	ModeFixedFirstContact   = "fixed_first_contact"
	ModeFixedFrameGrammar   = "fixed_frame_grammar"
	ModeCosmeticSymbolsOnly = "cosmetic_symbols_only"
	ModeFixedScheduler      = "fixed_scheduler"
	ModeFixedInvalidInput   = "fixed_invalid_input"
	ModePaddingNoiseOnly    = "padding_noise_only"
)

func Modes() []string {
	return []string{
		ModeFixedFirstContact,
		ModeFixedFrameGrammar,
		ModeCosmeticSymbolsOnly,
		ModeFixedScheduler,
		ModeFixedInvalidInput,
		ModePaddingNoiseOnly,
	}
}

func GenerateProfiles(mode string, startSeed int64, count int) ([]*ir.Profile, error) {
	if count < 0 {
		return nil, fmt.Errorf("count must be non-negative")
	}
	if !knownMode(mode) {
		return nil, fmt.Errorf("unknown mutant mode %q", mode)
	}
	base, err := compiler.Generate(startSeed)
	if err != nil {
		return nil, err
	}
	profiles := make([]*ir.Profile, 0, count)
	for i := 0; i < count; i++ {
		seed := startSeed + int64(i)
		p, err := compiler.Generate(seed)
		if err != nil {
			return nil, err
		}
		switch mode {
		case ModeFixedFirstContact:
			applyFixedFirstContact(p, base)
			renameWireSymbols(p, mode, i)
		case ModeFixedFrameGrammar:
			p.FrameGrammar = cloneFrameGrammar(base.FrameGrammar)
		case ModeCosmeticSymbolsOnly:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
		case ModeFixedScheduler:
			p.Scheduler = base.Scheduler
		case ModeFixedInvalidInput:
			p.InvalidInput = base.InvalidInput
		case ModePaddingNoiseOnly:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
			p.Padding = paddingForIndex(i)
		}
		refreshMetadata(p, mode, seed, i)
		if err := ir.Validate(p); err != nil {
			return nil, fmt.Errorf("%s mutant %d invalid: %w", mode, i, err)
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

func TraceFixtures(mode string, profiles []*ir.Profile) [][]ktrace.Event {
	switch mode {
	case ModeFixedFirstContact:
		return fixedProtocolShapeTraces(mode, profiles, false)
	case ModePaddingNoiseOnly:
		return fixedProtocolShapeTraces(mode, profiles, true)
	default:
		return profileShapeTraces(mode, profiles)
	}
}

func applyFixedFirstContact(p, base *ir.Profile) {
	p.States = cloneStates(base.States)
	p.Transitions = cloneTransitions(base.Transitions)
	p.FirstContact = cloneFirstContact(base.FirstContact)
	p.Auth.ProofMessage = base.Auth.ProofMessage
}

func renameWireSymbols(p *ir.Profile, mode string, index int) {
	used := map[string]bool{}
	for i := range p.Messages {
		symbol := symbolFor(mode, "msg", index, i, 14)
		p.Messages[i].WireSymbol = symbol
		used[symbol] = true
	}
	for i := range p.FirstContact.Steps {
		symbol := symbolFor(mode, "fc", index, i, 12)
		for used[symbol] {
			symbol = symbolFor(mode, "fcx", index, i, 12)
		}
		p.FirstContact.Steps[i].WireSymbol = symbol
		used[symbol] = true
	}
}

func refreshMetadata(p *ir.Profile, mode string, seed int64, index int) {
	p.ID = fmt.Sprintf("mutant_%s_%03d", strings.ReplaceAll(mode, "-", "_"), index)
	p.Seed = seed
	p.GenerationHash = ""
	p.Auth.KeyID = fmt.Sprintf("test-only-mutant-%s-%03d", shortMode(mode), index)
	p.Auth.TestKeyHex = testKeyHex(mode, seed, index)
	hash, err := ir.CanonicalHash(p)
	if err == nil {
		p.GenerationHash = hash
	}
}

func paddingForIndex(index int) ir.PaddingPolicy {
	minPad := index % 8
	return ir.PaddingPolicy{
		Mode:            "bounded",
		MinPaddingBytes: minPad,
		MaxPaddingBytes: minPad + 8 + (index % 5),
		Probability:     1,
	}
}

func profileShapeTraces(mode string, profiles []*ir.Profile) [][]ktrace.Event {
	traces := make([][]ktrace.Event, 0, len(profiles))
	for i, p := range profiles {
		var events []ktrace.Event
		for j, step := range p.FirstContact.Steps {
			events = append(events, ktrace.Event{
				TimeUnixNano:  fixtureTime(j),
				ProfileID:     p.ID,
				EventType:     "first_contact",
				State:         step.ToState,
				Semantic:      step.Message,
				Direction:     step.Direction,
				FrameBytes:    contactFrameBytes(step),
				PayloadBytes:  step.PayloadSize,
				SchedulerMode: p.Scheduler.Mode,
			})
		}
		events = append(events,
			ktrace.Event{TimeUnixNano: fixtureTime(20), ProfileID: p.ID, EventType: "frame_encode", State: p.FirstContact.RelayReadyState, Semantic: ir.SemanticData, Direction: "client_to_server", FrameBytes: 80 + i%17, PayloadBytes: 64, PaddingBytes: p.Padding.MinPaddingBytes, SchedulerMode: p.Scheduler.Mode},
			ktrace.Event{TimeUnixNano: fixtureTime(21), ProfileID: p.ID, EventType: "frame_decode", State: p.FirstContact.RelayReadyState, Semantic: ir.SemanticData, Direction: "server_to_client", FrameBytes: 82 + i%19, PayloadBytes: 64, PaddingBytes: p.Padding.MinPaddingBytes, SchedulerMode: p.Scheduler.Mode},
			ktrace.Event{TimeUnixNano: fixtureTime(22), ProfileID: p.ID, EventType: "invalid_input", Note: p.InvalidInput.FailedAuth},
			ktrace.Event{TimeUnixNano: fixtureTime(23), ProfileID: p.ID, EventType: "malformed_frame", Note: p.InvalidInput.MalformedFrame},
			ktrace.Event{TimeUnixNano: fixtureTime(24), ProfileID: p.ID, EventType: "close", Note: p.InvalidInput.UnknownFirstMessage},
		)
		traces = append(traces, events)
	}
	return traces
}

func fixedProtocolShapeTraces(mode string, profiles []*ir.Profile, noisyPadding bool) [][]ktrace.Event {
	traces := make([][]ktrace.Event, 0, len(profiles))
	for i, p := range profiles {
		padA, padB := 0, 0
		if noisyPadding {
			padA = (i * 7) % 24
			padB = (i * 11) % 24
		}
		traces = append(traces, []ktrace.Event{
			{TimeUnixNano: fixtureTime(0), ProfileID: p.ID, EventType: "first_contact", State: "s0", Semantic: "setup", Direction: "client_to_server", FrameBytes: 36, PayloadBytes: 20, PaddingBytes: 0, SchedulerMode: p.Scheduler.Mode},
			{TimeUnixNano: fixtureTime(1), ProfileID: p.ID, EventType: "first_contact", State: "s1", Semantic: "reply", Direction: "server_to_client", FrameBytes: 32, PayloadBytes: 16, PaddingBytes: 0, SchedulerMode: p.Scheduler.Mode},
			{TimeUnixNano: fixtureTime(2), ProfileID: p.ID, EventType: "first_contact", State: "s2", Semantic: "proof", Direction: "client_to_server", FrameBytes: 48, PayloadBytes: 32, PaddingBytes: 0, SchedulerMode: p.Scheduler.Mode},
			{TimeUnixNano: fixtureTime(3), ProfileID: p.ID, EventType: "frame_encode", State: "s2", Semantic: ir.SemanticData, Direction: "client_to_server", FrameBytes: 96 + padA, PayloadBytes: 64, PaddingBytes: padA, SchedulerMode: p.Scheduler.Mode},
			{TimeUnixNano: fixtureTime(4), ProfileID: p.ID, EventType: "frame_decode", State: "s2", Semantic: ir.SemanticData, Direction: "server_to_client", FrameBytes: 96 + padB, PayloadBytes: 64, PaddingBytes: padB, SchedulerMode: p.Scheduler.Mode},
			{TimeUnixNano: fixtureTime(5), ProfileID: p.ID, EventType: "invalid_input", Note: "fixed_invalid"},
			{TimeUnixNano: fixtureTime(6), ProfileID: p.ID, EventType: "malformed_frame", Note: "fixed_malformed"},
			{TimeUnixNano: fixtureTime(7), ProfileID: p.ID, EventType: "close", Note: "fixed_close"},
		})
	}
	return traces
}

func contactFrameBytes(step ir.FirstContactStep) int {
	return 1 + len(step.WireSymbol) + 2 + step.PayloadSize
}

func fixtureTime(index int) int64 {
	return 1_700_000_000_000_000_000 + int64(index)*1_000_000
}

func cloneProfile(p *ir.Profile) *ir.Profile {
	raw, _ := json.Marshal(p)
	var out ir.Profile
	_ = json.Unmarshal(raw, &out)
	return &out
}

func cloneFrameGrammar(in ir.FrameGrammar) ir.FrameGrammar {
	out := in
	out.HeaderOrder = append([]string(nil), in.HeaderOrder...)
	return out
}

func cloneStates(in []ir.State) []ir.State {
	return append([]ir.State(nil), in...)
}

func cloneTransitions(in []ir.Transition) []ir.Transition {
	return append([]ir.Transition(nil), in...)
}

func cloneFirstContact(in ir.FirstContactSpec) ir.FirstContactSpec {
	out := in
	out.Steps = append([]ir.FirstContactStep(nil), in.Steps...)
	return out
}

func symbolFor(mode, kind string, index, ordinal, length int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d:%d", mode, kind, index, ordinal)))
	raw := hex.EncodeToString(sum[:])
	if length < 2 {
		length = 2
	}
	return "m" + raw[:length-1]
}

func testKeyHex(mode string, seed int64, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("mutant-test-key:%s:%d:%d", mode, seed, index)))
	return hex.EncodeToString(sum[:])
}

func shortMode(mode string) string {
	clean := strings.ReplaceAll(mode, "_", "-")
	if len(clean) <= 20 {
		return clean
	}
	return clean[:20]
}

func knownMode(mode string) bool {
	modes := Modes()
	sort.Strings(modes)
	i := sort.SearchStrings(modes, mode)
	return i < len(modes) && modes[i] == mode
}
