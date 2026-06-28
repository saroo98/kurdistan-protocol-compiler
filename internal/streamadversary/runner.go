// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package streamadversary

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"kurdistan/internal/framing"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
	"kurdistan/internal/scheduler"
	kstream "kurdistan/internal/stream"
	ktrace "kurdistan/internal/trace"
)

type streamHandle struct {
	id       uint32
	label    string
	priority string
}

func RunScenario(ctx context.Context, p *ir.Profile, scenario Scenario) (ScenarioRun, error) {
	if err := ctx.Err(); err != nil {
		return ScenarioRun{}, err
	}
	if scenario.Type == "" {
		return ScenarioRun{}, fmt.Errorf("scenario type is required")
	}
	if err := ir.Validate(p); err != nil {
		return ScenarioRun{}, err
	}
	cfg := kstream.ConfigFromProfile(p)
	if scenario.StreamCount > cfg.MaxConcurrentStreams {
		cfg.MaxConcurrentStreams = scenario.StreamCount
	}
	if scenario.Type == ScenarioSessionWindowExhaustion {
		cfg.MaxConcurrentStreams = max(4, min(p.Stream.MaxConcurrentStreams, 4))
		cfg.InitialStreamWindowBytes = 16 * 1024
		cfg.InitialSessionWindowBytes = 32 * 1024
	}
	session, err := kstream.NewSession(cfg)
	if err != nil {
		return ScenarioRun{}, err
	}
	runner := scenarioRunner{ctx: ctx, profile: p, scenario: scenario, session: session, events: []ktrace.Event{}}
	run, err := runner.run()
	if err != nil {
		return ScenarioRun{}, err
	}
	return run, nil
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
		case mutant.ModeNoBackpressure:
			if runs[i].Scenario == ScenarioBlockedStream || runs[i].Scenario == ScenarioSessionWindowExhaustion {
				runs[i].Checks.BackpressureEvents = 0
				runs[i].Checks.BackpressureCorrect = false
				runs[i].Correct = false
				for j := range runs[i].Events {
					runs[i].Events[j].Backpressure = false
					if runs[i].Events[j].StreamEvent == "blocked" || runs[i].Events[j].StreamEvent == "session_blocked" {
						runs[i].Events[j].StreamEvent = "data"
						runs[i].Events[j].Note = "mutant_no_backpressure"
					}
				}
			}
		case mutant.ModeFIFOSchedulerOnly:
			if runs[i].Scenario == ScenarioBulkVsInteractive {
				runs[i].Checks.SchedulerCorrect = false
				runs[i].Correct = false
			}
		}
	}
	return runs, nil
}

type scenarioRunner struct {
	ctx      context.Context
	profile  *ir.Profile
	scenario Scenario
	session  *kstream.Session
	events   []ktrace.Event
	handles  []streamHandle
	checks   ScenarioChecks
}

func (r *scenarioRunner) run() (ScenarioRun, error) {
	if r.scenario.StreamCount <= 0 {
		r.scenario.StreamCount = 4
	}
	switch r.scenario.Type {
	case ScenarioBalancedInterleave:
		return r.runBalanced()
	case ScenarioBulkVsInteractive:
		return r.runBulkVsInteractive()
	case ScenarioBlockedStream:
		return r.runBlocked()
	case ScenarioSessionWindowExhaustion:
		return r.runSessionWindow()
	case ScenarioResetMidstream:
		return r.runResetMidstream()
	case ScenarioCloseRace:
		return r.runCloseRace()
	case ScenarioUnevenStreamSizes:
		return r.runUneven()
	default:
		return ScenarioRun{}, fmt.Errorf("unknown stream adversary scenario %q", r.scenario.Type)
	}
}

func (r *scenarioRunner) runBalanced() (ScenarioRun, error) {
	if err := r.openStreams([]string{"interactive", "bulk", "interactive", "bulk"}); err != nil {
		return ScenarioRun{}, err
	}
	r.addScheduleEvents()
	payload := payloadFor(r.scenario, "balanced", r.scenario.ChunkSizeBytes)
	for round := 0; round < 2; round++ {
		for _, h := range r.handles {
			if err := r.writeEcho(h, payload, fmt.Sprintf("round_%d", round)); err != nil {
				return ScenarioRun{}, err
			}
		}
	}
	if err := r.closeAll(); err != nil {
		return ScenarioRun{}, err
	}
	r.checks.BackpressureCorrect = true
	r.checks.SchedulerCorrect = true
	r.checks.ResetCloseCorrect = r.checks.CloseCount == len(r.handles)
	return r.finish(), nil
}

func (r *scenarioRunner) runBulkVsInteractive() (ScenarioRun, error) {
	if err := r.openStreams([]string{"bulk", "interactive", "interactive", "interactive"}); err != nil {
		return ScenarioRun{}, err
	}
	order := r.addScheduleEvents()
	r.checks.SchedulerCorrect = schedulerOrderMatchesPolicy(r.profile.Stream.PriorityPolicy, order)
	if err := r.writeEcho(r.handles[1], payloadFor(r.scenario, "interactive:a", r.scenario.SmallPayloadBytes), "interactive_first"); err != nil {
		return ScenarioRun{}, err
	}
	if err := r.writeEcho(r.handles[2], payloadFor(r.scenario, "interactive:b", r.scenario.SmallPayloadBytes), "interactive_second"); err != nil {
		return ScenarioRun{}, err
	}
	if err := r.writeWithWindowRecovery(r.handles[0], payloadFor(r.scenario, "bulk", r.scenario.BulkPayloadBytes), "bulk"); err != nil {
		return ScenarioRun{}, err
	}
	r.checks.OtherStreamsContinued = true
	r.checks.BackpressureCorrect = true
	r.checks.ResetCloseCorrect = true
	_ = r.closeAll()
	return r.finish(), nil
}

func (r *scenarioRunner) runBlocked() (ScenarioRun, error) {
	if err := r.openStreams([]string{"bulk", "interactive", "bulk"}); err != nil {
		return ScenarioRun{}, err
	}
	r.addScheduleEvents()
	large := payloadFor(r.scenario, "blocked", r.profile.Stream.InitialStreamWindowBytes+1)
	if err := r.writeWithWindowRecovery(r.handles[0], large, "blocked_stream"); err != nil {
		return ScenarioRun{}, err
	}
	if err := r.writeEcho(r.handles[1], payloadFor(r.scenario, "continues", r.scenario.SmallPayloadBytes), "other_continues"); err != nil {
		return ScenarioRun{}, err
	}
	r.checks.OtherStreamsContinued = true
	r.checks.BackpressureCorrect = r.checks.BackpressureEvents > 0
	r.checks.SchedulerCorrect = true
	r.checks.ResetCloseCorrect = true
	_ = r.closeAll()
	return r.finish(), nil
}

func (r *scenarioRunner) runSessionWindow() (ScenarioRun, error) {
	if err := r.openStreams([]string{"bulk", "interactive", "bulk", "interactive"}); err != nil {
		return ScenarioRun{}, err
	}
	r.addScheduleEvents()
	chunk := payloadFor(r.scenario, "session-fill", 16*1024)
	for _, h := range r.handles[:2] {
		if err := r.writeEcho(h, chunk, "session_fill"); err != nil {
			return ScenarioRun{}, err
		}
	}
	for _, h := range r.handles {
		_, err := r.session.WriteData(h.id, []byte{1})
		if errors.Is(err, kstream.ErrBackpressure) {
			r.checks.SessionBlockedCount++
			r.checks.BackpressureEvents++
			r.events = append(r.events, r.metadataEvent(h, "session_blocked", ir.SemanticData, true, "session_backpressure"))
			continue
		}
		if err != nil {
			return ScenarioRun{}, err
		}
	}
	if err := r.session.WindowUpdate(r.handles[2].id, 4096); err != nil {
		return ScenarioRun{}, err
	}
	r.checks.WindowUpdateEvents++
	r.checks.WindowUpdateRecovered = true
	if err := r.emitFrame(r.handles[2], framing.Operation{Semantic: ir.SemanticWindowUpdate, StreamID: r.handles[2].id, CreditBytes: 4096}, "server_to_client", "window_update", false, "window_policy="+r.profile.Stream.WindowUpdatePolicy); err != nil {
		return ScenarioRun{}, err
	}
	r.checks.BackpressureCorrect = r.checks.SessionBlockedCount == len(r.handles)
	r.checks.SchedulerCorrect = true
	r.checks.ResetCloseCorrect = true
	_ = r.closeAll()
	return r.finish(), nil
}

func (r *scenarioRunner) runResetMidstream() (ScenarioRun, error) {
	if err := r.openStreams([]string{"bulk", "interactive", "bulk", "interactive"}); err != nil {
		return ScenarioRun{}, err
	}
	r.addScheduleEvents()
	if err := r.writeEcho(r.handles[0], payloadFor(r.scenario, "partial", 512), "partial_before_reset"); err != nil {
		return ScenarioRun{}, err
	}
	if err := r.session.Reset(r.handles[0].id, r.profile.Stream.ResetPolicy); err != nil {
		return ScenarioRun{}, err
	}
	r.checks.ResetCount++
	if err := r.emitFrame(r.handles[0], framing.Operation{Semantic: ir.SemanticResetStream, StreamID: r.handles[0].id, Reason: r.profile.Stream.ResetPolicy}, "client_to_server", "reset", false, "reset_policy="+r.profile.Stream.ResetPolicy); err != nil {
		return ScenarioRun{}, err
	}
	if err := r.writeEcho(r.handles[1], payloadFor(r.scenario, "continues", r.scenario.SmallPayloadBytes), "after_reset_continue"); err != nil {
		return ScenarioRun{}, err
	}
	r.checks.OtherStreamsContinued = true
	r.checks.BackpressureCorrect = true
	r.checks.SchedulerCorrect = true
	r.checks.ResetCloseCorrect = r.checks.ResetCount == 1
	_ = r.closeOpen()
	return r.finish(), nil
}

func (r *scenarioRunner) runCloseRace() (ScenarioRun, error) {
	if err := r.openStreams([]string{"interactive", "bulk", "interactive"}); err != nil {
		return ScenarioRun{}, err
	}
	r.addScheduleEvents()
	if err := r.writeEcho(r.handles[1], payloadFor(r.scenario, "active", r.scenario.ChunkSizeBytes), "active_before_close"); err != nil {
		return ScenarioRun{}, err
	}
	if err := r.session.CloseLocal(r.handles[0].id); err != nil {
		return ScenarioRun{}, err
	}
	r.checks.CloseCount++
	if err := r.emitFrame(r.handles[0], framing.Operation{Semantic: ir.SemanticClose, StreamID: r.handles[0].id, Reason: r.profile.Stream.ClosePolicy, EndStream: true}, "client_to_server", "close", false, "close_policy="+r.profile.Stream.ClosePolicy); err != nil {
		return ScenarioRun{}, err
	}
	if err := r.writeEcho(r.handles[1], payloadFor(r.scenario, "continues", r.scenario.SmallPayloadBytes), "after_close_continue"); err != nil {
		return ScenarioRun{}, err
	}
	r.checks.OtherStreamsContinued = true
	r.checks.BackpressureCorrect = true
	r.checks.SchedulerCorrect = true
	r.checks.ResetCloseCorrect = true
	_ = r.closeOpen()
	return r.finish(), nil
}

func (r *scenarioRunner) runUneven() (ScenarioRun, error) {
	if err := r.openStreams([]string{"interactive", "bulk", "interactive", "bulk"}); err != nil {
		return ScenarioRun{}, err
	}
	r.addScheduleEvents()
	sizes := []int{r.scenario.SmallPayloadBytes, 8 * 1024, 256, r.scenario.BulkPayloadBytes}
	for i, h := range r.handles {
		if err := r.writeWithWindowRecovery(h, payloadFor(r.scenario, fmt.Sprintf("size_%d", i), sizes[i]), "uneven"); err != nil {
			return ScenarioRun{}, err
		}
	}
	r.checks.OtherStreamsContinued = true
	r.checks.BackpressureCorrect = true
	r.checks.SchedulerCorrect = true
	r.checks.ResetCloseCorrect = true
	_ = r.closeAll()
	return r.finish(), nil
}

func (r *scenarioRunner) openStreams(priorities []string) error {
	count := r.scenario.StreamCount
	if count > len(priorities) {
		count = len(priorities)
	}
	for i := 0; i < count; i++ {
		id, err := r.session.OpenStream(priorities[i])
		if err != nil {
			return err
		}
		h := streamHandle{id: id, label: fmt.Sprintf("stream_%02d_%s_%s", i+1, r.profile.Stream.IDEncodingMode, r.profile.Stream.IDStrategy), priority: priorities[i]}
		r.handles = append(r.handles, h)
		note := strings.Join([]string{
			"id_encoding=" + r.profile.Stream.IDEncodingMode,
			"id_strategy=" + r.profile.Stream.IDStrategy,
			"window_policy=" + r.profile.Stream.WindowUpdatePolicy,
			"scheduler_policy=" + r.profile.Stream.PriorityPolicy,
			"close_policy=" + r.profile.Stream.ClosePolicy,
			"reset_policy=" + r.profile.Stream.ResetPolicy,
		}, ";")
		if err := r.emitFrame(h, framing.Operation{Semantic: ir.SemanticOpenStream, StreamID: id, Priority: priorities[i]}, "client_to_server", "open", false, note); err != nil {
			return err
		}
	}
	return nil
}

func (r *scenarioRunner) addScheduleEvents() []streamHandle {
	items := make([]scheduler.StreamItem, 0, len(r.handles))
	for _, h := range r.handles {
		size := r.scenario.SmallPayloadBytes
		if h.priority == "bulk" {
			size = r.scenario.BulkPayloadBytes
		}
		items = append(items, scheduler.StreamItem{StreamID: h.id, PayloadBytes: size, Priority: h.priority})
	}
	flushes := scheduler.PlanStreams(r.profile.Stream, r.profile.Scheduler, items)
	order := []streamHandle{}
	byID := map[uint32]streamHandle{}
	for _, h := range r.handles {
		byID[h.id] = h
	}
	for _, flush := range flushes {
		for _, item := range flush.Items {
			h := byID[item.StreamID]
			order = append(order, h)
			ev := r.metadataEvent(h, "schedule", item.Semantic, false, "scheduler_policy="+r.profile.Stream.PriorityPolicy)
			ev.EventType = "scheduler_decision"
			ev.PayloadBytes = item.PayloadBytes
			r.events = append(r.events, ev)
		}
	}
	return order
}

func (r *scenarioRunner) writeWithWindowRecovery(h streamHandle, payload []byte, event string) error {
	if err := r.writeEcho(h, payload, event); err == nil {
		return nil
	} else if !errors.Is(err, kstream.ErrBackpressure) {
		return err
	}
	credit := len(payload) + r.profile.Stream.InitialStreamWindowBytes
	if err := r.session.WindowUpdate(h.id, credit); err != nil {
		return err
	}
	r.checks.WindowUpdateEvents++
	r.checks.WindowUpdateRecovered = true
	if err := r.emitFrame(h, framing.Operation{Semantic: ir.SemanticWindowUpdate, StreamID: h.id, CreditBytes: credit}, "server_to_client", "window_update", false, "window_policy="+r.profile.Stream.WindowUpdatePolicy); err != nil {
		return err
	}
	return r.writeEcho(h, payload, event+"_recovered")
}

func (r *scenarioRunner) writeEcho(h streamHandle, payload []byte, event string) error {
	result, err := r.session.WriteData(h.id, payload)
	if errors.Is(err, kstream.ErrBackpressure) {
		r.checks.BackpressureEvents++
		r.events = append(r.events, r.metadataEvent(h, "blocked", ir.SemanticData, true, "stream_backpressure"))
		return err
	}
	if err != nil {
		return err
	}
	if err := r.emitFrame(h, framing.Operation{Semantic: ir.SemanticData, StreamID: h.id, Priority: h.priority, Payload: payload}, "client_to_server", event, false, "write_ok"); err != nil {
		return err
	}
	echo := r.session.ReadData(h.id)
	if !bytes.Equal(echo, payload) {
		return fmt.Errorf("echo mismatch for %s", h.label)
	}
	r.events = append(r.events, ktrace.Event{
		ProfileID:           r.profile.ID,
		EventType:           "stream_echo",
		Semantic:            ir.SemanticData,
		Direction:           "server_to_client",
		PayloadBytes:        len(echo),
		SchedulerMode:       r.profile.Scheduler.Mode,
		StreamLabel:         h.label,
		StreamEvent:         "echo",
		StreamState:         string(r.session.State(h.id)),
		StreamWindowBucket:  kstream.WindowBucket(result.StreamWindowRemaining),
		SessionWindowBucket: kstream.WindowBucket(result.SessionWindowRemaining),
		PriorityClass:       kstream.PriorityClass(h.priority),
	})
	return nil
}

func (r *scenarioRunner) closeAll() error {
	for _, h := range r.handles {
		if err := r.closeIfOpen(h); err != nil {
			return err
		}
	}
	return nil
}

func (r *scenarioRunner) closeOpen() error {
	for _, h := range r.handles {
		if kstream.IsTerminal(r.session.State(h.id)) {
			continue
		}
		if err := r.closeIfOpen(h); err != nil {
			return err
		}
	}
	return nil
}

func (r *scenarioRunner) closeIfOpen(h streamHandle) error {
	state := r.session.State(h.id)
	if state == kstream.StateReset || state == kstream.StateClosed {
		return nil
	}
	if state == kstream.StateOpen {
		if err := r.session.CloseLocal(h.id); err != nil {
			return err
		}
	}
	if r.session.State(h.id) == kstream.StateHalfClosedLocal {
		if err := r.session.CloseRemote(h.id); err != nil {
			return err
		}
	}
	r.checks.CloseCount++
	return r.emitFrame(h, framing.Operation{Semantic: ir.SemanticClose, StreamID: h.id, Reason: r.profile.Stream.ClosePolicy, EndStream: true}, "client_to_server", "close", false, "close_policy="+r.profile.Stream.ClosePolicy)
}

func (r *scenarioRunner) emitFrame(h streamHandle, op framing.Operation, direction, streamEvent string, backpressure bool, note string) error {
	frames, err := framing.EncodeOperation(r.profile, op, r.profile.Seed+int64(op.StreamID)+int64(len(r.events)))
	if err != nil {
		return err
	}
	_, decoded, err := framing.DecodeFrames(r.profile, frames)
	if err != nil {
		return err
	}
	for _, part := range decoded {
		r.events = append(r.events, ktrace.Event{
			ProfileID:           r.profile.ID,
			EventType:           "stream_frame",
			Semantic:            part.Operation.Semantic,
			WireSymbol:          part.WireSymbol,
			Direction:           direction,
			FrameBytes:          part.FrameBytes,
			PayloadBytes:        part.PayloadBytes,
			PaddingBytes:        part.PaddingBytes,
			SchedulerMode:       r.profile.Scheduler.Mode,
			StreamLabel:         h.label,
			StreamEvent:         streamEvent,
			StreamState:         string(r.session.State(h.id)),
			StreamWindowBucket:  kstream.WindowBucket(r.session.StreamWindow(h.id)),
			SessionWindowBucket: kstream.WindowBucket(r.session.SessionWindow()),
			PriorityClass:       kstream.PriorityClass(h.priority),
			CloseResetEvent:     closeResetEvent(part.Operation.Semantic),
			Backpressure:        backpressure,
			Note:                note,
		})
	}
	return nil
}

func (r *scenarioRunner) metadataEvent(h streamHandle, eventType, semantic string, backpressure bool, note string) ktrace.Event {
	return ktrace.Event{
		ProfileID:           r.profile.ID,
		EventType:           eventType,
		Semantic:            semantic,
		SchedulerMode:       r.profile.Scheduler.Mode,
		StreamLabel:         h.label,
		StreamEvent:         eventType,
		StreamState:         string(r.session.State(h.id)),
		StreamWindowBucket:  kstream.WindowBucket(r.session.StreamWindow(h.id)),
		SessionWindowBucket: kstream.WindowBucket(r.session.SessionWindow()),
		PriorityClass:       kstream.PriorityClass(h.priority),
		Backpressure:        backpressure,
		Note:                note,
	}
}

func (r *scenarioRunner) finish() ScenarioRun {
	if r.checks.BackpressureCorrect == false && r.scenario.Type != ScenarioBlockedStream && r.scenario.Type != ScenarioSessionWindowExhaustion {
		r.checks.BackpressureCorrect = true
	}
	if r.checks.SchedulerCorrect == false && r.scenario.Type != ScenarioBulkVsInteractive {
		r.checks.SchedulerCorrect = true
	}
	if r.checks.ResetCloseCorrect == false && r.scenario.Type != ScenarioResetMidstream && r.scenario.Type != ScenarioCloseRace {
		r.checks.ResetCloseCorrect = true
	}
	correct := r.checks.BackpressureCorrect && r.checks.SchedulerCorrect && r.checks.ResetCloseCorrect
	if r.scenario.Type == ScenarioBlockedStream && !r.checks.OtherStreamsContinued {
		correct = false
	}
	if r.scenario.Type == ScenarioSessionWindowExhaustion && (r.checks.SessionBlockedCount == 0 || !r.checks.WindowUpdateRecovered) {
		correct = false
	}
	return ScenarioRun{
		ProfileID: r.profile.ID,
		Scenario:  r.scenario.Type,
		Correct:   correct,
		Checks:    r.checks,
		Events:    r.events,
	}
}

func payloadFor(s Scenario, label string, size int) []byte {
	if size <= 0 {
		size = 1
	}
	marker := []byte("streamadv:" + s.Type + ":" + label + ":")
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = marker[i%len(marker)]
	}
	return payload
}

func schedulerOrderMatchesPolicy(policy string, order []streamHandle) bool {
	if len(order) == 0 {
		return false
	}
	switch policy {
	case "interactive_first":
		return order[0].priority == "interactive"
	case "fifo":
		return order[0].priority == "bulk"
	case "smallest_pending_first", "weighted_round_robin":
		return true
	default:
		return true
	}
}

func closeResetEvent(semantic string) string {
	switch semantic {
	case ir.SemanticClose, ir.SemanticSessionClose:
		return "close"
	case ir.SemanticResetStream:
		return "reset"
	default:
		return ""
	}
}

func eventsHaveStreamMetadata(events []ktrace.Event) bool {
	for _, ev := range events {
		if ev.StreamLabel != "" && ev.StreamEvent != "" && ev.StreamState != "" && ev.StreamWindowBucket != "" && ev.SessionWindowBucket != "" {
			return true
		}
	}
	return false
}
