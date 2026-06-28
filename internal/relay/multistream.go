package relay

import (
	"bytes"
	"context"
	"fmt"

	"kurdistan/internal/framing"
	"kurdistan/internal/ir"
	"kurdistan/internal/scheduler"
	kstream "kurdistan/internal/stream"
	ktrace "kurdistan/internal/trace"
)

type MultiStreamRequest struct {
	Label           string
	Priority        string
	Payload         []byte
	ResetAfterOpen  bool
	CloseAfterWrite bool
}

type MultiStreamResult struct {
	OpenedStreams       int
	ClosedStreams       int
	ResetStreams        int
	BackpressureEvents  int
	WindowUpdateEvents  int
	Echoes              map[string][]byte
	StreamLabelsByInput map[string]string
}

func DefaultMultiStreamDemoRequests(n int) []MultiStreamRequest {
	if n <= 0 {
		n = 3
	}
	requests := make([]MultiStreamRequest, 0, n)
	for i := 0; i < n; i++ {
		priority := "bulk"
		if i%2 == 0 {
			priority = "interactive"
		}
		requests = append(requests, MultiStreamRequest{
			Label:    fmt.Sprintf("demo_%02d", i+1),
			Priority: priority,
			Payload:  []byte(fmt.Sprintf("local lab multistream message %02d", i+1)),
		})
	}
	return requests
}

func SimulateMultiStreamEcho(ctx context.Context, p *ir.Profile, requests []MultiStreamRequest) (MultiStreamResult, []ktrace.Event, error) {
	if err := ctx.Err(); err != nil {
		return MultiStreamResult{}, nil, err
	}
	if err := ir.Validate(p); err != nil {
		return MultiStreamResult{}, nil, err
	}
	if len(requests) == 0 {
		requests = DefaultMultiStreamDemoRequests(3)
	}
	session, err := kstream.NewSession(kstream.ConfigFromProfile(p))
	if err != nil {
		return MultiStreamResult{}, nil, err
	}
	result := MultiStreamResult{
		Echoes:              map[string][]byte{},
		StreamLabelsByInput: map[string]string{},
	}
	type opened struct {
		req      MultiStreamRequest
		streamID uint32
		label    string
	}
	openedStreams := make([]opened, 0, len(requests))
	events := []ktrace.Event{}
	for i, req := range requests {
		id, err := session.OpenStream(req.Priority)
		if err != nil {
			return result, events, err
		}
		label := streamTraceLabel(i, id)
		result.OpenedStreams++
		result.StreamLabelsByInput[req.Label] = label
		openedStreams = append(openedStreams, opened{req: req, streamID: id, label: label})
		op := framing.Operation{Semantic: ir.SemanticOpenStream, StreamID: id, Sequence: uint64(i + 1), Priority: req.Priority}
		frameEvents, err := traceOperation(p, op, "client", "client_to_server", label, "open", session.State(id), session.StreamWindow(id), session.SessionWindow(), false)
		if err != nil {
			return result, events, err
		}
		events = append(events, frameEvents...)
	}

	items := make([]scheduler.StreamItem, 0, len(openedStreams))
	for _, opened := range openedStreams {
		items = append(items, scheduler.StreamItem{
			StreamID:     opened.streamID,
			Semantic:     ir.SemanticData,
			PayloadBytes: len(opened.req.Payload),
			Priority:     opened.req.Priority,
			Blocked:      opened.req.ResetAfterOpen,
		})
	}
	_ = scheduler.PlanStreams(p.Stream, p.Scheduler, items)

	for i, opened := range openedStreams {
		if opened.req.ResetAfterOpen {
			if err := session.Reset(opened.streamID, "lab_reset"); err != nil {
				return result, events, err
			}
			result.ResetStreams++
			op := framing.Operation{Semantic: ir.SemanticResetStream, StreamID: opened.streamID, Sequence: uint64(100 + i), Reason: p.Stream.ResetPolicy}
			frameEvents, err := traceOperation(p, op, "client", "client_to_server", opened.label, "reset", session.State(opened.streamID), session.StreamWindow(opened.streamID), session.SessionWindow(), false)
			if err != nil {
				return result, events, err
			}
			events = append(events, frameEvents...)
			continue
		}
		write, err := session.WriteData(opened.streamID, opened.req.Payload)
		if err != nil {
			if err != kstream.ErrBackpressure {
				return result, events, err
			}
			result.BackpressureEvents++
			events = append(events, streamEvent(p, "client", opened.label, "blocked", ir.SemanticData, session.State(opened.streamID), session.StreamWindow(opened.streamID), session.SessionWindow(), opened.req.Priority, true, "flow_control"))
			credit := len(opened.req.Payload) + p.Stream.InitialStreamWindowBytes
			if err := session.WindowUpdate(opened.streamID, credit); err != nil {
				return result, events, err
			}
			result.WindowUpdateEvents++
			op := framing.Operation{Semantic: ir.SemanticWindowUpdate, StreamID: opened.streamID, Sequence: uint64(200 + i), CreditBytes: credit}
			frameEvents, err := traceOperation(p, op, "server", "server_to_client", opened.label, "window_update", session.State(opened.streamID), session.StreamWindow(opened.streamID), session.SessionWindow(), false)
			if err != nil {
				return result, events, err
			}
			events = append(events, frameEvents...)
			write, err = session.WriteData(opened.streamID, opened.req.Payload)
			if err != nil {
				return result, events, err
			}
		}
		op := framing.Operation{Semantic: ir.SemanticData, StreamID: opened.streamID, Sequence: uint64(300 + i), Priority: opened.req.Priority, Payload: opened.req.Payload}
		frameEvents, err := traceOperation(p, op, "client", "client_to_server", opened.label, "data", session.State(opened.streamID), write.StreamWindowRemaining, write.SessionWindowRemaining, false)
		if err != nil {
			return result, events, err
		}
		events = append(events, frameEvents...)
		echo := session.ReadData(opened.streamID)
		if !bytes.Equal(echo, opened.req.Payload) {
			return result, events, fmt.Errorf("stream %s echo mismatch", opened.label)
		}
		result.Echoes[opened.req.Label] = append([]byte(nil), echo...)
		echoOp := framing.Operation{Semantic: ir.SemanticData, StreamID: opened.streamID, Sequence: uint64(400 + i), Priority: opened.req.Priority, Payload: echo}
		echoEvents, err := traceOperation(p, echoOp, "server", "server_to_client", opened.label, "echo", session.State(opened.streamID), session.StreamWindow(opened.streamID), session.SessionWindow(), false)
		if err != nil {
			return result, events, err
		}
		events = append(events, echoEvents...)
		if err := session.CloseLocal(opened.streamID); err != nil {
			return result, events, err
		}
		if err := session.CloseRemote(opened.streamID); err != nil {
			return result, events, err
		}
		result.ClosedStreams++
		closeOp := framing.Operation{Semantic: ir.SemanticClose, StreamID: opened.streamID, Sequence: uint64(500 + i), Reason: p.Stream.ClosePolicy, EndStream: true}
		closeEvents, err := traceOperation(p, closeOp, "client", "client_to_server", opened.label, "close", session.State(opened.streamID), session.StreamWindow(opened.streamID), session.SessionWindow(), false)
		if err != nil {
			return result, events, err
		}
		events = append(events, closeEvents...)
	}
	sessionClose := framing.Operation{Semantic: ir.SemanticSessionClose, Sequence: 900, Reason: "lab_session_complete"}
	closeEvents, err := traceOperation(p, sessionClose, "client", "client_to_server", "session", "session_close", kstream.StateClosed, 0, session.SessionWindow(), false)
	if err != nil {
		return result, events, err
	}
	events = append(events, closeEvents...)
	return result, events, nil
}

func traceOperation(p *ir.Profile, op framing.Operation, role, direction, label, streamEvent string, state kstream.State, streamWindow, sessionWindow int, backpressure bool) ([]ktrace.Event, error) {
	frames, err := framing.EncodeOperation(p, op, p.Seed+int64(op.Sequence)+int64(op.StreamID))
	if err != nil {
		return nil, err
	}
	_, decoded, err := framing.DecodeFrames(p, frames)
	if err != nil {
		return nil, err
	}
	events := make([]ktrace.Event, 0, len(decoded))
	for _, part := range decoded {
		events = append(events, ktrace.Event{
			Role:                role,
			ProfileID:           p.ID,
			EventType:           "stream_frame",
			Semantic:            part.Operation.Semantic,
			WireSymbol:          part.WireSymbol,
			Direction:           direction,
			FrameBytes:          part.FrameBytes,
			PayloadBytes:        part.PayloadBytes,
			PaddingBytes:        part.PaddingBytes,
			SchedulerMode:       p.Scheduler.Mode,
			StreamLabel:         label,
			StreamEvent:         streamEvent,
			StreamState:         string(state),
			StreamWindowBucket:  kstream.WindowBucket(streamWindow),
			SessionWindowBucket: kstream.WindowBucket(sessionWindow),
			PriorityClass:       kstream.PriorityClass(op.Priority),
			CloseResetEvent:     closeResetEvent(op.Semantic),
			Backpressure:        backpressure,
		})
	}
	return events, nil
}

func streamEvent(p *ir.Profile, role, label, eventType, semantic string, state kstream.State, streamWindow, sessionWindow int, priority string, backpressure bool, note string) ktrace.Event {
	return ktrace.Event{
		Role:                role,
		ProfileID:           p.ID,
		EventType:           eventType,
		Semantic:            semantic,
		SchedulerMode:       p.Scheduler.Mode,
		StreamLabel:         label,
		StreamEvent:         eventType,
		StreamState:         string(state),
		StreamWindowBucket:  kstream.WindowBucket(streamWindow),
		SessionWindowBucket: kstream.WindowBucket(sessionWindow),
		PriorityClass:       kstream.PriorityClass(priority),
		Backpressure:        backpressure,
		Note:                note,
	}
}

func streamTraceLabel(index int, id uint32) string {
	return fmt.Sprintf("stream_%02d_bucket_%d", index+1, id%8)
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
