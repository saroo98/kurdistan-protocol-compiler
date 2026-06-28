// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyrelay

import (
	"context"
	"fmt"
	"sort"

	"kurdistan/internal/framing"
	"kurdistan/internal/ir"
	"kurdistan/internal/proxysem"
	kstream "kurdistan/internal/stream"
	ktrace "kurdistan/internal/trace"
)

type IntentRequest struct {
	Intent      proxysem.RelayIntent
	Request     proxysem.TargetRequest
	Label       string
	Scenario    string
	RequestSize int
}

type Result struct {
	OpenedStreams         int            `json:"opened_streams"`
	ClosedStreams         int            `json:"closed_streams"`
	ResetStreams          int            `json:"reset_streams"`
	TargetErrors          int            `json:"target_errors"`
	BackpressureEvents    int            `json:"backpressure_events"`
	WindowUpdateEvents    int            `json:"window_update_events"`
	ResponseBytes         int            `json:"response_bytes"`
	TargetClasses         map[string]int `json:"target_classes"`
	OtherStreamsContinued bool           `json:"other_streams_continued"`
}

func Simulate(ctx context.Context, p *ir.Profile, requests []IntentRequest) (Result, []ktrace.Event, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, nil, err
	}
	if err := ir.Validate(p); err != nil {
		return Result{}, nil, err
	}
	if len(requests) == 0 {
		requests = DefaultRequests(p, 3)
	}
	if len(requests) > p.Stream.MaxConcurrentStreams {
		return Result{}, nil, fmt.Errorf("proxy intent count exceeds max concurrent streams")
	}
	session, err := kstream.NewSession(kstream.ConfigFromProfile(p))
	if err != nil {
		return Result{}, nil, err
	}
	result := Result{TargetClasses: map[string]int{}}
	events := []ktrace.Event{}
	type opened struct {
		request  IntentRequest
		streamID uint32
		label    string
	}
	openedStreams := make([]opened, 0, len(requests))
	for i, req := range requests {
		if req.Intent.MaxRequestBytes == 0 {
			req.Intent.MaxRequestBytes = p.ProxySemantics.MaxRequestBytes
		}
		if req.Intent.MaxResponseBytes == 0 {
			req.Intent.MaxResponseBytes = p.ProxySemantics.MaxResponseBytes
		}
		if req.Intent.RelayIntentID == 0 {
			req.Intent.RelayIntentID = uint64(i + 1)
		}
		if req.RequestSize == 0 {
			req.RequestSize = req.Request.Bytes
		}
		if req.RequestSize == 0 {
			req.RequestSize = 256
		}
		priority := string(req.Intent.PriorityClass)
		if priority == "" {
			priority = "bulk"
		}
		streamID, err := session.OpenStream(priority)
		if err != nil {
			return result, events, err
		}
		req.Intent.StreamID = uint64(streamID)
		req.Request.StreamID = uint64(streamID)
		req.Request.Bytes = req.RequestSize
		if req.Request.Class == "" {
			req.Request.Class = req.Intent.RequestClass
		}
		if err := proxysem.ValidateRelayIntent(req.Intent); err != nil {
			return result, events, err
		}
		label := req.Label
		if label == "" {
			label = fmt.Sprintf("proxy_stream_%02d_bucket_%d", i+1, streamID%8)
		}
		result.OpenedStreams++
		result.TargetClasses[req.Intent.Target.Class]++
		openedStreams = append(openedStreams, opened{request: req, streamID: streamID, label: label})
		if err := appendOperation(p, &events, req, label, session, framing.Operation{
			Semantic:      ir.SemanticOpenStream,
			StreamID:      streamID,
			RelayIntentID: req.Intent.RelayIntentID,
			Priority:      priority,
		}, "client", "client_to_server", "open_stream", false); err != nil {
			return result, events, err
		}
		if err := appendOperation(p, &events, req, label, session, framing.Operation{
			Semantic:      ir.SemanticOpenRelay,
			StreamID:      streamID,
			RelayIntentID: req.Intent.RelayIntentID,
			TargetClass:   req.Intent.Target.Class,
			TargetVariant: req.Intent.Target.Variant,
			RequestClass:  string(req.Intent.RequestClass),
			ResponseMode:  string(req.Intent.ResponseMode),
			Priority:      priority,
		}, "client", "client_to_server", "open_relay", false); err != nil {
			return result, events, err
		}
		if err := appendOperation(p, &events, req, label, session, framing.Operation{
			Semantic:      ir.SemanticTargetDescriptor,
			StreamID:      streamID,
			RelayIntentID: req.Intent.RelayIntentID,
			TargetClass:   req.Intent.Target.Class,
			TargetVariant: req.Intent.Target.Variant,
			RequestClass:  string(req.Intent.RequestClass),
			ResponseMode:  string(req.Intent.ResponseMode),
			MetadataClass: p.ProxySemantics.TargetDescriptorEncoding,
		}, "client", "client_to_server", "target_descriptor", false); err != nil {
			return result, events, err
		}
	}
	for index, item := range openedStreams {
		req := item.request
		if err := writeData(p, &result, &events, session, req, item.label, item.streamID, req.RequestSize, "target_data", false); err != nil {
			return result, events, err
		}
		chunks, targetResult, err := proxysem.RunIntent(req.Intent, req.Request, p.Seed+int64(index))
		if err != nil {
			return result, events, err
		}
		if targetResult.ErrorCode != "" && !targetResult.Reset {
			result.TargetErrors++
			if err := appendOperation(p, &events, req, item.label, session, framing.Operation{
				Semantic:        ir.SemanticTargetError,
				StreamID:        item.streamID,
				RelayIntentID:   req.Intent.RelayIntentID,
				TargetClass:     req.Intent.Target.Class,
				TargetErrorCode: targetResult.ErrorCode,
			}, "server", "server_to_client", "target_error", false); err != nil {
				return result, events, err
			}
			_ = closeStream(p, &result, &events, session, req, item.label, item.streamID, "target_error_close")
			continue
		}
		for _, chunk := range chunks {
			if chunk.Backpressure {
				result.BackpressureEvents++
				events = append(events, metadataEvent(p, req, item.label, session, item.streamID, "target_backpressure", true))
			}
			if err := writeResponseChunk(p, &result, &events, session, req, item.label, item.streamID, chunk); err != nil {
				return result, events, err
			}
			if chunk.Reset {
				if err := resetStream(p, &result, &events, session, req, item.label, item.streamID, targetResult.ErrorCode); err != nil {
					return result, events, err
				}
				break
			}
		}
		if targetResult.Reset {
			continue
		}
		if err := closeStream(p, &result, &events, session, req, item.label, item.streamID, "target_complete"); err != nil {
			return result, events, err
		}
	}
	result.OtherStreamsContinued = continuedAfterErrorOrReset(events)
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].StreamLabel == events[j].StreamLabel {
			return events[i].EventType < events[j].EventType
		}
		return events[i].StreamLabel < events[j].StreamLabel
	})
	return result, events, nil
}

func DefaultRequests(p *ir.Profile, count int) []IntentRequest {
	if count <= 0 {
		count = 3
	}
	if p != nil && p.Stream.MaxConcurrentStreams > 0 && count > p.Stream.MaxConcurrentStreams {
		count = p.Stream.MaxConcurrentStreams
	}
	classes := []string{proxysem.TargetEcho, proxysem.TargetFixedResponse, proxysem.TargetChunkedResponse, proxysem.TargetSlowResponse}
	requests := make([]IntentRequest, 0, count)
	for i := 0; i < count; i++ {
		class := classes[i%len(classes)]
		requests = append(requests, IntentRequest{
			Label:       fmt.Sprintf("proxy_demo_%02d", i+1),
			RequestSize: 256 + i*64,
			Intent: proxysem.RelayIntent{
				Target:           proxysem.TargetDescriptor{Class: class, Parameters: map[string]string{"bytes": fmt.Sprint(1024 + i*512), "chunks": "2"}},
				RequestClass:     proxysem.RequestInteractive,
				PriorityClass:    proxysem.PriorityInteractive,
				ResponseMode:     proxysem.ResponseChunked,
				MaxRequestBytes:  p.ProxySemantics.MaxRequestBytes,
				MaxResponseBytes: p.ProxySemantics.MaxResponseBytes,
			},
		})
	}
	return requests
}

func writeData(p *ir.Profile, result *Result, events *[]ktrace.Event, session *kstream.Session, req IntentRequest, label string, streamID uint32, bytes int, event string, response bool) error {
	payload := make([]byte, bytes)
	write, err := session.WriteData(streamID, payload)
	if err != nil {
		if err != kstream.ErrBackpressure {
			return err
		}
		result.BackpressureEvents++
		*events = append(*events, metadataEvent(p, req, label, session, streamID, "flow_backpressure", true))
		credit := bytes + p.Stream.InitialStreamWindowBytes
		if err := session.WindowUpdate(streamID, credit); err != nil {
			return err
		}
		result.WindowUpdateEvents++
		if err := appendOperation(p, events, req, label, session, framing.Operation{
			Semantic:      ir.SemanticWindowUpdate,
			StreamID:      streamID,
			RelayIntentID: req.Intent.RelayIntentID,
			CreditBytes:   credit,
		}, "server", "server_to_client", "window_update", false); err != nil {
			return err
		}
		write, err = session.WriteData(streamID, payload)
		if err != nil {
			return err
		}
	}
	semantic := ir.SemanticTargetData
	direction := "client_to_server"
	role := "client"
	op := framing.Operation{
		Semantic:         semantic,
		StreamID:         streamID,
		RelayIntentID:    req.Intent.RelayIntentID,
		TargetClass:      req.Intent.Target.Class,
		RequestClass:     string(req.Intent.RequestClass),
		ResponseMode:     string(req.Intent.ResponseMode),
		PayloadByteCount: bytes,
		Payload:          payload,
	}
	if response {
		op.Semantic = ir.SemanticTargetResponse
		op.ResponseByteCount = bytes
		op.PayloadByteCount = 0
		direction = "server_to_client"
		role = "server"
		result.ResponseBytes += bytes
	}
	_ = write
	return appendOperation(p, events, req, label, session, op, role, direction, event, false)
}

func writeResponseChunk(p *ir.Profile, result *Result, events *[]ktrace.Event, session *kstream.Session, req IntentRequest, label string, streamID uint32, chunk proxysem.TargetChunk) error {
	payload := make([]byte, chunk.Bytes)
	write, err := session.WriteData(streamID, payload)
	if err != nil {
		if err != kstream.ErrBackpressure {
			return err
		}
		result.BackpressureEvents++
		*events = append(*events, metadataEvent(p, req, label, session, streamID, "response_backpressure", true))
		credit := chunk.Bytes + p.Stream.InitialStreamWindowBytes
		if err := session.WindowUpdate(streamID, credit); err != nil {
			return err
		}
		result.WindowUpdateEvents++
		if err := appendOperation(p, events, req, label, session, framing.Operation{
			Semantic:      ir.SemanticWindowUpdate,
			StreamID:      streamID,
			RelayIntentID: req.Intent.RelayIntentID,
			CreditBytes:   credit,
		}, "server", "server_to_client", "window_update", false); err != nil {
			return err
		}
		write, err = session.WriteData(streamID, payload)
		if err != nil {
			return err
		}
	}
	_ = write
	result.ResponseBytes += chunk.Bytes
	return appendOperation(p, events, req, label, session, framing.Operation{
		Semantic:           ir.SemanticTargetResponse,
		StreamID:           streamID,
		RelayIntentID:      req.Intent.RelayIntentID,
		TargetClass:        req.Intent.Target.Class,
		RequestClass:       string(req.Intent.RequestClass),
		ResponseMode:       string(req.Intent.ResponseMode),
		ResponseChunkIndex: chunk.ChunkIndex,
		ResponseByteCount:  chunk.Bytes,
		MetadataClass:      chunk.MetadataClass,
		Payload:            payload,
	}, "server", "server_to_client", "target_response", chunk.Backpressure)
}

func closeStream(p *ir.Profile, result *Result, events *[]ktrace.Event, session *kstream.Session, req IntentRequest, label string, streamID uint32, reason string) error {
	if session.State(streamID) == kstream.StateOpen {
		if err := session.CloseLocal(streamID); err != nil {
			return err
		}
	}
	if session.State(streamID) == kstream.StateHalfClosedLocal {
		if err := session.CloseRemote(streamID); err != nil {
			return err
		}
	}
	result.ClosedStreams++
	return appendOperation(p, events, req, label, session, framing.Operation{
		Semantic:          ir.SemanticTargetClose,
		StreamID:          streamID,
		RelayIntentID:     req.Intent.RelayIntentID,
		TargetClass:       req.Intent.Target.Class,
		TargetCloseReason: reason,
		EndStream:         true,
	}, "server", "server_to_client", "target_close", false)
}

func resetStream(p *ir.Profile, result *Result, events *[]ktrace.Event, session *kstream.Session, req IntentRequest, label string, streamID uint32, reason string) error {
	if reason == "" {
		reason = p.ProxySemantics.TargetResetPolicy
	}
	if err := session.Reset(streamID, reason); err != nil {
		return err
	}
	result.ResetStreams++
	return appendOperation(p, events, req, label, session, framing.Operation{
		Semantic:          ir.SemanticTargetReset,
		StreamID:          streamID,
		RelayIntentID:     req.Intent.RelayIntentID,
		TargetClass:       req.Intent.Target.Class,
		TargetResetReason: reason,
	}, "server", "server_to_client", "target_reset", false)
}

func appendOperation(p *ir.Profile, events *[]ktrace.Event, req IntentRequest, label string, session *kstream.Session, op framing.Operation, role, direction, targetEvent string, backpressure bool) error {
	frames, err := framing.EncodeOperation(p, op, p.Seed+int64(op.RelayIntentID)+int64(op.StreamID)+int64(len(*events)))
	if err != nil {
		return err
	}
	_, decoded, err := framing.DecodeFrames(p, frames)
	if err != nil {
		return err
	}
	for _, part := range decoded {
		*events = append(*events, ktrace.Event{
			Role:                role,
			ProfileID:           p.ID,
			EventType:           "proxy_frame",
			Semantic:            part.Operation.Semantic,
			WireSymbol:          part.WireSymbol,
			Direction:           direction,
			FrameBytes:          part.FrameBytes,
			PayloadBytes:        part.PayloadBytes,
			PaddingBytes:        part.PaddingBytes,
			SchedulerMode:       p.Scheduler.Mode,
			StreamLabel:         label,
			StreamEvent:         targetEvent,
			StreamState:         string(session.State(op.StreamID)),
			StreamWindowBucket:  kstream.WindowBucket(session.StreamWindow(op.StreamID)),
			SessionWindowBucket: kstream.WindowBucket(session.SessionWindow()),
			PriorityClass:       string(req.Intent.PriorityClass),
			CloseResetEvent:     closeResetEvent(op.Semantic),
			Backpressure:        backpressure,
			TargetClassBucket:   req.Intent.Target.Class,
			RequestClassBucket:  string(req.Intent.RequestClass),
			ResponseModeBucket:  string(req.Intent.ResponseMode),
			TargetEventType:     targetEvent,
			TargetErrorBucket:   part.Operation.TargetErrorCode,
			TargetReset:         part.Operation.Semantic == ir.SemanticTargetReset,
			TargetClose:         part.Operation.Semantic == ir.SemanticTargetClose,
			ResponseChunkBucket: proxysem.ResponseBucket(part.Operation.ResponseByteCount),
			TargetBackpressure:  backpressure,
			ProxyScenario:       req.Scenario,
			Note:                stringsJoinPolicy(p),
		})
	}
	return nil
}

func metadataEvent(p *ir.Profile, req IntentRequest, label string, session *kstream.Session, streamID uint32, event string, backpressure bool) ktrace.Event {
	return ktrace.Event{
		Role:                "server",
		ProfileID:           p.ID,
		EventType:           "proxy_metadata",
		Semantic:            ir.SemanticTargetMetadata,
		SchedulerMode:       p.Scheduler.Mode,
		StreamLabel:         label,
		StreamEvent:         event,
		StreamState:         string(session.State(streamID)),
		StreamWindowBucket:  kstream.WindowBucket(session.StreamWindow(streamID)),
		SessionWindowBucket: kstream.WindowBucket(session.SessionWindow()),
		PriorityClass:       string(req.Intent.PriorityClass),
		Backpressure:        backpressure,
		TargetClassBucket:   req.Intent.Target.Class,
		RequestClassBucket:  string(req.Intent.RequestClass),
		ResponseModeBucket:  string(req.Intent.ResponseMode),
		TargetEventType:     event,
		TargetBackpressure:  backpressure,
		ProxyScenario:       req.Scenario,
		Note:                stringsJoinPolicy(p),
	}
}

func closeResetEvent(semantic string) string {
	switch semantic {
	case ir.SemanticTargetClose, ir.SemanticClose, ir.SemanticSessionClose:
		return "close"
	case ir.SemanticTargetReset, ir.SemanticResetStream:
		return "reset"
	default:
		return ""
	}
}

func continuedAfterErrorOrReset(events []ktrace.Event) bool {
	seenFault := false
	for _, ev := range events {
		if ev.TargetErrorBucket != "" || ev.TargetReset {
			seenFault = true
			continue
		}
		if seenFault && ev.TargetEventType == "target_response" {
			return true
		}
	}
	return !seenFault
}

func stringsJoinPolicy(p *ir.Profile) string {
	return "relay_intent_encoding=" + p.ProxySemantics.RelayIntentEncoding +
		";descriptor_encoding=" + p.ProxySemantics.TargetDescriptorEncoding +
		";response_mode_encoding=" + p.ProxySemantics.ResponseModeEncoding +
		";target_error_policy=" + p.ProxySemantics.TargetErrorPolicy +
		";target_close_policy=" + p.ProxySemantics.TargetClosePolicy +
		";target_reset_policy=" + p.ProxySemantics.TargetResetPolicy +
		";target_metadata_policy=" + p.ProxySemantics.TargetMetadataPolicy +
		";target_class_mapping=" + p.ProxySemantics.TargetClassMapping
}
