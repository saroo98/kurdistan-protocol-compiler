package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"kurdistan/internal/compiler"
)

func TestSimulateMultiStreamEchoInterleavesClosesAndResets(t *testing.T) {
	p, err := compiler.Generate(300)
	if err != nil {
		t.Fatal(err)
	}
	p.GenerationHash = ""
	p.Stream.MaxConcurrentStreams = 4
	p.Stream.InitialStreamWindowBytes = 16 * 1024
	p.Stream.InitialSessionWindowBytes = 64 * 1024
	requests := []MultiStreamRequest{
		{Label: "a", Priority: "interactive", Payload: []byte("alpha")},
		{Label: "b", Priority: "bulk", Payload: []byte("beta")},
		{Label: "c", Priority: "bulk", Payload: []byte("gamma"), ResetAfterOpen: true},
		{Label: "d", Priority: "interactive", Payload: []byte("delta")},
	}
	result, events, err := SimulateMultiStreamEcho(context.Background(), p, requests)
	if err != nil {
		t.Fatal(err)
	}
	if result.OpenedStreams != 4 || result.ResetStreams != 1 || result.ClosedStreams != 3 {
		t.Fatalf("unexpected result: %+v", result)
	}
	for _, req := range requests {
		if req.ResetAfterOpen {
			if _, ok := result.Echoes[req.Label]; ok {
				t.Fatalf("reset stream %q produced echo", req.Label)
			}
			continue
		}
		if !bytes.Equal(result.Echoes[req.Label], req.Payload) {
			t.Fatalf("echo mismatch for %q", req.Label)
		}
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"alpha", "beta", "gamma", "delta"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("trace contains payload %q: %s", forbidden, raw)
		}
	}
	var sawBackpressureMetadata bool
	for _, ev := range events {
		if ev.StreamLabel == "" || ev.StreamEvent == "" || ev.StreamState == "" {
			continue
		}
		if ev.StreamWindowBucket != "" && ev.SessionWindowBucket != "" {
			sawBackpressureMetadata = true
		}
	}
	if !sawBackpressureMetadata {
		t.Fatalf("trace did not include safe stream/window metadata")
	}
}

func TestSimulateMultiStreamEchoEnforcesMaxConcurrentStreams(t *testing.T) {
	p, err := compiler.Generate(301)
	if err != nil {
		t.Fatal(err)
	}
	p.GenerationHash = ""
	p.Stream.MaxConcurrentStreams = 2
	requests := []MultiStreamRequest{
		{Label: "a", Payload: []byte("a")},
		{Label: "b", Payload: []byte("b")},
		{Label: "c", Payload: []byte("c")},
	}
	if _, _, err := SimulateMultiStreamEcho(context.Background(), p, requests); err == nil {
		t.Fatalf("expected max concurrent stream error")
	}
}
