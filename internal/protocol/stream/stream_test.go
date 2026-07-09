package stream

import (
	"bytes"
	"errors"
	"testing"
)

func TestSessionLifecycleCloseAndResetAreIndependent(t *testing.T) {
	session, err := NewSession(Config{
		MaxConcurrentStreams:      2,
		InitialStreamWindowBytes:  64,
		InitialSessionWindowBytes: 128,
		PriorityPolicy:            "fifo",
		ClosePolicy:               "explicit_close",
		ResetPolicy:               "immediate_reset",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := session.OpenStream("interactive")
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.OpenStream("bulk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.OpenStream("bulk"); !errors.Is(err, ErrMaxConcurrentStreams) {
		t.Fatalf("third stream error = %v, want ErrMaxConcurrentStreams", err)
	}
	if _, err := session.WriteData(first, []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	if _, err := session.WriteData(second, []byte("beta")); err != nil {
		t.Fatal(err)
	}
	if got := session.ReadData(first); !bytes.Equal(got, []byte("alpha")) {
		t.Fatalf("first stream read = %q", got)
	}
	if err := session.CloseLocal(first); err != nil {
		t.Fatal(err)
	}
	if session.State(first) != StateHalfClosedLocal {
		t.Fatalf("first stream state = %s", session.State(first))
	}
	if _, err := session.WriteData(second, []byte("continues")); err != nil {
		t.Fatalf("second stream should continue after first close: %v", err)
	}
	if err := session.Reset(second, "test-reset"); err != nil {
		t.Fatal(err)
	}
	if session.State(second) != StateReset {
		t.Fatalf("second stream state = %s", session.State(second))
	}
	if session.State(first) == StateReset {
		t.Fatalf("reset leaked to first stream")
	}
}

func TestFlowControlBackpressureAndWindowUpdate(t *testing.T) {
	session, err := NewSession(Config{
		MaxConcurrentStreams:      1,
		InitialStreamWindowBytes:  4,
		InitialSessionWindowBytes: 8,
		PriorityPolicy:            "fifo",
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := session.OpenStream("interactive")
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.WriteData(id, []byte("12345"))
	if !errors.Is(err, ErrBackpressure) {
		t.Fatalf("oversized write error = %v, want ErrBackpressure", err)
	}
	if !result.Backpressured {
		t.Fatalf("write result did not mark backpressure")
	}
	if err := session.WindowUpdate(id, 8); err != nil {
		t.Fatal(err)
	}
	if _, err := session.WriteData(id, []byte("12345")); err != nil {
		t.Fatalf("write after window update failed: %v", err)
	}
	if session.StreamWindow(id) != 7 {
		t.Fatalf("stream window after write = %d", session.StreamWindow(id))
	}
}

func TestScheduleActiveStreamsHonorsPriorityAndSkipsBlocked(t *testing.T) {
	session, err := NewSession(Config{
		MaxConcurrentStreams:      3,
		InitialStreamWindowBytes:  16,
		InitialSessionWindowBytes: 48,
		PriorityPolicy:            "interactive_first",
	})
	if err != nil {
		t.Fatal(err)
	}
	bulk, _ := session.OpenStream("bulk")
	interactive, _ := session.OpenStream("interactive")
	blocked, _ := session.OpenStream("bulk")
	if _, err := session.WriteData(blocked, bytes.Repeat([]byte("x"), 32)); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("expected blocked stream backpressure, got %v", err)
	}
	order := session.ScheduleActiveStreams()
	if len(order) < 2 {
		t.Fatalf("schedule too short: %v", order)
	}
	if order[0] != interactive {
		t.Fatalf("interactive stream was not first: %v", order)
	}
	for _, id := range order {
		if id == blocked {
			t.Fatalf("blocked stream was scheduled: %v", order)
		}
	}
	if order[1] != bulk {
		t.Fatalf("bulk stream missing after interactive stream: %v", order)
	}
}
