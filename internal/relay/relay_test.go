package relay

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	ktrace "kurdistan/internal/trace"
)

func TestLocalEchoRoundTrip(t *testing.T) {
	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()
	p, _ := compiler.Generate(100)
	serverAddr, stopServer := startServer(t, p, echoAddr, nil)
	defer stopServer()
	got, err := ClientRoundTrip(context.Background(), p, serverAddr, []byte("hello kurdistan"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello kurdistan" {
		t.Fatal("echo mismatch")
	}
}

func TestOneKiBRoundTrip(t *testing.T) {
	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()
	p, _ := compiler.Generate(101)
	serverAddr, stopServer := startServer(t, p, echoAddr, nil)
	defer stopServer()
	payload := bytes.Repeat([]byte("a"), 1024)
	got, err := ClientRoundTrip(context.Background(), p, serverAddr, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("1 KiB echo mismatch")
	}
}

func TestOneMiBRoundTrip(t *testing.T) {
	echoAddr, stopEcho := startEcho(t)
	defer stopEcho()
	p, _ := compiler.Generate(102)
	serverAddr, stopServer := startServer(t, p, echoAddr, nil)
	defer stopServer()
	payload := bytes.Repeat([]byte("b"), 1024*1024)
	got, err := ClientRoundTrip(context.Background(), p, serverAddr, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("1 MiB echo mismatch")
	}
}

func TestTargetUnavailableReturnsControlledError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := ln.Addr().String()
	_ = ln.Close()
	p, _ := compiler.Generate(103)
	serverAddr, stopServer := startServer(t, p, target, nil)
	defer stopServer()
	_, err = ClientRoundTrip(context.Background(), p, serverAddr, []byte("x"), nil)
	if err == nil {
		t.Fatal("expected target unavailable error")
	}
}

func TestPayloadContentsNeverAppearInLogs(t *testing.T) {
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ServeEcho(ctx, ln, log.New(&logs, "", 0)) }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("secret-payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	cancel()
	time.Sleep(10 * time.Millisecond)
	if strings.Contains(logs.String(), string(payload)) {
		t.Fatal("payload appeared in logs")
	}
}

func TestEndToEndTraceComparison(t *testing.T) {
	traceA := &bytes.Buffer{}
	traceB := &bytes.Buffer{}
	runProfile := func(seed int64, w *bytes.Buffer) {
		echoAddr, stopEcho := startEcho(t)
		defer stopEcho()
		p, _ := compiler.Generate(seed)
		rec := ktrace.NewRecorder(w)
		serverAddr, stopServer := startServer(t, p, echoAddr, rec)
		defer stopServer()
		got, err := ClientRoundTrip(context.Background(), p, serverAddr, []byte("hello kurdistan"), rec)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "hello kurdistan" {
			t.Fatal("echo mismatch")
		}
	}
	runProfile(200, traceA)
	runProfile(201, traceB)
	eventsA, err := ktrace.DecodeJSONL(bytes.NewReader(traceA.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	eventsB, err := ktrace.DecodeJSONL(bytes.NewReader(traceB.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	report := ktrace.CompareEvents(eventsA, eventsB)
	if !report.MeaningfullyDifferent {
		t.Fatalf("expected traces to differ, got %s", report.Conclusion)
	}
}

func startEcho(t *testing.T) (string, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ServeEcho(ctx, ln, nil) }()
	return ln.Addr().String(), cancel
}

func startServer(t *testing.T, p *ir.Profile, target string, rec *ktrace.Recorder) (string, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = Serve(ctx, ln, target, p, rec, nil) }()
	return ln.Addr().String(), cancel
}
