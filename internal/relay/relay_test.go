package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	ktrace "kurdistan/internal/observe/trace"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
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

type failAcceptListener struct {
	addr    net.Addr
	accepts int
}

func (listener *failAcceptListener) Accept() (net.Conn, error) {
	listener.accepts++
	return nil, errors.New("Accept must not be called")
}
func (listener *failAcceptListener) Close() error   { return nil }
func (listener *failAcceptListener) Addr() net.Addr { return listener.addr }

type literalTestAddr string

func (addr literalTestAddr) Network() string { return "tcp" }
func (addr literalTestAddr) String() string  { return string(addr) }

func TestLiteralLoopbackNoDNSMatrix(t *testing.T) {
	accepted := []string{"127.0.0.1:1", "127.255.2.3:65535", "[::1]:443"}
	for _, address := range accepted {
		if !IsLoopbackAddress(address) {
			t.Fatalf("literal loopback rejected: %q", address)
		}
	}
	rejected := []string{
		"localhost:80", "example.com:80", "0.0.0.0:80", "[::]:80", "8.8.8.8:53", "[2001:db8::1]:443",
		"127.0.0.1", "127.0.0.1:http", "[::1%lo0]:80", "[::ffff:127.0.0.1]:80", "bad", ":80", "127.0.0.1:0", "127.0.0.1:65536",
	}
	for _, address := range rejected {
		if IsLoopbackAddress(address) {
			t.Fatalf("non-literal-loopback accepted: %q", address)
		}
	}
}

func TestZeroIORejectedClientAndTargetV1(t *testing.T) {
	p, _ := compiler.Generate(301)
	oldDial := legacyDialContext
	defer func() { legacyDialContext = oldDial }()
	dials := 0
	legacyDialContext = func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, errors.New("dial must not be called")
	}
	for _, address := range []string{"localhost:80", "0.0.0.0:1", "example.com:443"} {
		if _, err := ClientRoundTrip(context.Background(), p, address, []byte("x"), nil); err == nil {
			t.Fatalf("client address %q accepted", address)
		}
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if err := HandleServerConn(context.Background(), left, "localhost:80", p, nil); err == nil {
		t.Fatal("invalid target accepted")
	}
	if dials != 0 {
		t.Fatalf("rejected inputs performed %d dials", dials)
	}
}

func TestZeroIORejectedServeBeforeAcceptV1(t *testing.T) {
	p, _ := compiler.Generate(302)
	for _, test := range []struct{ listen, target string }{
		{"0.0.0.0:1", "127.0.0.1:1"},
		{"127.0.0.1:1", "localhost:1"},
	} {
		listener := &failAcceptListener{addr: literalTestAddr(test.listen)}
		if err := Serve(context.Background(), listener, test.target, p, nil, nil); err == nil {
			t.Fatalf("invalid server inputs accepted: %+v", test)
		}
		if listener.accepts != 0 {
			t.Fatalf("invalid server inputs called Accept %d times", listener.accepts)
		}
	}
}

func TestNoDNSOrListenSourceV1(t *testing.T) {
	raw, err := os.ReadFile("relay.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, forbidden := range []string{"net.Listen(", "LookupHost(", "LookupIP(", "ResolveTCPAddr("} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("legacy relay source contains forbidden network resolver/listener %q", forbidden)
		}
	}
}
