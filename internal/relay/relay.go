package relay

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"kurdistan/internal/auth"
	"kurdistan/internal/framing"
	"kurdistan/internal/fsm"
	"kurdistan/internal/ir"
	ktrace "kurdistan/internal/trace"
)

const streamID uint32 = 1

func ServeEcho(ctx context.Context, ln net.Listener, logger *log.Logger) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			if logger != nil {
				logger.Printf("echo connection opened from loopback=%v", isLoopbackConn(conn.RemoteAddr()))
			}
			n, _ := io.Copy(conn, conn)
			if logger != nil {
				logger.Printf("echo connection closed bytes=%d", n)
			}
		}()
	}
}

func Serve(ctx context.Context, ln net.Listener, target string, p *ir.Profile, rec *ktrace.Recorder, logger *log.Logger) error {
	if err := ir.Validate(p); err != nil {
		return err
	}
	if !IsLoopbackAddress(ln.Addr().String()) || !IsLoopbackAddress(target) {
		return fmt.Errorf("server listen and target must be loopback addresses")
	}
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				wg.Wait()
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			if logger != nil {
				logger.Printf("server connection opened from loopback=%v", isLoopbackConn(conn.RemoteAddr()))
			}
			if err := HandleServerConn(ctx, conn, target, p, rec); err != nil && logger != nil {
				logger.Printf("server connection closed with controlled error: %v", err)
			}
		}()
	}
}

func HandleServerConn(ctx context.Context, conn net.Conn, target string, p *ir.Profile, rec *ktrace.Recorder) error {
	deadline := time.Now().Add(time.Duration(p.Limits.MaxSessionMillis) * time.Millisecond)
	_ = conn.SetDeadline(deadline)
	reader := bufio.NewReader(conn)
	if err := ServerHandshake(reader, conn, p, rec); err != nil {
		return err
	}
	op, parts, err := framing.ReadOperation(reader, p)
	if err != nil {
		return err
	}
	for _, part := range parts {
		_ = rec.Record(ktrace.Event{Role: ir.RoleServer, ProfileID: p.ID, EventType: "frame_decode", Semantic: part.Operation.Semantic, WireSymbol: part.WireSymbol, Direction: "client_to_server", FrameBytes: part.FrameBytes, PayloadBytes: part.PayloadBytes, PaddingBytes: part.PaddingBytes, SchedulerMode: p.Scheduler.Mode})
	}
	if op.Semantic != ir.SemanticData {
		return fmt.Errorf("expected data operation, got %q", op.Semantic)
	}
	dialer := net.Dialer{}
	targetConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("target unavailable: %w", err)
	}
	defer targetConn.Close()
	_ = targetConn.SetDeadline(deadline)
	if _, err := targetConn.Write(op.Payload); err != nil {
		return err
	}
	echo := make([]byte, len(op.Payload))
	if _, err := io.ReadFull(targetConn, echo); err != nil {
		return err
	}
	writtenParts, err := framing.WriteOperation(conn, p, framing.Operation{Semantic: ir.SemanticData, StreamID: streamID, Payload: echo}, p.Seed+2)
	if err != nil {
		return err
	}
	for _, part := range writtenParts {
		_ = rec.Record(ktrace.Event{Role: ir.RoleServer, ProfileID: p.ID, EventType: "frame_encode", Semantic: part.Operation.Semantic, WireSymbol: part.WireSymbol, Direction: "server_to_client", FrameBytes: part.FrameBytes, PayloadBytes: part.PayloadBytes, PaddingBytes: part.PaddingBytes, SchedulerMode: p.Scheduler.Mode})
	}
	return nil
}

func ClientRoundTrip(ctx context.Context, p *ir.Profile, server string, payload []byte, rec *ktrace.Recorder) ([]byte, error) {
	if err := ir.Validate(p); err != nil {
		return nil, err
	}
	if !IsLoopbackAddress(server) {
		return nil, fmt.Errorf("client server address must be loopback")
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(p.Limits.MaxSessionMillis) * time.Millisecond))
	reader := bufio.NewReader(conn)
	if err := ClientHandshake(reader, conn, p, rec); err != nil {
		return nil, err
	}
	writtenParts, err := framing.WriteOperation(conn, p, framing.Operation{Semantic: ir.SemanticData, StreamID: streamID, Payload: payload}, p.Seed+1)
	if err != nil {
		return nil, err
	}
	for _, part := range writtenParts {
		_ = rec.Record(ktrace.Event{Role: ir.RoleClient, ProfileID: p.ID, EventType: "frame_encode", Semantic: part.Operation.Semantic, WireSymbol: part.WireSymbol, Direction: "client_to_server", FrameBytes: part.FrameBytes, PayloadBytes: part.PayloadBytes, PaddingBytes: part.PaddingBytes, SchedulerMode: p.Scheduler.Mode})
	}
	op, parts, err := framing.ReadOperation(reader, p)
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		_ = rec.Record(ktrace.Event{Role: ir.RoleClient, ProfileID: p.ID, EventType: "frame_decode", Semantic: part.Operation.Semantic, WireSymbol: part.WireSymbol, Direction: "server_to_client", FrameBytes: part.FrameBytes, PayloadBytes: part.PayloadBytes, PaddingBytes: part.PaddingBytes, SchedulerMode: p.Scheduler.Mode})
	}
	return op.Payload, nil
}

func ClientHandshake(r *bufio.Reader, w io.Writer, p *ir.Profile, rec *ktrace.Recorder) error {
	clientFSM, err := fsm.New(p, ir.RoleClient)
	if err != nil {
		return err
	}
	serverShadow, err := fsm.New(p, ir.RoleServer)
	if err != nil {
		return err
	}
	var transcript [][]byte
	nonce := deterministicNonce(p)
	for i, step := range p.FirstContact.Steps {
		if step.Role == ir.RoleClient {
			payload, err := contactPayload(p, step, transcript, nonce, i)
			if err != nil {
				return err
			}
			packet, err := encodeContact(step, payload)
			if err != nil {
				return err
			}
			if _, err := w.Write(packet); err != nil {
				return err
			}
			if err := clientFSM.Apply(step.Message); err != nil {
				return err
			}
			_ = rec.Record(ktrace.Event{Role: ir.RoleClient, ProfileID: p.ID, EventType: "first_contact", State: step.ToState, Semantic: step.Message, WireSymbol: step.WireSymbol, Direction: step.Direction, FrameBytes: len(packet), PayloadBytes: len(payload), SchedulerMode: p.Scheduler.Mode})
			if !step.Proof {
				transcript = append(transcript, packet)
			}
			serverShadowState(serverShadow, step.ToState)
			continue
		}
		packet, payload, err := readContact(r, step)
		if err != nil {
			return err
		}
		if err := serverShadow.Apply(step.Message); err != nil {
			return err
		}
		transcript = append(transcript, packet)
		_ = rec.Record(ktrace.Event{Role: ir.RoleClient, ProfileID: p.ID, EventType: "first_contact", State: step.ToState, Semantic: step.Message, WireSymbol: step.WireSymbol, Direction: step.Direction, FrameBytes: len(packet), PayloadBytes: len(payload), SchedulerMode: p.Scheduler.Mode})
		clientSetState(clientFSM, step.ToState)
	}
	if !clientFSM.RelayReady() {
		return fmt.Errorf("client did not reach relay-ready")
	}
	return nil
}

func ServerHandshake(r *bufio.Reader, w io.Writer, p *ir.Profile, rec *ktrace.Recorder) error {
	serverFSM, err := fsm.New(p, ir.RoleServer)
	if err != nil {
		return err
	}
	clientShadow, err := fsm.New(p, ir.RoleClient)
	if err != nil {
		return err
	}
	var transcript [][]byte
	var nonce []byte
	replay := auth.NewReplayCache()
	for i, step := range p.FirstContact.Steps {
		if step.Role == ir.RoleClient {
			packet, payload, err := readContact(r, step)
			if err != nil {
				return err
			}
			if i == 0 {
				if len(payload) < p.Auth.NonceBytes {
					return fmt.Errorf("missing nonce")
				}
				nonce = append([]byte(nil), payload[:p.Auth.NonceBytes]...)
				if !replay.Accept(nonce) {
					return fmt.Errorf("replay nonce rejected")
				}
			}
			if step.Proof {
				if !auth.Verify(p, transcript, nonce, payload) {
					return fmt.Errorf("auth proof rejected")
				}
			}
			if err := clientShadow.Apply(step.Message); err != nil {
				return err
			}
			_ = rec.Record(ktrace.Event{Role: ir.RoleServer, ProfileID: p.ID, EventType: "first_contact", State: step.ToState, Semantic: step.Message, WireSymbol: step.WireSymbol, Direction: step.Direction, FrameBytes: len(packet), PayloadBytes: len(payload), SchedulerMode: p.Scheduler.Mode})
			if !step.Proof {
				transcript = append(transcript, packet)
			}
			serverSetState(serverFSM, step.ToState)
			continue
		}
		payload, err := contactPayload(p, step, transcript, nonce, i)
		if err != nil {
			return err
		}
		packet, err := encodeContact(step, payload)
		if err != nil {
			return err
		}
		if _, err := w.Write(packet); err != nil {
			return err
		}
		if err := serverFSM.Apply(step.Message); err != nil {
			return err
		}
		transcript = append(transcript, packet)
		_ = rec.Record(ktrace.Event{Role: ir.RoleServer, ProfileID: p.ID, EventType: "first_contact", State: step.ToState, Semantic: step.Message, WireSymbol: step.WireSymbol, Direction: step.Direction, FrameBytes: len(packet), PayloadBytes: len(payload), SchedulerMode: p.Scheduler.Mode})
		clientSetState(clientShadow, step.ToState)
	}
	if !serverFSM.RelayReady() {
		return fmt.Errorf("server did not reach relay-ready")
	}
	return nil
}

func encodeContact(step ir.FirstContactStep, payload []byte) ([]byte, error) {
	if len(step.WireSymbol) > 255 || len(payload) > 0xffff {
		return nil, fmt.Errorf("first-contact packet too large")
	}
	out := []byte{byte(len(step.WireSymbol))}
	out = append(out, []byte(step.WireSymbol)...)
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(len(payload)))
	out = append(out, b[:]...)
	out = append(out, payload...)
	return out, nil
}

func readContact(r *bufio.Reader, step ir.FirstContactStep) ([]byte, []byte, error) {
	symLenByte, err := r.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	symLen := int(symLenByte)
	sym := make([]byte, symLen)
	if _, err := io.ReadFull(r, sym); err != nil {
		return nil, nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, nil, err
	}
	payloadLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, nil, err
	}
	packet := []byte{symLenByte}
	packet = append(packet, sym...)
	packet = append(packet, lenBuf[:]...)
	packet = append(packet, payload...)
	if string(sym) != step.WireSymbol {
		return nil, nil, fmt.Errorf("first-contact profile mismatch")
	}
	return packet, payload, nil
}

func contactPayload(p *ir.Profile, step ir.FirstContactStep, transcript [][]byte, nonce []byte, index int) ([]byte, error) {
	if step.Proof {
		return auth.Proof(p, transcript, nonce)
	}
	payload := make([]byte, step.PayloadSize)
	copy(payload, []byte(step.WireSymbol))
	for i := range payload {
		payload[i] ^= byte((int(p.Seed) + index + i) & 0xff)
	}
	if index == 0 && step.Role == ir.RoleClient {
		copy(payload, nonce)
	}
	return payload, nil
}

func deterministicNonce(p *ir.Profile) []byte {
	nonce := make([]byte, p.Auth.NonceBytes)
	for i := range nonce {
		nonce[i] = byte((p.Seed>>uint((i%8)*8) + int64(i*17)) & 0xff)
	}
	return nonce
}

func IsLoopbackAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackConn(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	return IsLoopbackAddress(addr.String())
}

func serverShadowState(i *fsm.Interpreter, state string) { serverSetState(i, state) }
func serverSetState(i *fsm.Interpreter, state string)    { forceState(i, state) }
func clientSetState(i *fsm.Interpreter, state string)    { forceState(i, state) }

func forceState(i *fsm.Interpreter, state string) {
	// The first-contact transcript is a shared path; the peer-side interpreter
	// is advanced to the state reached by the message just observed.
	_ = i.SetStateForPeer(state)
}
