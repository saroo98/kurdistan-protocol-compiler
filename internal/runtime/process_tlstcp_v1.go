// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/wirev1"
	"kurdistan/internal/transport/tlstcp"
)

var ErrProcessSessionV1 = errors.New("process-separated Kurd session rejected")

const maxProcessTLSTCPIdleTimeoutV1 = 24 * time.Hour

// ProcessTLSTCPDuplexCarrierV1 adapts the message-oriented strict TLS carrier
// to the bounded length-prefixed stream contract used by PacketPumpV1. It does
// not decrypt, reinterpret, or retain application payloads.
type ProcessTLSTCPDuplexCarrierV1 struct {
	ctx       context.Context
	carrier   *tlstcp.Conn
	ioTimeout time.Duration
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	closed    atomic.Bool
	readBuf   []byte
	writeBuf  []byte
}

func NewProcessTLSTCPDuplexCarrierV1(ctx context.Context, carrier *tlstcp.Conn, idleTimeout time.Duration) (*ProcessTLSTCPDuplexCarrierV1, error) {
	if ctx == nil || carrier == nil || idleTimeout <= 0 || idleTimeout > maxProcessTLSTCPIdleTimeoutV1 {
		return nil, ErrProcessSessionV1
	}
	return &ProcessTLSTCPDuplexCarrierV1{ctx: ctx, carrier: carrier, ioTimeout: 2 * idleTimeout}, nil
}

func (adapter *ProcessTLSTCPDuplexCarrierV1) Read(output []byte) (int, error) {
	if adapter == nil || adapter.carrier == nil || adapter.closed.Load() || len(output) == 0 {
		return 0, ErrProcessSessionV1
	}
	adapter.readMu.Lock()
	defer adapter.readMu.Unlock()
	if len(adapter.readBuf) == 0 {
		operationContext, cancel := context.WithTimeout(adapter.ctx, adapter.ioTimeout)
		frame, err := adapter.carrier.Receive(operationContext)
		cancel()
		if err != nil {
			return 0, err
		}
		encoded, err := wirev1.Encode(frame)
		clear(frame.Payload)
		if err != nil {
			return 0, ErrProcessSessionV1
		}
		adapter.readBuf = make([]byte, 4+len(encoded))
		binary.BigEndian.PutUint32(adapter.readBuf[:4], uint32(len(encoded)))
		copy(adapter.readBuf[4:], encoded)
		clear(encoded)
	}
	count := copy(output, adapter.readBuf)
	copy(adapter.readBuf, adapter.readBuf[count:])
	clear(adapter.readBuf[len(adapter.readBuf)-count:])
	adapter.readBuf = adapter.readBuf[:len(adapter.readBuf)-count]
	return count, nil
}

func (adapter *ProcessTLSTCPDuplexCarrierV1) Write(input []byte) (int, error) {
	if adapter == nil || adapter.carrier == nil || adapter.closed.Load() || len(input) == 0 {
		return 0, ErrProcessSessionV1
	}
	adapter.writeMu.Lock()
	defer adapter.writeMu.Unlock()
	if len(adapter.writeBuf)+len(input) > 4+wirev1.HeaderBytes+wirev1.MaxPayloadBytes {
		return 0, ErrProcessSessionV1
	}
	adapter.writeBuf = append(adapter.writeBuf, input...)
	for len(adapter.writeBuf) >= 4 {
		length := uint64(binary.BigEndian.Uint32(adapter.writeBuf[:4]))
		if length == 0 || length > wirev1.HeaderBytes+wirev1.MaxPayloadBytes {
			adapter.clearWriteV1()
			return 0, ErrProcessSessionV1
		}
		if uint64(len(adapter.writeBuf)-4) < length {
			break
		}
		end := 4 + int(length)
		frame, err := wirev1.Decode(adapter.writeBuf[4:end])
		if err != nil {
			adapter.clearWriteV1()
			return 0, ErrProcessSessionV1
		}
		operationContext, cancel := context.WithTimeout(adapter.ctx, adapter.ioTimeout)
		err = adapter.carrier.Send(operationContext, frame)
		cancel()
		if err != nil {
			clear(frame.Payload)
			adapter.clearWriteV1()
			return 0, err
		}
		clear(frame.Payload)
		copy(adapter.writeBuf, adapter.writeBuf[end:])
		clear(adapter.writeBuf[len(adapter.writeBuf)-end:])
		adapter.writeBuf = adapter.writeBuf[:len(adapter.writeBuf)-end]
	}
	return len(input), nil
}

func (adapter *ProcessTLSTCPDuplexCarrierV1) Close() error {
	if adapter == nil {
		return nil
	}
	var err error
	adapter.closeOnce.Do(func() {
		adapter.closed.Store(true)
		err = adapter.carrier.Close()
		adapter.readMu.Lock()
		clear(adapter.readBuf)
		adapter.readBuf = nil
		adapter.readMu.Unlock()
		adapter.writeMu.Lock()
		adapter.clearWriteV1()
		adapter.writeMu.Unlock()
	})
	return err
}

func (adapter *ProcessTLSTCPDuplexCarrierV1) clearWriteV1() {
	clear(adapter.writeBuf)
	adapter.writeBuf = nil
}

var _ io.ReadWriteCloser = (*ProcessTLSTCPDuplexCarrierV1)(nil)

// ProcessSessionSinkV1 is the relay's bounded downstream delivery boundary.
type ProcessSessionSinkV1 interface {
	Deliver(context.Context, []byte) error
}

// RunProcessClientDuplexOperationV1 proves one profile-shaped operation over
// independently owned TLS, handshake, envelope, replay, and framing state.
// Long-lived TUN ownership composes the same endpoint through PacketPumpV1.
func RunProcessClientDuplexOperationV1(ctx context.Context, carrier *tlstcp.Conn, handshake *ProcessWireClientHandshakeV1, planDigest [32]byte, program liveprogram.ProgramV1, operation framing.Operation) error {
	if ctx == nil || carrier == nil || handshake == nil || planDigest == ([32]byte{}) || liveprogram.ValidateV1(program) != nil || len(operation.Payload) == 0 {
		return ErrProcessSessionV1
	}
	endpoint, err := EstablishProcessClientDuplexEndpointV1(ctx, carrier, handshake, planDigest, program)
	if err != nil {
		return err
	}
	defer endpoint.Abort()
	records, err := endpoint.SealOperation(operation, int64(operation.Sequence))
	if err != nil || len(records) != 1 || sendEncodedProcessFrameV1(ctx, carrier, records[0]) != nil {
		clearFrameSetV1(records)
		return failClientDuplexSessionV1(handshake, carrier, endpoint)
	}
	clearFrameSetV1(records)
	closeRecord, err := endpoint.SealClose(CloseCodeTerminalV1)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, closeRecord) != nil {
		clear(closeRecord)
		return failClientDuplexSessionV1(handshake, carrier, endpoint)
	}
	clear(closeRecord)
	return nil
}

// EstablishProcessClientDuplexEndpointV1 completes the authenticated Kurd
// handshake and carrier-binding exchange for a long-lived client packet pump.
// On failure it closes all partially established state. On success the caller
// owns both the returned endpoint and carrier.
func EstablishProcessClientDuplexEndpointV1(ctx context.Context, carrier *tlstcp.Conn, handshake *ProcessWireClientHandshakeV1, planDigest [32]byte, program liveprogram.ProgramV1) (*ProcessClientDuplexEndpointV1, error) {
	if ctx == nil || carrier == nil || handshake == nil || planDigest == ([32]byte{}) || liveprogram.ValidateV1(program) != nil {
		return nil, ErrProcessSessionV1
	}
	clientHello, err := handshake.Start()
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, clientHello) != nil {
		return nil, failClientDuplexSessionV1(handshake, carrier, nil)
	}
	serverHello, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return nil, failClientDuplexSessionV1(handshake, carrier, nil)
	}
	clientFinish, err := handshake.AcceptServerHello(serverHello)
	clear(serverHello)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, clientFinish) != nil {
		return nil, failClientDuplexSessionV1(handshake, carrier, nil)
	}
	serverFinish, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return nil, failClientDuplexSessionV1(handshake, carrier, nil)
	}
	result, err := handshake.AcceptServerFinish(serverFinish)
	clear(serverFinish)
	if err != nil {
		return nil, failClientDuplexSessionV1(handshake, carrier, nil)
	}
	endpoint, err := NewProcessClientDuplexEndpointV1(result, planDigest, program)
	if err != nil {
		result.Close()
		return nil, failClientDuplexSessionV1(handshake, carrier, nil)
	}
	binding, err := carrier.CarrierBinding()
	if err != nil {
		return nil, failClientDuplexSessionV1(handshake, carrier, endpoint)
	}
	bind, err := endpoint.ProfileBind(binding)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, bind) != nil {
		clear(bind)
		return nil, failClientDuplexSessionV1(handshake, carrier, endpoint)
	}
	clear(bind)
	ready, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil || endpoint.AcceptEngineReady(ready) != nil {
		clear(ready)
		return nil, failClientDuplexSessionV1(handshake, carrier, endpoint)
	}
	clear(ready)
	return endpoint, nil
}

func RunProcessRelayDuplexOperationV1(ctx context.Context, carrier *tlstcp.Conn, handshake *ProcessWireRelayHandshakeV1, planDigest [32]byte, program liveprogram.ProgramV1, sink ProcessSessionSinkV1) error {
	if ctx == nil || carrier == nil || handshake == nil || planDigest == ([32]byte{}) || liveprogram.ValidateV1(program) != nil || sink == nil {
		return ErrProcessSessionV1
	}
	clientHello, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return failRelayDuplexSessionV1(handshake, carrier, nil)
	}
	serverHello, err := handshake.AcceptClientHello(clientHello)
	clear(clientHello)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, serverHello) != nil {
		clear(serverHello)
		return failRelayDuplexSessionV1(handshake, carrier, nil)
	}
	clear(serverHello)
	clientFinish, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return failRelayDuplexSessionV1(handshake, carrier, nil)
	}
	serverFinish, result, err := handshake.AcceptClientFinish(clientFinish)
	clear(clientFinish)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, serverFinish) != nil {
		clear(serverFinish)
		if result != nil {
			result.Close()
		}
		return failRelayDuplexSessionV1(handshake, carrier, nil)
	}
	clear(serverFinish)
	endpoint, err := NewProcessRelayDuplexEndpointV1(result, planDigest, program)
	if err != nil {
		result.Close()
		return failRelayDuplexSessionV1(handshake, carrier, nil)
	}
	defer endpoint.Abort()
	binding, err := carrier.CarrierBinding()
	if err != nil {
		return failRelayDuplexSessionV1(handshake, carrier, endpoint)
	}
	bind, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return failRelayDuplexSessionV1(handshake, carrier, endpoint)
	}
	ready, err := endpoint.AcceptProfileBind(bind, binding)
	clear(bind)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, ready) != nil {
		clear(ready)
		return failRelayDuplexSessionV1(handshake, carrier, endpoint)
	}
	clear(ready)
	encoded, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return failRelayDuplexSessionV1(handshake, carrier, endpoint)
	}
	pending, err := endpoint.OpenFrame(encoded)
	clear(encoded)
	if err != nil || pending == nil {
		return failRelayDuplexSessionV1(handshake, carrier, endpoint)
	}
	operation := pending.Operation()
	if operation.Semantic != "data" || sink.Deliver(ctx, operation.Payload) != nil {
		clear(operation.Payload)
		_ = pending.Discard()
		return failRelayDuplexSessionV1(handshake, carrier, endpoint)
	}
	clear(operation.Payload)
	if err := pending.Commit(); err != nil {
		return failRelayDuplexSessionV1(handshake, carrier, endpoint)
	}
	closeRecord, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return failRelayDuplexSessionV1(handshake, carrier, endpoint)
	}
	_, err = endpoint.OpenFrame(closeRecord)
	clear(closeRecord)
	if !errors.Is(err, ErrLinkClosed) {
		return failRelayDuplexSessionV1(handshake, carrier, endpoint)
	}
	return nil
}

func failClientDuplexSessionV1(handshake *ProcessWireClientHandshakeV1, carrier *tlstcp.Conn, endpoint *ProcessClientDuplexEndpointV1) error {
	handshake.Close()
	if endpoint != nil {
		endpoint.Abort()
	}
	_ = carrier.Close()
	return ErrProcessSessionV1
}

func failRelayDuplexSessionV1(handshake *ProcessWireRelayHandshakeV1, carrier *tlstcp.Conn, endpoint *ProcessRelayDuplexEndpointV1) error {
	handshake.Close()
	if endpoint != nil {
		endpoint.Abort()
	}
	_ = carrier.Close()
	return ErrProcessSessionV1
}

// RunProcessClientSessionV1 executes one complete client-side session over a
// role-local TLS carrier. The relay handshake, replay state, record codec, and
// delivery authority are never present in this call.
func RunProcessClientSessionV1(ctx context.Context, carrier *tlstcp.Conn, handshake *ProcessWireClientHandshakeV1, planDigest [32]byte, streamSlot uint16, payload []byte) error {
	if ctx == nil || carrier == nil || handshake == nil || planDigest == ([32]byte{}) ||
		streamSlot == 0 || streamSlot == processControlSlotV1 || len(payload) == 0 {
		return ErrProcessSessionV1
	}
	fail := func(endpoint *ProcessClientRecordEndpointV1) error {
		handshake.Close()
		if endpoint != nil {
			endpoint.Abort()
		}
		_ = carrier.Close()
		return ErrProcessSessionV1
	}
	clientHello, err := handshake.Start()
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, clientHello) != nil {
		return fail(nil)
	}
	serverHello, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return fail(nil)
	}
	clientFinish, err := handshake.AcceptServerHello(serverHello)
	clear(serverHello)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, clientFinish) != nil {
		return fail(nil)
	}
	serverFinish, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return fail(nil)
	}
	handshakeResult, err := handshake.AcceptServerFinish(serverFinish)
	clear(serverFinish)
	if err != nil {
		return fail(nil)
	}
	endpoint, err := NewProcessClientRecordEndpointV1(handshakeResult, planDigest)
	if err != nil {
		handshakeResult.Close()
		return fail(nil)
	}
	defer endpoint.Abort()
	binding, err := carrier.CarrierBinding()
	if err != nil {
		return fail(endpoint)
	}
	bind, err := endpoint.ProfileBind(binding)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, bind) != nil {
		clear(bind)
		return fail(endpoint)
	}
	clear(bind)
	ready, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil || endpoint.AcceptEngineReady(ready) != nil {
		clear(ready)
		return fail(endpoint)
	}
	clear(ready)
	record, err := endpoint.Seal(streamSlot, payload)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, record) != nil {
		clear(record)
		return fail(endpoint)
	}
	clear(record)
	ack, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil || endpoint.AcceptAck(ack) != nil {
		clear(ack)
		return fail(endpoint)
	}
	clear(ack)
	closeRecord, err := endpoint.CloseRecord()
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, closeRecord) != nil {
		clear(closeRecord)
		return fail(endpoint)
	}
	clear(closeRecord)
	return nil
}

// RunProcessRelaySessionV1 executes the relay side with independently owned
// handshake, replay, protected-record, and downstream-delivery state.
func RunProcessRelaySessionV1(ctx context.Context, carrier *tlstcp.Conn, handshake *ProcessWireRelayHandshakeV1, planDigest [32]byte, sink ProcessSessionSinkV1) error {
	if ctx == nil || carrier == nil || handshake == nil || planDigest == ([32]byte{}) || sink == nil {
		return ErrProcessSessionV1
	}
	fail := func(endpoint *ProcessRelayRecordEndpointV1) error {
		handshake.Close()
		if endpoint != nil {
			endpoint.Abort()
		}
		_ = carrier.Close()
		return ErrProcessSessionV1
	}
	clientHello, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return fail(nil)
	}
	serverHello, err := handshake.AcceptClientHello(clientHello)
	clear(clientHello)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, serverHello) != nil {
		clear(serverHello)
		return fail(nil)
	}
	clear(serverHello)
	clientFinish, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return fail(nil)
	}
	serverFinish, handshakeResult, err := handshake.AcceptClientFinish(clientFinish)
	clear(clientFinish)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, serverFinish) != nil {
		clear(serverFinish)
		if handshakeResult != nil {
			handshakeResult.Close()
		}
		return fail(nil)
	}
	clear(serverFinish)
	endpoint, err := NewProcessRelayRecordEndpointV1(handshakeResult, planDigest)
	if err != nil {
		handshakeResult.Close()
		return fail(nil)
	}
	defer endpoint.Abort()
	binding, err := carrier.CarrierBinding()
	if err != nil {
		return fail(endpoint)
	}
	bind, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return fail(endpoint)
	}
	ready, err := endpoint.AcceptProfileBind(bind, binding)
	clear(bind)
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, ready) != nil {
		clear(ready)
		return fail(endpoint)
	}
	clear(ready)
	record, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil {
		return fail(endpoint)
	}
	plaintext, delivery, err := endpoint.Open(record)
	clear(record)
	if err != nil {
		clear(plaintext)
		return fail(endpoint)
	}
	if err := sink.Deliver(ctx, plaintext); err != nil {
		clear(plaintext)
		delivery.Reject()
		return fail(endpoint)
	}
	clear(plaintext)
	ack, err := delivery.Commit()
	if err != nil || sendEncodedProcessFrameV1(ctx, carrier, ack) != nil {
		clear(ack)
		return fail(endpoint)
	}
	clear(ack)
	closeRecord, err := receiveEncodedProcessFrameV1(ctx, carrier)
	if err != nil || endpoint.AcceptClose(closeRecord) != nil {
		clear(closeRecord)
		return fail(endpoint)
	}
	clear(closeRecord)
	return nil
}

func sendEncodedProcessFrameV1(ctx context.Context, carrier *tlstcp.Conn, encoded []byte) error {
	if len(encoded) == 0 {
		return ErrProcessSessionV1
	}
	frame, err := wirev1.Decode(encoded)
	if err != nil {
		return ErrProcessSessionV1
	}
	defer clear(frame.Payload)
	return carrier.Send(ctx, frame)
}

func receiveEncodedProcessFrameV1(ctx context.Context, carrier *tlstcp.Conn) ([]byte, error) {
	frame, err := carrier.Receive(ctx)
	if err != nil {
		return nil, ErrProcessSessionV1
	}
	defer clear(frame.Payload)
	encoded, err := wirev1.Encode(frame)
	if err != nil {
		return nil, ErrProcessSessionV1
	}
	return encoded, nil
}
