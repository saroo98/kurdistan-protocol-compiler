// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"errors"

	"kurdistan/internal/protocol/wirev1"
	"kurdistan/internal/transport/tlstcp"
)

var ErrProcessSessionV1 = errors.New("process-separated Kurd session rejected")

// ProcessSessionSinkV1 is the relay's bounded downstream delivery boundary.
type ProcessSessionSinkV1 interface {
	Deliver(context.Context, []byte) error
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
