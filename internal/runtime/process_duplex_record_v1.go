// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/wirev1"
)

const (
	duplexKindOperationV1 byte = 1
	duplexKindKeepaliveV1 byte = 2
	duplexKindCloseV1     byte = 3
	duplexBodyHeaderV1         = 16
	duplexMaximumFramesV1      = 256
)

var (
	ErrAuthenticatedFrameState = errors.New("authenticated_frame_state")
	duplexMagicV1              = [8]byte{'K', 'R', 'D', 'D', 'P', 'X', '0', '1'}
)

type ProcessDuplexEndpointV1 interface {
	SealOperation(operation framing.Operation, seed int64) ([][]byte, error)
	OpenFrame(encoded []byte) (*AuthenticatedInnerFrameV1, error)
	SealKeepalive(seed int64) ([]byte, error)
	SealClose(code uint16) ([]byte, error)
	Abort()
}

type ProcessClientDuplexEndpointV1 struct{ state *processDuplexStateV1 }
type ProcessRelayDuplexEndpointV1 struct{ state *processDuplexStateV1 }

type processDuplexStateV1 struct {
	self *processDuplexStateV1
	mu   sync.Mutex

	client      bool
	digest      [32]byte
	context     security.EnvelopeContextV1
	codec       *security.EnvelopeCodecV1
	program     liveprogram.ProgramV1
	maxMessages uint64
	sendCount   uint64
	recvCount   uint64
	bindStarted bool
	bound       bool
	closed      bool
	pending     *AuthenticatedInnerFrameV1
}

type AuthenticatedInnerFrameV1 struct {
	self      *AuthenticatedInnerFrameV1
	owner     *processDuplexStateV1
	operation framing.Operation
	streamID  uint32
	sequence  uint64
	replay    security.AuthenticatedReplayV1
	terminal  bool
}

func NewProcessClientDuplexEndpointV1(result *auth.ProcessHandshakeResultV1, planDigest [32]byte, program liveprogram.ProgramV1) (*ProcessClientDuplexEndpointV1, error) {
	state, err := newProcessDuplexStateV1(result, planDigest, program, true)
	if err != nil {
		return nil, err
	}
	return &ProcessClientDuplexEndpointV1{state: state}, nil
}

func NewProcessRelayDuplexEndpointV1(result *auth.ProcessHandshakeResultV1, planDigest [32]byte, program liveprogram.ProgramV1) (*ProcessRelayDuplexEndpointV1, error) {
	state, err := newProcessDuplexStateV1(result, planDigest, program, false)
	if err != nil {
		return nil, err
	}
	return &ProcessRelayDuplexEndpointV1{state: state}, nil
}

func newProcessDuplexStateV1(result *auth.ProcessHandshakeResultV1, planDigest [32]byte, program liveprogram.ProgramV1, client bool) (*processDuplexStateV1, error) {
	if err := liveprogram.ValidateV1(program); err != nil {
		return nil, ErrProfileIncompatible
	}
	context, codec, config, err := newProcessRecordCodecV1(result, planDigest, client)
	if err != nil {
		return nil, err
	}
	state := &processDuplexStateV1{client: client, digest: planDigest, context: context, codec: codec, program: program.Clone(), maxMessages: config.MaxSessionMessages}
	state.self = state
	return state, nil
}

func (endpoint *ProcessClientDuplexEndpointV1) ProfileBind(exporter [32]byte) ([]byte, error) {
	state, err := endpoint.clientStateV1()
	if err != nil {
		return nil, err
	}
	return state.profileBindV1(exporter)
}

func (endpoint *ProcessClientDuplexEndpointV1) AcceptEngineReady(encoded []byte) error {
	state, err := endpoint.clientStateV1()
	if err != nil {
		return err
	}
	return state.acceptEngineReadyV1(encoded)
}

func (endpoint *ProcessRelayDuplexEndpointV1) AcceptProfileBind(encoded []byte, exporter [32]byte) ([]byte, error) {
	state, err := endpoint.relayStateV1()
	if err != nil {
		return nil, err
	}
	return state.acceptProfileBindV1(encoded, exporter)
}

func (endpoint *ProcessClientDuplexEndpointV1) SealOperation(operation framing.Operation, seed int64) ([][]byte, error) {
	state, err := endpoint.clientStateV1()
	if err != nil {
		return nil, err
	}
	return state.sealOperationV1(operation, seed)
}
func (endpoint *ProcessRelayDuplexEndpointV1) SealOperation(operation framing.Operation, seed int64) ([][]byte, error) {
	state, err := endpoint.relayStateV1()
	if err != nil {
		return nil, err
	}
	return state.sealOperationV1(operation, seed)
}
func (endpoint *ProcessClientDuplexEndpointV1) OpenFrame(encoded []byte) (*AuthenticatedInnerFrameV1, error) {
	state, err := endpoint.clientStateV1()
	if err != nil {
		return nil, err
	}
	return state.openFrameV1(encoded)
}
func (endpoint *ProcessRelayDuplexEndpointV1) OpenFrame(encoded []byte) (*AuthenticatedInnerFrameV1, error) {
	state, err := endpoint.relayStateV1()
	if err != nil {
		return nil, err
	}
	return state.openFrameV1(encoded)
}
func (endpoint *ProcessClientDuplexEndpointV1) SealKeepalive(seed int64) ([]byte, error) {
	state, err := endpoint.clientStateV1()
	if err != nil {
		return nil, err
	}
	return state.sealKeepaliveV1(seed)
}
func (endpoint *ProcessRelayDuplexEndpointV1) SealKeepalive(seed int64) ([]byte, error) {
	state, err := endpoint.relayStateV1()
	if err != nil {
		return nil, err
	}
	return state.sealKeepaliveV1(seed)
}
func (endpoint *ProcessClientDuplexEndpointV1) SealClose(code uint16) ([]byte, error) {
	state, err := endpoint.clientStateV1()
	if err != nil {
		return nil, err
	}
	return state.sealCloseV1(code)
}
func (endpoint *ProcessRelayDuplexEndpointV1) SealClose(code uint16) ([]byte, error) {
	state, err := endpoint.relayStateV1()
	if err != nil {
		return nil, err
	}
	return state.sealCloseV1(code)
}
func (endpoint *ProcessClientDuplexEndpointV1) Abort() {
	if state, err := endpoint.clientStateV1(); err == nil {
		state.abortV1()
	}
}
func (endpoint *ProcessRelayDuplexEndpointV1) Abort() {
	if state, err := endpoint.relayStateV1(); err == nil {
		state.abortV1()
	}
}

func (endpoint *ProcessClientDuplexEndpointV1) clientStateV1() (*processDuplexStateV1, error) {
	if endpoint == nil || endpoint.state == nil {
		return nil, ErrSecureChannel
	}
	return endpoint.state, nil
}

func (endpoint *ProcessRelayDuplexEndpointV1) relayStateV1() (*processDuplexStateV1, error) {
	if endpoint == nil || endpoint.state == nil {
		return nil, ErrSecureChannel
	}
	return endpoint.state, nil
}

func (state *processDuplexStateV1) profileBindV1(exporter [32]byte) ([]byte, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.validLockedV1() || !state.client || state.bound || state.bindStarted || exporter == ([32]byte{}) {
		return nil, state.failLockedV1(ErrSecureChannel)
	}
	body := make([]byte, 72)
	copy(body[:8], processBindMagicV1[:])
	copy(body[8:40], exporter[:])
	copy(body[40:], state.digest[:])
	defer clear(body)
	record, err := state.sealBodyLockedV1(wirev1.TypeProfileBind, 0, processControlSlotV1, body)
	if err != nil {
		return nil, state.failLockedV1(err)
	}
	state.bindStarted = true
	return record, nil
}

func (state *processDuplexStateV1) acceptEngineReadyV1(encoded []byte) error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.validLockedV1() || !state.client || !state.bindStarted || state.bound {
		return state.failLockedV1(ErrSecureChannel)
	}
	body, replay, _, err := state.authenticateBodyLockedV1(encoded, wirev1.TypeEngineReady, 0, processControlSlotV1)
	if err != nil {
		return state.failLockedV1(err)
	}
	defer clear(body)
	if len(body) != len(processReadyMagicV1) || subtle.ConstantTimeCompare(body, processReadyMagicV1[:]) != 1 {
		_ = replay.Discard()
		return state.failLockedV1(ErrRecordInvalid)
	}
	if err := replay.Commit(); err != nil {
		return state.failLockedV1(err)
	}
	state.recvCount++
	state.bound = true
	return nil
}

func (state *processDuplexStateV1) acceptProfileBindV1(encoded []byte, exporter [32]byte) ([]byte, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.validLockedV1() || state.client || state.bound || exporter == ([32]byte{}) {
		return nil, state.failLockedV1(ErrSecureChannel)
	}
	body, replay, _, err := state.authenticateBodyLockedV1(encoded, wirev1.TypeProfileBind, 0, processControlSlotV1)
	if err != nil {
		return nil, state.failLockedV1(err)
	}
	defer clear(body)
	if len(body) != 72 || subtle.ConstantTimeCompare(body[:8], processBindMagicV1[:]) != 1 || subtle.ConstantTimeCompare(body[8:40], exporter[:]) != 1 || subtle.ConstantTimeCompare(body[40:], state.digest[:]) != 1 {
		_ = replay.Discard()
		return nil, state.failLockedV1(ErrRecordInvalid)
	}
	if err := replay.Commit(); err != nil {
		return nil, state.failLockedV1(err)
	}
	state.recvCount++
	ready := append([]byte(nil), processReadyMagicV1[:]...)
	defer clear(ready)
	record, err := state.sealBodyLockedV1(wirev1.TypeEngineReady, 0, processControlSlotV1, ready)
	if err != nil {
		return nil, state.failLockedV1(err)
	}
	state.bound = true
	return record, nil
}

func (state *processDuplexStateV1) sealOperationV1(operation framing.Operation, seed int64) ([][]byte, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.validLockedV1() || !state.bound || operation.StreamID == 0 || operation.StreamID >= uint32(processControlSlotV1) || len(operation.Payload) == 0 {
		return nil, state.failLockedV1(ErrSecureChannel)
	}
	frames, err := framing.EncodeLiveOperation(state.program, cloneFramingOperationV1(operation), seed)
	if err != nil || len(frames) == 0 || len(frames) > duplexMaximumFramesV1 {
		clearFrameSetV1(frames)
		return nil, state.failLockedV1(ErrRecordInvalid)
	}
	body, err := encodeDuplexOperationBodyV1(frames)
	clearFrameSetV1(frames)
	if err != nil {
		return nil, state.failLockedV1(err)
	}
	defer clear(body)
	record, err := state.sealBodyLockedV1(wirev1.TypeReliableData, operation.StreamID, uint16(operation.StreamID), body)
	if err != nil {
		return nil, state.failLockedV1(err)
	}
	return [][]byte{record}, nil
}

func (state *processDuplexStateV1) sealKeepaliveV1(seed int64) ([]byte, error) {
	_ = seed
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.validLockedV1() || !state.bound {
		return nil, state.failLockedV1(ErrSecureChannel)
	}
	body := encodeDuplexControlBodyV1(duplexKindKeepaliveV1, 0)
	defer clear(body)
	record, err := state.sealBodyLockedV1(wirev1.TypeReliableData, uint32(processControlSlotV1), processControlSlotV1, body)
	if err != nil {
		return nil, state.failLockedV1(err)
	}
	return record, nil
}

func (state *processDuplexStateV1) sealCloseV1(code uint16) ([]byte, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.validLockedV1() || !state.bound || code != CloseCodeTerminalV1 {
		return nil, state.failLockedV1(ErrSecureChannel)
	}
	body := encodeDuplexControlBodyV1(duplexKindCloseV1, code)
	defer clear(body)
	record, err := state.sealBodyLockedV1(wirev1.TypeClose, 0, processControlSlotV1, body)
	state.closeLockedV1()
	return record, err
}

func (state *processDuplexStateV1) openFrameV1(encoded []byte) (*AuthenticatedInnerFrameV1, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.validLockedV1() || !state.bound || state.pending != nil {
		return nil, state.failLockedV1(ErrSecureChannel)
	}
	frame, err := wirev1.Decode(encoded)
	if err != nil || frame.Flags != wirev1.FlagCritical || frame.PlanDigest != state.digest || (frame.Type != wirev1.TypeReliableData && frame.Type != wirev1.TypeClose) {
		clear(frame.Payload)
		return nil, state.failLockedV1(ErrRecordInvalid)
	}
	outerStream := frame.StreamID
	expectedSlot := processControlSlotV1
	if frame.Type == wirev1.TypeReliableData && outerStream != uint32(processControlSlotV1) {
		if outerStream == 0 || outerStream >= uint32(processControlSlotV1) {
			clear(frame.Payload)
			return nil, state.failLockedV1(ErrRecordInvalid)
		}
		expectedSlot = uint16(outerStream)
	}
	direction := applicationDirectionRelayV1
	if !state.client {
		direction = applicationDirectionClientV1
	}
	envelope, err := decodeProcessEnvelopeV1(frame.Payload, direction, state.context.MaxEnvelopeBytes)
	clear(frame.Payload)
	if err != nil || envelope.Slot != expectedSlot {
		clear(envelope.Ciphertext)
		return nil, state.failLockedV1(ErrRecordInvalid)
	}
	body, replay, err := state.codec.AuthenticateApplicationV1(envelope)
	sequence := envelope.Sequence
	clear(envelope.Ciphertext)
	if err != nil {
		return nil, state.failLockedV1(err)
	}
	defer clear(body)
	kind, code, innerFrames, err := decodeDuplexBodyV1(body)
	if err != nil {
		_ = replay.Discard()
		return nil, state.failLockedV1(err)
	}
	defer clearFrameSetV1(innerFrames)
	switch kind {
	case duplexKindKeepaliveV1:
		if frame.Type != wirev1.TypeReliableData || outerStream != uint32(processControlSlotV1) || code != 0 {
			_ = replay.Discard()
			return nil, state.failLockedV1(ErrRecordInvalid)
		}
		if err := replay.Commit(); err != nil {
			return nil, state.failLockedV1(err)
		}
		state.recvCount++
		return nil, nil
	case duplexKindCloseV1:
		if frame.Type != wirev1.TypeClose || outerStream != 0 || code != CloseCodeTerminalV1 {
			_ = replay.Discard()
			return nil, state.failLockedV1(ErrRecordInvalid)
		}
		if err := replay.Commit(); err != nil {
			return nil, state.failLockedV1(err)
		}
		state.recvCount++
		state.closeLockedV1()
		return nil, ErrLinkClosed
	case duplexKindOperationV1:
		if frame.Type != wirev1.TypeReliableData || outerStream == uint32(processControlSlotV1) || code != 0 {
			_ = replay.Discard()
			return nil, state.failLockedV1(ErrRecordInvalid)
		}
		operation, _, err := framing.DecodeLiveFrames(state.program, innerFrames)
		if err != nil || operation.StreamID != outerStream || operation.StreamID == 0 || operation.StreamID >= uint32(processControlSlotV1) {
			clear(operation.Payload)
			_ = replay.Discard()
			return nil, state.failLockedV1(ErrRecordInvalid)
		}
		pending := &AuthenticatedInnerFrameV1{owner: state, operation: cloneFramingOperationV1(operation), streamID: outerStream, sequence: sequence, replay: replay}
		clear(operation.Payload)
		pending.self = pending
		state.pending = pending
		return pending, nil
	default:
		_ = replay.Discard()
		return nil, state.failLockedV1(ErrRecordInvalid)
	}
}

func (frame *AuthenticatedInnerFrameV1) Operation() framing.Operation {
	if frame == nil || frame.self != frame || frame.owner == nil {
		return framing.Operation{}
	}
	frame.owner.mu.Lock()
	defer frame.owner.mu.Unlock()
	if frame.terminal || frame.owner.pending != frame {
		return framing.Operation{}
	}
	return cloneFramingOperationV1(frame.operation)
}

func (frame *AuthenticatedInnerFrameV1) StreamID() uint32 {
	if frame == nil || frame.self != frame || frame.owner == nil {
		return 0
	}
	frame.owner.mu.Lock()
	defer frame.owner.mu.Unlock()
	if frame.terminal || frame.owner.pending != frame {
		return 0
	}
	return frame.streamID
}

func (frame *AuthenticatedInnerFrameV1) Sequence() uint64 {
	if frame == nil || frame.self != frame || frame.owner == nil {
		return 0
	}
	frame.owner.mu.Lock()
	defer frame.owner.mu.Unlock()
	if frame.terminal || frame.owner.pending != frame {
		return 0
	}
	return frame.sequence
}

func (frame *AuthenticatedInnerFrameV1) Commit() error  { return frame.finishV1(true) }
func (frame *AuthenticatedInnerFrameV1) Discard() error { return frame.finishV1(false) }

func (frame *AuthenticatedInnerFrameV1) finishV1(commit bool) error {
	if frame == nil || frame.self != frame || frame.owner == nil {
		return ErrAuthenticatedFrameState
	}
	owner := frame.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if frame.terminal || owner.pending != frame || !owner.validLockedV1() {
		return ErrAuthenticatedFrameState
	}
	frame.terminal = true
	owner.pending = nil
	var err error
	if commit {
		err = frame.replay.Commit()
		if err == nil {
			owner.recvCount++
		}
	} else {
		err = frame.replay.Discard()
	}
	clear(frame.operation.Payload)
	frame.operation = framing.Operation{}
	frame.replay = security.AuthenticatedReplayV1{}
	if !commit || err != nil {
		owner.closeLockedV1()
	}
	if err != nil {
		return normalizeProcessRecordErrorV1(err)
	}
	return nil
}

func (state *processDuplexStateV1) sealBodyLockedV1(frameType uint8, outerStream uint32, slot uint16, body []byte) ([]byte, error) {
	if state.sendCount >= state.maxMessages {
		return nil, ErrSessionMessageLimit
	}
	envelope, err := state.codec.SealApplicationV1(slot, body)
	if err != nil {
		return nil, err
	}
	payload, err := encodeProcessEnvelopeV1(envelope)
	clear(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	encoded, err := wirev1.Encode(wirev1.Frame{Type: frameType, Flags: wirev1.FlagCritical, StreamID: outerStream, PlanDigest: state.digest, Payload: payload})
	if err != nil {
		return nil, ErrRecordInvalid
	}
	state.sendCount++
	return encoded, nil
}

func (state *processDuplexStateV1) authenticateBodyLockedV1(encoded []byte, frameType uint8, outerStream uint32, slot uint16) ([]byte, security.AuthenticatedReplayV1, uint64, error) {
	if state.recvCount >= state.maxMessages {
		return nil, security.AuthenticatedReplayV1{}, 0, ErrSessionMessageLimit
	}
	direction := applicationDirectionRelayV1
	if !state.client {
		direction = applicationDirectionClientV1
	}
	frame, envelope, err := decodeProcessRecordFrameV1(encoded, frameType, state.digest, direction, state.context.MaxEnvelopeBytes)
	if err != nil {
		return nil, security.AuthenticatedReplayV1{}, 0, err
	}
	defer clear(envelope.Ciphertext)
	if frame.StreamID != outerStream || envelope.Slot != slot {
		return nil, security.AuthenticatedReplayV1{}, 0, ErrRecordInvalid
	}
	body, replay, err := state.codec.AuthenticateApplicationV1(envelope)
	return body, replay, envelope.Sequence, err
}

func (state *processDuplexStateV1) abortV1() {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	state.closeLockedV1()
}

func (state *processDuplexStateV1) validLockedV1() bool {
	return state != nil && state.self == state && !state.closed && state.codec != nil
}

func (state *processDuplexStateV1) failLockedV1(err error) error {
	state.closeLockedV1()
	return normalizeProcessRecordErrorV1(err)
}

func (state *processDuplexStateV1) closeLockedV1() {
	if state == nil || state.closed {
		return
	}
	state.closed = true
	state.bound = false
	state.bindStarted = false
	state.codec = nil
	state.context = security.EnvelopeContextV1{}
	state.digest = [32]byte{}
	state.program = liveprogram.ProgramV1{}
	if state.pending != nil {
		state.pending.terminal = true
		clear(state.pending.operation.Payload)
		state.pending.operation = framing.Operation{}
		state.pending.replay = security.AuthenticatedReplayV1{}
		state.pending = nil
	}
}

func encodeDuplexOperationBodyV1(frames [][]byte) ([]byte, error) {
	if len(frames) == 0 || len(frames) > duplexMaximumFramesV1 {
		return nil, ErrRecordInvalid
	}
	total := duplexBodyHeaderV1
	for _, frame := range frames {
		if len(frame) == 0 || len(frame) > wirev1.MaxPayloadBytes || total > wirev1.MaxPayloadBytes-4-len(frame) {
			return nil, ErrRecordInvalid
		}
		total += 4 + len(frame)
	}
	body := make([]byte, total)
	copy(body[:8], duplexMagicV1[:])
	body[8] = duplexKindOperationV1
	binary.BigEndian.PutUint16(body[10:12], uint16(len(frames)))
	binary.BigEndian.PutUint32(body[12:16], uint32(total-duplexBodyHeaderV1))
	offset := duplexBodyHeaderV1
	for _, frame := range frames {
		binary.BigEndian.PutUint32(body[offset:offset+4], uint32(len(frame)))
		offset += 4
		copy(body[offset:offset+len(frame)], frame)
		offset += len(frame)
	}
	return body, nil
}

func encodeDuplexControlBodyV1(kind byte, code uint16) []byte {
	body := make([]byte, duplexBodyHeaderV1)
	copy(body[:8], duplexMagicV1[:])
	body[8] = kind
	binary.BigEndian.PutUint16(body[10:12], code)
	return body
}

func decodeDuplexBodyV1(body []byte) (byte, uint16, [][]byte, error) {
	if len(body) < duplexBodyHeaderV1 || subtle.ConstantTimeCompare(body[:8], duplexMagicV1[:]) != 1 || body[9] != 0 {
		return 0, 0, nil, ErrRecordInvalid
	}
	kind := body[8]
	value := binary.BigEndian.Uint16(body[10:12])
	payloadLength := binary.BigEndian.Uint32(body[12:16])
	if uint64(duplexBodyHeaderV1)+uint64(payloadLength) != uint64(len(body)) {
		return 0, 0, nil, ErrRecordInvalid
	}
	if kind != duplexKindOperationV1 {
		if payloadLength != 0 || (kind != duplexKindKeepaliveV1 && kind != duplexKindCloseV1) {
			return 0, 0, nil, ErrRecordInvalid
		}
		return kind, value, nil, nil
	}
	count := int(value)
	if count == 0 || count > duplexMaximumFramesV1 {
		return 0, 0, nil, ErrRecordInvalid
	}
	frames := make([][]byte, 0, count)
	offset := duplexBodyHeaderV1
	for index := 0; index < count; index++ {
		if offset+4 > len(body) {
			clearFrameSetV1(frames)
			return 0, 0, nil, ErrRecordInvalid
		}
		length := uint64(binary.BigEndian.Uint32(body[offset : offset+4]))
		offset += 4
		if length == 0 || length > wirev1.MaxPayloadBytes || uint64(offset)+length > uint64(len(body)) {
			clearFrameSetV1(frames)
			return 0, 0, nil, ErrRecordInvalid
		}
		frames = append(frames, append([]byte(nil), body[offset:offset+int(length)]...))
		offset += int(length)
	}
	if offset != len(body) {
		clearFrameSetV1(frames)
		return 0, 0, nil, ErrRecordInvalid
	}
	return kind, 0, frames, nil
}

func cloneFramingOperationV1(operation framing.Operation) framing.Operation {
	operation.Payload = append([]byte(nil), operation.Payload...)
	return operation
}

func clearFrameSetV1(frames [][]byte) {
	for _, frame := range frames {
		clear(frame)
	}
}

var _ ProcessDuplexEndpointV1 = (*ProcessClientDuplexEndpointV1)(nil)
var _ ProcessDuplexEndpointV1 = (*ProcessRelayDuplexEndpointV1)(nil)
