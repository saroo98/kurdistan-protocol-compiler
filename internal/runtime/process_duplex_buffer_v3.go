// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"unsafe"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/wirev1"
)

// ProcessDuplexBoundsV3 is the lifetime reservation, not current RSS or a
// service grant. Values remain available after Abort for owner accounting.
type ProcessDuplexBoundsV3 struct {
	OwnedBytes                      uint64
	MaxRecordBytes, MaxPayloadBytes uint32
}

// ProcessDuplexEndpointV3 is an authenticated framing primitive only. Select
// production V3 only after exact verified program/service admission with
// matching ServiceAdmissionV1 scope. It cannot grant an absent signed service.
//
// A single TX producer must finish writing each borrowed record before its
// next seal. A single RX consumer owns ReceiveBufferV3 and completes pending
// delivery before its next read/open. Info/copy is not delivery; Commit follows
// successful delivery, Discard terminates. Stop/join all external buffer users
// before Abort. SealCloseV3 leaves its borrowed final record intact until Abort.
// Later packet/chunk admission must enforce MTU<=MaxPayloadBytes and chunks<=L-8.
type ProcessDuplexEndpointV3 interface {
	SealDataV3([]byte, uint32, int64) ([]byte, error)
	OpenFrameV3([]byte) (*AuthenticatedInnerFrameV1, error)
	SealKeepaliveV3() ([]byte, error)
	SealCloseV3(uint16) ([]byte, error)
	ReceiveBufferV3() []byte
	BoundsV3() ProcessDuplexBoundsV3
	Abort()
}
type ProcessClientDuplexEndpointV3 struct{ state *processDuplexStateV1 }
type ProcessRelayDuplexEndpointV3 struct{ state *processDuplexStateV1 }

// Same bounded backing and crypto owner; only legacy packet TX metadata differs.
type processClientRawEndpointV2 struct{ ProcessClientDuplexEndpointV3 }

func (e *processClientRawEndpointV2) SealDataV3(b []byte, stream uint32, seed int64) ([]byte, error) {
	if e == nil {
		return nil, ErrSecureChannel
	}
	return e.state.sealPacketDataV3(b, stream, seed, rawPacketPumpV2)
}

func NewProcessClientDuplexEndpointV3(result *auth.ProcessHandshakeResultV1, planDigest [32]byte, program liveprogram.ProgramV1, maxRecordBytes uint32, budgetBytes uint64) (*ProcessClientDuplexEndpointV3, error) {
	s, e := newDuplexStateV3(result, planDigest, program, maxRecordBytes, budgetBytes, true)
	if e != nil {
		return nil, e
	}
	return &ProcessClientDuplexEndpointV3{state: s}, nil
}
func NewProcessRelayDuplexEndpointV3(result *auth.ProcessHandshakeResultV1, planDigest [32]byte, program liveprogram.ProgramV1, maxRecordBytes uint32, budgetBytes uint64) (*ProcessRelayDuplexEndpointV3, error) {
	s, e := newDuplexStateV3(result, planDigest, program, maxRecordBytes, budgetBytes, false)
	if e != nil {
		return nil, e
	}
	return &ProcessRelayDuplexEndpointV3{state: s}, nil
}
func (e *ProcessClientDuplexEndpointV3) ProfileBind(x [32]byte) ([]byte, error) {
	if e == nil || e.state == nil {
		return nil, ErrSecureChannel
	}
	return e.state.profileBindV1(x)
}
func (e *ProcessRelayDuplexEndpointV3) AcceptProfileBind(b []byte, x [32]byte) ([]byte, error) {
	if e == nil || e.state == nil {
		return nil, ErrSecureChannel
	}
	return e.state.acceptProfileBindV1(b, x)
}
func (e *ProcessClientDuplexEndpointV3) AcceptEngineReady(b []byte) error {
	if e == nil || e.state == nil {
		return ErrSecureChannel
	}
	return e.state.acceptEngineReadyV1(b)
}
func (e *ProcessClientDuplexEndpointV3) SealDataV3(b []byte, s uint32, seed int64) ([]byte, error) {
	if e == nil {
		return nil, ErrSecureChannel
	}
	return e.state.sealDataV3(b, s, seed)
}
func (e *ProcessRelayDuplexEndpointV3) SealDataV3(b []byte, s uint32, seed int64) ([]byte, error) {
	if e == nil {
		return nil, ErrSecureChannel
	}
	return e.state.sealDataV3(b, s, seed)
}
func (e *ProcessClientDuplexEndpointV3) OpenFrameV3(b []byte) (*AuthenticatedInnerFrameV1, error) {
	if e == nil {
		return nil, ErrSecureChannel
	}
	return e.state.openFrameV3(b)
}
func (e *ProcessRelayDuplexEndpointV3) OpenFrameV3(b []byte) (*AuthenticatedInnerFrameV1, error) {
	if e == nil {
		return nil, ErrSecureChannel
	}
	return e.state.openFrameV3(b)
}
func (e *ProcessClientDuplexEndpointV3) SealKeepaliveV3() ([]byte, error) {
	if e == nil || e.state == nil {
		return nil, ErrSecureChannel
	}
	return e.state.sealKeepaliveV1(0)
}
func (e *ProcessRelayDuplexEndpointV3) SealKeepaliveV3() ([]byte, error) {
	if e == nil || e.state == nil {
		return nil, ErrSecureChannel
	}
	return e.state.sealKeepaliveV1(0)
}
func (e *ProcessClientDuplexEndpointV3) SealCloseV3(c uint16) ([]byte, error) {
	if e == nil || e.state == nil {
		return nil, ErrSecureChannel
	}
	return e.state.sealCloseV1(c)
}
func (e *ProcessRelayDuplexEndpointV3) SealCloseV3(c uint16) ([]byte, error) {
	if e == nil || e.state == nil {
		return nil, ErrSecureChannel
	}
	return e.state.sealCloseV1(c)
}
func (e *ProcessClientDuplexEndpointV3) ReceiveBufferV3() []byte {
	if e == nil {
		return nil
	}
	return e.state.receiveBufferV3()
}
func (e *ProcessRelayDuplexEndpointV3) ReceiveBufferV3() []byte {
	if e == nil {
		return nil
	}
	return e.state.receiveBufferV3()
}
func (e *ProcessClientDuplexEndpointV3) BoundsV3() ProcessDuplexBoundsV3 {
	if e == nil {
		return ProcessDuplexBoundsV3{}
	}
	return e.state.boundsV3()
}
func (e *ProcessRelayDuplexEndpointV3) BoundsV3() ProcessDuplexBoundsV3 {
	if e == nil {
		return ProcessDuplexBoundsV3{}
	}
	return e.state.boundsV3()
}
func (e *ProcessClientDuplexEndpointV3) Abort() {
	if e != nil {
		e.state.abortV1()
	}
}
func (e *ProcessRelayDuplexEndpointV3) Abort() {
	if e != nil {
		e.state.abortV1()
	}
}
func (f *AuthenticatedInnerFrameV1) DataInfoV3() (framing.LiveDataInfoV3, error) {
	if f == nil || f.self != f || f.owner == nil {
		return framing.LiveDataInfoV3{}, ErrAuthenticatedFrameState
	}
	s := f.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if !f.validDataV3Locked() {
		return framing.LiveDataInfoV3{}, ErrAuthenticatedFrameState
	}
	return framing.LiveDataInfoV3{StreamID: f.streamID, PayloadBytes: uint32(len(f.operation.Payload))}, nil
}
func (f *AuthenticatedInnerFrameV1) CopyPayloadIntoV3(b []byte) (int, error) {
	if f == nil || f.self != f || f.owner == nil {
		return 0, ErrAuthenticatedFrameState
	}
	s := f.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if !f.validDataV3Locked() {
		return 0, ErrAuthenticatedFrameState
	}
	if len(b) < len(f.operation.Payload) {
		return 0, ServiceResourceLimitV1
	}
	return copy(b, f.operation.Payload), nil
}
func (f *AuthenticatedInnerFrameV1) validDataV3Locked() bool {
	return f.owner.bounded != nil && f.owner.validLockedV1() && !f.terminal && f.owner.pending == f && f.operation.Semantic == "data"
}

// One TX producer must finish its carrier write before the next seal. One RX
// reader may borrow ReceiveBufferV3; its pending delivery must finish before the
// next read/open. Abort is called only after all external buffer users join.
// These primitives implement no carrier pump, signed-service grant or lifecycle
// coordination. A later admitted owner must enforce MTU<=L and chunks<=L-8.
type duplexWorkspaceV3 struct {
	bounds                                                           ProcessDuplexBoundsV3
	framing                                                          *framing.LiveDataCodecV3
	envelope                                                         *security.EnvelopeCodecV1 // survives logical close until joined Abort
	txFrames, txBody, rxBody, txRecord, rxRecord, rxPayload, padding []byte
	txSpans, rxSpans                                                 [256]framing.FrameSpanV3
}

// Prepared framing retains <=6218 bytes on pinned 64-bit targets; 64 KiB
// separately covers its validation/projection/RNG construction. Auth projection
// validation/snapshot has its own 1 MiB allowance, never hidden in this one.
const duplexFramingAllowanceV3 uint64 = 65536

// Six sequential SHA256-HKDF expands: 152 retained output bytes, 32-byte
// PRK+32-byte transferred input, <=128-byte info buffer per expand and fixed
// HMAC/SHA256 states. 16 KiB separately reserves the complete KDF construction
// and two strict-config projections, measured by construction regression.
const duplexSetupAllowanceV3 uint64 = 16384

type duplexSizeV3 struct {
	bounds                            ProcessDuplexBoundsV3
	dataCap, frameBytes, paddingBytes uint32
}

func duplexFixedBytesV3() uint64 {
	return auth.ProjectedContextValidationBytesV3 + duplexFramingAllowanceV3 + duplexSetupAllowanceV3 + uint64(unsafe.Sizeof(processDuplexStateV1{})) + uint64(unsafe.Sizeof(duplexWorkspaceV3{})) + uint64(unsafe.Sizeof(AuthenticatedInnerFrameV1{})) + uint64(unsafe.Sizeof(ProcessClientDuplexEndpointV3{}))
}

// sizeDuplexV3 is shared by pre-socket preparation and authenticated allocation.
// It derives no keys and never reduces payload capacity to satisfy a budget.
func sizeDuplexV3(program liveprogram.ProgramV1, codec *framing.LiveDataCodecV3, envelopeBytes uint32, cryptoBytes uint64, recordCap, minimum uint32, budget uint64) (duplexSizeV3, error) {
	fixed := duplexFixedBytesV3()
	if codec == nil || len(program.Messages) == 0 || minimum < 272 || minimum > 65535 || recordCap < 92 || recordCap > 1<<20 || envelopeBytes < 16 || budget > 128<<20 || budget < fixed || cryptoBytes > budget-fixed {
		return duplexSizeV3{}, ServiceResourceLimitV1
	}
	fixed += cryptoBytes
	e, rc := uint64(envelopeBytes), uint64(recordCap)
	dcap := min(e-16, uint64(wirev1.MaxPayloadBytes-44), rc-92)
	rcap := min(rc, e+76, uint64(wirev1.MaxPayloadBytes+48))
	fits := func(n int) (framing.LiveDataBoundsV3, bool) {
		b, err := codec.Bounds(n)
		return b, err == nil && 16+4*uint64(b.FrameCount)+uint64(b.FrameBytes) <= dcap
	}
	if _, ok := fits(272); !ok {
		return duplexSizeV3{}, ServiceResourceLimitV1
	}
	lo, hi := 272, min(65535, program.Messages[0].MaxPayloadBytes, program.Limits.MaxPayloadBytes)
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		if _, ok := fits(mid); ok {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	fb, _ := fits(lo)
	if uint32(lo) < minimum {
		return duplexSizeV3{}, ServiceResourceLimitV1
	}
	total := fixed
	for _, n := range []uint64{uint64(fb.FrameBytes), dcap, dcap, rcap, rcap, uint64(lo), uint64(fb.PaddingBytes)} {
		if n > budget-total {
			return duplexSizeV3{}, ServiceResourceLimitV1
		}
		total += n
	}
	return duplexSizeV3{bounds: ProcessDuplexBoundsV3{OwnedBytes: total, MaxRecordBytes: uint32(rcap), MaxPayloadBytes: uint32(lo)}, dataCap: uint32(dcap), frameBytes: fb.FrameBytes, paddingBytes: fb.PaddingBytes}, nil
}

func newDuplexStateV3(result *auth.ProcessHandshakeResultV1, digest [32]byte, program liveprogram.ProgramV1, recordCap uint32, budget uint64, client bool) (*processDuplexStateV1, error) {
	return newDuplexStateMinimumV3(result, digest, program, recordCap, budget, client, 272)
}

// The combined pump checks its effective MTU before channel-secret transfer.
// Legacy public V3 constructors retain the original 272-byte minimum.
func newDuplexStateMinimumV3(result *auth.ProcessHandshakeResultV1, digest [32]byte, program liveprogram.ProgramV1, recordCap uint32, budget uint64, client bool, minimum uint32) (*processDuplexStateV1, error) {
	if minimum < 272 || minimum > 65535 {
		return nil, ServiceResourceLimitV1
	}
	fixed := duplexFixedBytesV3()
	if recordCap < 1 || recordCap > 1<<20 || budget > 128<<20 || budget < fixed {
		return nil, ServiceResourceLimitV1
	}
	if result == nil || digest == ([32]byte{}) {
		return nil, ErrProfileIncompatible
	}
	snapshot, err := result.ProjectedContextSnapshotV3(program, "tls13-tcp", auth.ProjectedContextValidationBytesV3)
	if err != nil {
		var failure *auth.HandshakeError
		if errors.As(err, &failure) && failure.Code == auth.FailureInternalLimit {
			return nil, ServiceResourceLimitV1
		}
		return nil, ErrProfileIncompatible
	}
	context, config, err := prepareProcessRecordContextV1(snapshot, client)
	if err != nil {
		return nil, err
	}
	cryptoBytes, err := security.EnvelopeOwnedBytesV3(context)
	if err != nil {
		return nil, err
	}
	if cryptoBytes > budget-fixed {
		return nil, ServiceResourceLimitV1
	}
	if context.MaxEnvelopeBytes < 16 || recordCap < 92 {
		return nil, ServiceResourceLimitV1
	}
	codec, err := framing.NewLiveDataCodecV3(program)
	if err != nil {
		return nil, ErrProfileIncompatible
	}
	size, err := sizeDuplexV3(program, codec, context.MaxEnvelopeBytes, cryptoBytes, recordCap, minimum, budget)
	if err != nil {
		return nil, err
	}
	// All sizes/profile checks precede transfer, KDF and variable arena makes.
	return constructDuplexV3(result, digest, snapshot, context, config, codec, size, client)
}

// Only callers that have completed real snapshot/context/sizing reconciliation
// may enter this single secret-consuming allocation stage.
func constructDuplexV3(result *auth.ProcessHandshakeResultV1, digest [32]byte, snapshot auth.AuthenticatedContextSnapshotV1, context security.EnvelopeContextV1, config StrictSessionConfigV1, codec *framing.LiveDataCodecV3, size duplexSizeV3, client bool) (*processDuplexStateV1, error) {
	envelope, err := deriveProcessRecordCodecV1(result, snapshot, context, client, true)
	if err != nil {
		return nil, err
	}
	w := &duplexWorkspaceV3{bounds: size.bounds, framing: codec, envelope: envelope,
		txFrames: make([]byte, int(size.frameBytes)), txBody: make([]byte, int(size.dataCap)), rxBody: make([]byte, int(size.dataCap)), txRecord: make([]byte, int(size.bounds.MaxRecordBytes)), rxRecord: make([]byte, int(size.bounds.MaxRecordBytes)), rxPayload: make([]byte, int(size.bounds.MaxPayloadBytes)), padding: make([]byte, int(size.paddingBytes))}
	state := &processDuplexStateV1{client: client, digest: digest, context: context, codec: envelope, maxMessages: config.MaxSessionMessages, bounded: w}
	state.self = state
	return state, nil
}

func (s *processDuplexStateV1) boundsV3() ProcessDuplexBoundsV3 {
	if s == nil {
		return ProcessDuplexBoundsV3{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.bounded == nil {
		return ProcessDuplexBoundsV3{}
	}
	return s.bounded.bounds
}
func (s *processDuplexStateV1) receiveBufferV3() []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLockedV1() || s.bounded == nil {
		return nil
	}
	return s.bounded.rxRecord[:len(s.bounded.rxRecord):len(s.bounded.rxRecord)]
}

func (w *duplexWorkspaceV3) destroyV3() {
	if w.envelope != nil {
		_ = w.envelope.DestroyBoundedV3()
		w.envelope = nil
	}
	for _, b := range [][]byte{w.txFrames, w.txBody, w.rxBody, w.txRecord, w.rxRecord, w.rxPayload, w.padding} {
		clear(b)
	}
	w.txFrames = nil
	w.txBody = nil
	w.rxBody = nil
	w.txRecord = nil
	w.rxRecord = nil
	w.rxPayload = nil
	w.padding = nil
	clear(w.txSpans[:])
	clear(w.rxSpans[:])
	w.framing = nil
}

func (s *processDuplexStateV1) controlBodyStorageV3(n int) []byte {
	if s.bounded == nil {
		return make([]byte, n)
	}
	b := s.bounded.txBody[:n:n]
	clear(b)
	return b
}
func writeDuplexControlBodyV3(body []byte, kind byte, code uint16) {
	clear(body)
	copy(body[:8], duplexMagicV1[:])
	body[8] = kind
	binary.BigEndian.PutUint16(body[10:12], code)
}

func (s *processDuplexStateV1) sealDataV3(payload []byte, stream uint32, seed int64) ([]byte, error) {
	return s.sealPacketDataV3(payload, stream, seed, mixedPacketPumpV1)
}

func (s *processDuplexStateV1) sealPacketDataV3(payload []byte, stream uint32, seed int64, kind packetPumpKindV1) ([]byte, error) {
	if s == nil {
		return nil, ErrSecureChannel
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLockedV1() || !s.bound || s.bounded == nil || stream < 2 || stream > 65534 {
		return nil, s.failLockedV1(ErrSecureChannel)
	}
	w := s.bounded
	if len(payload) == 0 || uint64(len(payload)) > uint64(w.bounds.MaxPayloadBytes) {
		return nil, ServiceResourceLimitV1
	}
	if s.sendCount >= s.maxMessages {
		return nil, s.failLockedV1(ErrSessionMessageLimit)
	}
	// Framing validates payload/span/scratch aliases before RNG/output mutation.
	var n, count int
	var err error
	switch kind {
	case mixedPacketPumpV1:
		n, count, err = w.framing.EncodeInto(w.txFrames, w.padding, payload, stream, seed, &w.txSpans)
	case rawPacketPumpV2:
		n, count, err = w.framing.EncodePacketV2Into(w.txFrames, w.padding, payload, stream, seed, &w.txSpans)
	default:
		return nil, ErrProfileIncompatible
	}
	if err != nil {
		return nil, ServiceResourceLimitV1
	}
	total := 16 + 4*count + n
	if total > len(w.txBody) {
		return nil, s.failLockedV1(ErrRecordInvalid)
	}
	body := w.txBody[:total:total]
	clear(body[:16])
	copy(body[:8], duplexMagicV1[:])
	body[8] = duplexKindOperationV1
	binary.BigEndian.PutUint16(body[10:12], uint16(count))
	binary.BigEndian.PutUint32(body[12:16], uint32(total-16))
	offset := 16
	for _, span := range w.txSpans[:count] {
		binary.BigEndian.PutUint32(body[offset:offset+4], span.Length)
		offset += 4
		copy(body[offset:offset+int(span.Length)], w.txFrames[int(span.Offset):int(span.Offset+span.Length)])
		offset += int(span.Length)
	}
	record, err := s.sealBodyLockedV1(wirev1.TypeReliableData, stream, uint16(stream), body)
	clear(body)
	clear(w.txFrames[:n])
	clear(w.padding)
	if err != nil {
		return nil, s.failLockedV1(err)
	}
	return record, nil
}

func (s *processDuplexStateV1) sealBodyIntoV3Locked(kind uint8, stream uint32, slot uint16, body []byte) ([]byte, error) {
	w := s.bounded
	total := len(body) + 92
	if total > len(w.txRecord) || len(body) > len(w.txBody) {
		return nil, ServiceResourceLimitV1
	}
	envelope, err := s.codec.SealApplicationIntoV1(w.txRecord[76:total:total], slot, body)
	if err != nil {
		return nil, err
	}
	h := encodeApplicationHeaderV1(ApplicationHeaderV1{Version: ApplicationRecordVersionV1, Type: RecordTypeApplicationFragmentV1, Epoch: envelope.Epoch, Direction: envelope.Direction, StreamSlot: envelope.Slot, Sequence: envelope.Sequence, SealedLength: envelope.SealedLength})
	copy(w.txRecord[48:76], h[:])
	n, err := wirev1.EncodeInto(w.txRecord[:total], wirev1.Frame{Type: kind, Flags: wirev1.FlagCritical, StreamID: stream, PlanDigest: s.digest, Payload: w.txRecord[48:total]})
	if err != nil {
		return nil, ErrRecordInvalid
	}
	s.sendCount++
	return w.txRecord[:n:n], nil
}

func decodeProcessEnvelopeViewV3(b []byte, direction uint16, max uint32) (security.EnvelopeRecordV1, error) {
	if len(b) < 44 {
		return security.EnvelopeRecordV1{}, ErrRecordInvalid
	}
	h, err := parseApplicationHeaderV1(b[:28])
	if err != nil || h.Version != ApplicationRecordVersionV1 || h.Type != RecordTypeApplicationFragmentV1 || h.Direction != direction || h.StreamSlot == 0 || h.SealedLength < 16 || h.SealedLength > max || uint64(h.SealedLength)+28 != uint64(len(b)) {
		return security.EnvelopeRecordV1{}, ErrRecordInvalid
	}
	return security.EnvelopeRecordV1{RecordType: h.Type, Epoch: h.Epoch, Direction: h.Direction, Slot: h.StreamSlot, Sequence: h.Sequence, SealedLength: h.SealedLength, Ciphertext: b[28:len(b):len(b)]}, nil
}

func (s *processDuplexStateV1) authenticateBodyIntoV3Locked(b []byte, kind uint8, stream uint32, slot uint16) ([]byte, security.AuthenticatedReplayV1, uint64, error) {
	if len(b) > len(s.bounded.rxRecord) {
		return nil, security.AuthenticatedReplayV1{}, 0, ServiceResourceLimitV1
	}
	f, err := wirev1.DecodeView(b)
	if err != nil || f.Type != kind || f.Flags != wirev1.FlagCritical || f.PlanDigest != s.digest || f.StreamID != stream {
		return nil, security.AuthenticatedReplayV1{}, 0, ErrRecordInvalid
	}
	direction := applicationDirectionRelayV1
	if !s.client {
		direction = applicationDirectionClientV1
	}
	e, err := decodeProcessEnvelopeViewV3(f.Payload, direction, s.context.MaxEnvelopeBytes)
	if err != nil || e.Slot != slot {
		return nil, security.AuthenticatedReplayV1{}, 0, ErrRecordInvalid
	}
	p, g, err := s.codec.AuthenticateApplicationIntoV1(s.bounded.rxBody, e)
	return p, g, e.Sequence, err
}

func (s *processDuplexStateV1) openFrameV3(encoded []byte) (*AuthenticatedInnerFrameV1, error) {
	if s == nil {
		return nil, ErrSecureChannel
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validLockedV1() || !s.bound || s.bounded == nil || s.pending != nil {
		return nil, s.failLockedV1(ErrSecureChannel)
	}
	if s.recvCount >= s.maxMessages {
		return nil, s.failLockedV1(ErrSessionMessageLimit)
	}
	if len(encoded) > len(s.bounded.rxRecord) {
		return nil, s.failLockedV1(ServiceResourceLimitV1)
	}
	frame, err := wirev1.DecodeView(encoded)
	if err != nil || frame.Flags != wirev1.FlagCritical || frame.PlanDigest != s.digest || (frame.Type != wirev1.TypeReliableData && frame.Type != wirev1.TypeClose) {
		return nil, s.failLockedV1(ErrRecordInvalid)
	}
	slot := processControlSlotV1
	if frame.Type == wirev1.TypeReliableData && frame.StreamID != 65535 {
		if frame.StreamID < 2 || frame.StreamID > 65534 {
			return nil, s.failLockedV1(ErrRecordInvalid)
		}
		slot = uint16(frame.StreamID)
	}
	body, replay, sequence, err := s.authenticateBodyIntoV3Locked(encoded, frame.Type, frame.StreamID, slot)
	if err != nil {
		return nil, s.failLockedV1(err)
	}
	defer clear(body)
	reject := func(err error) (*AuthenticatedInnerFrameV1, error) {
		_ = replay.Discard()
		return nil, s.failLockedV1(err)
	}
	if len(body) < 16 || subtle.ConstantTimeCompare(body[:8], duplexMagicV1[:]) != 1 || body[9] != 0 || uint64(binary.BigEndian.Uint32(body[12:16]))+16 != uint64(len(body)) {
		return reject(ErrRecordInvalid)
	}
	kind, value := body[8], binary.BigEndian.Uint16(body[10:12])
	if kind != duplexKindOperationV1 {
		if len(body) != 16 {
			return reject(ErrRecordInvalid)
		}
		if kind == duplexKindKeepaliveV1 {
			if frame.Type != wirev1.TypeReliableData || frame.StreamID != 65535 || value != 0 {
				return reject(ErrRecordInvalid)
			}
		} else if kind == duplexKindCloseV1 {
			if frame.Type != wirev1.TypeClose || frame.StreamID != 0 || value != CloseCodeTerminalV1 {
				return reject(ErrRecordInvalid)
			}
		} else {
			return reject(ErrRecordInvalid)
		}
		if err = replay.Commit(); err != nil {
			return nil, s.failLockedV1(err)
		}
		s.recvCount++
		if kind == duplexKindCloseV1 {
			s.closeLockedV1()
			return nil, ErrLinkClosed
		}
		return nil, nil
	}
	if frame.Type != wirev1.TypeReliableData || frame.StreamID == 65535 || value < 1 || value > 256 {
		return reject(ErrRecordInvalid)
	}
	w := s.bounded
	offset := 16
	// Validate the whole grammar before moving any bytes. Each source is ahead
	// of its compacted destination; forward copy never overwrites unread input.
	for i := 0; i < int(value); i++ {
		if len(body)-offset < 4 {
			return reject(ErrRecordInvalid)
		}
		n := uint64(binary.BigEndian.Uint32(body[offset : offset+4]))
		offset += 4
		if n == 0 || n > wirev1.MaxPayloadBytes || n > uint64(len(body)-offset) {
			return reject(ErrRecordInvalid)
		}
		w.rxSpans[i] = framing.FrameSpanV3{Offset: uint32(offset), Length: uint32(n)}
		offset += int(n)
	}
	if offset != len(body) {
		return reject(ErrRecordInvalid)
	}
	pos := 0
	for i := 0; i < int(value); i++ {
		span := w.rxSpans[i]
		copy(body[pos:pos+int(span.Length)], body[int(span.Offset):int(span.Offset+span.Length)])
		w.rxSpans[i].Offset = uint32(pos)
		pos += int(span.Length)
	}
	info, err := w.framing.DecodeInto(w.rxPayload, body[:pos], w.rxSpans[:int(value)])
	if err != nil || info.StreamID != frame.StreamID {
		return reject(ErrRecordInvalid)
	}
	p := &AuthenticatedInnerFrameV1{owner: s, operation: framing.Operation{Semantic: "data", StreamID: info.StreamID, Payload: w.rxPayload[:int(info.PayloadBytes):int(info.PayloadBytes)]}, streamID: info.StreamID, sequence: sequence, replay: replay}
	p.self = p
	s.pending = p
	return p, nil
}

var _ ProcessDuplexEndpointV3 = (*ProcessClientDuplexEndpointV3)(nil)
var _ ProcessDuplexEndpointV3 = (*ProcessRelayDuplexEndpointV3)(nil)
