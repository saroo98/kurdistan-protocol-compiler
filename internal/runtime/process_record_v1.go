// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"encoding/binary"
	"errors"
	"sync"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/wirev1"
)

const (
	processControlSlotV1       uint16 = ^uint16(0)
	processEnvelopeHeaderBytes        = 28
	processAEADOverheadV1             = 16
	processDataFixedBytesV1           = 44
)

var (
	processBindMagicV1  = [8]byte{'K', 'R', 'D', 'B', 'N', 'D', '0', '1'}
	processReadyMagicV1 = [8]byte{'K', 'R', 'D', 'R', 'E', 'A', 'D', 'Y'}
	processDataMagicV1  = [8]byte{'K', 'R', 'D', 'D', 'A', 'T', 'A', '1'}
	processAckMagicV1   = [8]byte{'K', 'R', 'D', 'A', 'C', 'K', '0', '1'}
	processCloseMagicV1 = [8]byte{'K', 'R', 'D', 'C', 'L', 'O', 'S', '1'}
)

type processOutstandingV1 struct {
	slot uint16
}

// ProcessClientRecordEndpointV1 is a client-process-owned protected record
// endpoint. It shares no mutable state with its relay peer.
type ProcessClientRecordEndpointV1 struct {
	self *ProcessClientRecordEndpointV1
	mu   sync.Mutex

	digest      [32]byte
	context     security.EnvelopeContextV1
	codec       *security.EnvelopeCodecV1
	maxFrame    uint32
	maxMessages uint64
	maxStreams  uint32

	bindStarted bool
	bound       bool
	closed      bool
	sendCount   uint64
	recvCount   uint64
	nextOp      uint64
	outstanding map[[32]byte]processOutstandingV1
}

// ProcessRelayRecordEndpointV1 is a relay-process-owned protected record
// endpoint. Replay state, delivery state, and acknowledgements are local to
// this object only.
type ProcessRelayRecordEndpointV1 struct {
	self *ProcessRelayRecordEndpointV1
	mu   sync.Mutex

	digest      [32]byte
	context     security.EnvelopeContextV1
	codec       *security.EnvelopeCodecV1
	maxFrame    uint32
	maxMessages uint64

	bound     bool
	closed    bool
	sendCount uint64
	recvCount uint64
	completed uint64
	seen      map[[32]byte]struct{}
	pending   *ProcessRelayDeliveryV1
}

// ProcessRelayDeliveryV1 acknowledges one authenticated record only after
// downstream delivery succeeds.
type ProcessRelayDeliveryV1 struct {
	self  *ProcessRelayDeliveryV1
	owner *ProcessRelayRecordEndpointV1
	id    [32]byte
	slot  uint16
	done  bool
}

func NewProcessClientRecordEndpointV1(result *auth.ProcessHandshakeResultV1, planDigest [32]byte) (*ProcessClientRecordEndpointV1, error) {
	context, codec, config, err := newProcessRecordCodecV1(result, planDigest, true)
	if err != nil {
		return nil, err
	}
	endpoint := &ProcessClientRecordEndpointV1{
		digest: planDigest, context: context, codec: codec,
		maxFrame: config.MaxFrameBytes, maxMessages: config.MaxSessionMessages, maxStreams: config.MaxConcurrentStreams,
		outstanding: make(map[[32]byte]processOutstandingV1),
	}
	endpoint.self = endpoint
	return endpoint, nil
}

func NewProcessRelayRecordEndpointV1(result *auth.ProcessHandshakeResultV1, planDigest [32]byte) (*ProcessRelayRecordEndpointV1, error) {
	context, codec, config, err := newProcessRecordCodecV1(result, planDigest, false)
	if err != nil {
		return nil, err
	}
	endpoint := &ProcessRelayRecordEndpointV1{
		digest: planDigest, context: context, codec: codec,
		maxFrame: config.MaxFrameBytes, maxMessages: config.MaxSessionMessages,
		seen: make(map[[32]byte]struct{}),
	}
	endpoint.self = endpoint
	return endpoint, nil
}

// ProfileBind emits the first protected post-handshake record. The TLS
// exporter is exact local carrier evidence and is never retained after sealing.
func (client *ProcessClientRecordEndpointV1) ProfileBind(tlsExporter [32]byte) ([]byte, error) {
	if client == nil || client.self != client {
		return nil, ErrSecureChannel
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || client.bound || client.bindStarted || tlsExporter == ([32]byte{}) {
		return nil, client.failLockedV1(ErrSecureChannel)
	}
	body := make([]byte, 72)
	copy(body[0:8], processBindMagicV1[:])
	copy(body[8:40], tlsExporter[:])
	copy(body[40:72], client.digest[:])
	defer clear(body)
	record, err := client.sealLockedV1(wirev1.TypeProfileBind, 0, processControlSlotV1, body)
	if err != nil {
		return nil, client.failLockedV1(err)
	}
	client.bindStarted = true
	return record, nil
}

// AcceptEngineReady proves that the relay authenticated the exact carrier and
// plan binding. Application records remain forbidden until this succeeds.
func (client *ProcessClientRecordEndpointV1) AcceptEngineReady(encoded []byte) error {
	if client == nil || client.self != client {
		return ErrSecureChannel
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || !client.bindStarted || client.bound {
		return client.failLockedV1(ErrSecureChannel)
	}
	body, capability, err := client.openLockedV1(encoded, wirev1.TypeEngineReady, 0, processControlSlotV1)
	if err != nil {
		return client.failLockedV1(err)
	}
	defer clear(body)
	if len(body) != len(processReadyMagicV1) || string(body) != string(processReadyMagicV1[:]) {
		_ = capability.Discard()
		return client.failLockedV1(ErrRecordInvalid)
	}
	if err := capability.Commit(); err != nil {
		return client.failLockedV1(err)
	}
	client.recvCount++
	client.bound = true
	return nil
}

// Seal returns a canonical wire-v1 ReliableData frame.
func (client *ProcessClientRecordEndpointV1) Seal(slot uint16, plaintext []byte) ([]byte, error) {
	if client == nil || client.self != client {
		return nil, ErrSecureChannel
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || !client.bound || slot == 0 || slot == processControlSlotV1 || len(plaintext) == 0 ||
		uint64(len(plaintext)) > uint64(client.maxFrame) || uint32(len(client.outstanding)) >= client.maxStreams {
		return nil, client.failLockedV1(ErrSecureChannel)
	}
	if client.nextOp == ^uint64(0) {
		return nil, client.failLockedV1(ErrSessionMessageLimit)
	}
	client.nextOp++
	id := operationIDV1(client.context.TranscriptHash, controlDirectionClientV1, 0, slot, client.nextOp)
	body := make([]byte, processDataFixedBytesV1+len(plaintext))
	copy(body[0:8], processDataMagicV1[:])
	copy(body[8:40], id[:])
	binary.BigEndian.PutUint32(body[40:44], uint32(len(plaintext)))
	copy(body[44:], plaintext)
	defer clear(body)
	record, err := client.sealLockedV1(wirev1.TypeReliableData, uint32(slot), slot, body)
	if err != nil {
		return nil, client.failLockedV1(err)
	}
	client.outstanding[id] = processOutstandingV1{slot: slot}
	return record, nil
}

// AcceptAck authenticates and commits the relay acknowledgement.
func (client *ProcessClientRecordEndpointV1) AcceptAck(encoded []byte) error {
	if client == nil || client.self != client {
		return ErrSecureChannel
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || !client.bound {
		return client.failLockedV1(ErrSecureChannel)
	}
	frame, envelope, err := decodeProcessRecordFrameV1(encoded, wirev1.TypeReliableData, client.digest, applicationDirectionRelayV1, client.context.MaxEnvelopeBytes)
	if err != nil {
		return client.failLockedV1(err)
	}
	defer clear(envelope.Ciphertext)
	body, capability, err := client.codec.AuthenticateApplicationV1(envelope)
	if err != nil {
		return client.failLockedV1(err)
	}
	defer clear(body)
	id, count, err := parseProcessAckV1(body)
	if err != nil {
		_ = capability.Discard()
		return client.failLockedV1(err)
	}
	outstanding, ok := client.outstanding[id]
	if !ok || frame.StreamID != uint32(outstanding.slot) || envelope.Slot != outstanding.slot || count == 0 {
		_ = capability.Discard()
		return client.failLockedV1(ErrOperationAckInvalid)
	}
	if err := capability.Commit(); err != nil {
		return client.failLockedV1(err)
	}
	delete(client.outstanding, id)
	client.recvCount++
	return nil
}

func (client *ProcessClientRecordEndpointV1) CloseRecord() ([]byte, error) {
	if client == nil || client.self != client {
		return nil, ErrSecureChannel
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closed || !client.bound {
		return nil, client.failLockedV1(ErrSecureChannel)
	}
	body := make([]byte, 10)
	copy(body[0:8], processCloseMagicV1[:])
	binary.BigEndian.PutUint16(body[8:10], CloseCodeTerminalV1)
	defer clear(body)
	record, err := client.sealLockedV1(wirev1.TypeClose, 0, processControlSlotV1, body)
	client.closeLockedV1()
	return record, err
}

func (client *ProcessClientRecordEndpointV1) Abort() {
	if client == nil || client.self != client {
		return
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.closeLockedV1()
}

// AcceptProfileBind authenticates the exact TLS exporter and plan binding
// before returning EngineReady.
func (relay *ProcessRelayRecordEndpointV1) AcceptProfileBind(encoded []byte, tlsExporter [32]byte) ([]byte, error) {
	if relay == nil || relay.self != relay {
		return nil, ErrSecureChannel
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed || relay.bound || tlsExporter == ([32]byte{}) {
		return nil, relay.failLockedV1(ErrSecureChannel)
	}
	body, capability, err := relay.openLockedV1(encoded, wirev1.TypeProfileBind, 0, processControlSlotV1)
	if err != nil {
		return nil, relay.failLockedV1(err)
	}
	defer clear(body)
	if len(body) != 72 || string(body[0:8]) != string(processBindMagicV1[:]) ||
		!equalRuntimeBytesV1(body[8:40], tlsExporter[:]) || !equalRuntimeBytesV1(body[40:72], relay.digest[:]) {
		_ = capability.Discard()
		return nil, relay.failLockedV1(ErrRecordInvalid)
	}
	if err := capability.Commit(); err != nil {
		return nil, relay.failLockedV1(err)
	}
	relay.recvCount++
	ready := append([]byte(nil), processReadyMagicV1[:]...)
	defer clear(ready)
	response, err := relay.sealLockedV1(wirev1.TypeEngineReady, 0, processControlSlotV1, ready)
	if err != nil {
		return nil, relay.failLockedV1(err)
	}
	relay.bound = true
	return response, nil
}

// Open authenticates a ReliableData frame but does not acknowledge it.
func (relay *ProcessRelayRecordEndpointV1) Open(encoded []byte) ([]byte, *ProcessRelayDeliveryV1, error) {
	if relay == nil || relay.self != relay {
		return nil, nil, ErrSecureChannel
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed || !relay.bound || relay.pending != nil {
		return nil, nil, relay.failLockedV1(ErrSecureChannel)
	}
	frame, envelope, err := decodeProcessRecordFrameV1(encoded, wirev1.TypeReliableData, relay.digest, applicationDirectionClientV1, relay.context.MaxEnvelopeBytes)
	if err != nil {
		return nil, nil, relay.failLockedV1(err)
	}
	defer clear(envelope.Ciphertext)
	body, capability, err := relay.codec.AuthenticateApplicationV1(envelope)
	if err != nil {
		return nil, nil, relay.failLockedV1(err)
	}
	defer clear(body)
	id, payload, err := parseProcessDataV1(body)
	if err != nil || frame.StreamID != uint32(envelope.Slot) || envelope.Slot == 0 || envelope.Slot == processControlSlotV1 {
		clear(payload)
		_ = capability.Discard()
		return nil, nil, relay.failLockedV1(ErrRecordInvalid)
	}
	if _, duplicate := relay.seen[id]; duplicate {
		clear(payload)
		_ = capability.Discard()
		return nil, nil, relay.failLockedV1(security.ErrReplayDuplicate)
	}
	if err := capability.Commit(); err != nil {
		clear(payload)
		return nil, nil, relay.failLockedV1(err)
	}
	relay.recvCount++
	relay.seen[id] = struct{}{}
	delivery := &ProcessRelayDeliveryV1{owner: relay, id: id, slot: envelope.Slot}
	delivery.self = delivery
	relay.pending = delivery
	return payload, delivery, nil
}

// Commit confirms successful downstream delivery and returns an authenticated
// acknowledgement. It is one-shot and bound to its creating relay endpoint.
func (delivery *ProcessRelayDeliveryV1) Commit() ([]byte, error) {
	if delivery == nil || delivery.self != delivery || delivery.owner == nil {
		return nil, ErrSecureChannel
	}
	relay := delivery.owner
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed || delivery.done || relay.pending != delivery {
		return nil, ErrSecureChannel
	}
	delivery.done = true
	relay.pending = nil
	relay.completed++
	body := make([]byte, 48)
	copy(body[0:8], processAckMagicV1[:])
	copy(body[8:40], delivery.id[:])
	binary.BigEndian.PutUint64(body[40:48], relay.completed)
	defer clear(body)
	record, err := relay.sealLockedV1(wirev1.TypeReliableData, uint32(delivery.slot), delivery.slot, body)
	if err != nil {
		return nil, relay.failLockedV1(err)
	}
	return record, nil
}

// Reject closes the relay endpoint after downstream delivery failure.
func (delivery *ProcessRelayDeliveryV1) Reject() {
	if delivery == nil || delivery.self != delivery || delivery.owner == nil {
		return
	}
	relay := delivery.owner
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if delivery.done || relay.pending != delivery {
		return
	}
	delivery.done = true
	relay.pending = nil
	relay.closeLockedV1()
}

func (relay *ProcessRelayRecordEndpointV1) AcceptClose(encoded []byte) error {
	if relay == nil || relay.self != relay {
		return ErrSecureChannel
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed || !relay.bound {
		return relay.failLockedV1(ErrSecureChannel)
	}
	body, capability, err := relay.openLockedV1(encoded, wirev1.TypeClose, 0, processControlSlotV1)
	if err != nil {
		return relay.failLockedV1(err)
	}
	defer clear(body)
	if len(body) != 10 || string(body[0:8]) != string(processCloseMagicV1[:]) ||
		binary.BigEndian.Uint16(body[8:10]) != CloseCodeTerminalV1 {
		_ = capability.Discard()
		return relay.failLockedV1(ErrRecordInvalid)
	}
	if err := capability.Commit(); err != nil {
		return relay.failLockedV1(err)
	}
	relay.closeLockedV1()
	return nil
}

func (relay *ProcessRelayRecordEndpointV1) Abort() {
	if relay == nil || relay.self != relay {
		return
	}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	relay.closeLockedV1()
}

func newProcessRecordCodecV1(result *auth.ProcessHandshakeResultV1, planDigest [32]byte, client bool) (security.EnvelopeContextV1, *security.EnvelopeCodecV1, StrictSessionConfigV1, error) {
	if result == nil || planDigest == ([32]byte{}) {
		return security.EnvelopeContextV1{}, nil, StrictSessionConfigV1{}, ErrProfileIncompatible
	}
	contextSnapshot, ok := result.ContextSnapshotV1()
	if !ok {
		return security.EnvelopeContextV1{}, nil, StrictSessionConfigV1{}, ErrProfileIncompatible
	}
	clientConfig, err := strictConfigFromContextV1(contextSnapshot, true)
	if err != nil {
		return security.EnvelopeContextV1{}, nil, StrictSessionConfigV1{}, err
	}
	relayConfig, err := strictConfigFromContextV1(contextSnapshot, false)
	if err != nil || clientConfig.MaxEnvelopeBytes != relayConfig.MaxEnvelopeBytes ||
		clientConfig.MaxFrameBytes != relayConfig.MaxFrameBytes ||
		clientConfig.MaxSessionMessages != relayConfig.MaxSessionMessages {
		return security.EnvelopeContextV1{}, nil, StrictSessionConfigV1{}, ErrProfileIncompatible
	}
	config := relayConfig
	if client {
		config = clientConfig
	}
	suite, err := strictTrafficSuiteV1(contextSnapshot.SelectedSuite)
	if err != nil {
		return security.EnvelopeContextV1{}, nil, StrictSessionConfigV1{}, err
	}
	secret, err := result.TakeChannelSecretV1()
	if err != nil {
		return security.EnvelopeContextV1{}, nil, StrictSessionConfigV1{}, err
	}
	schedule, err := security.DeriveKeyScheduleV1(security.KeyScheduleInput{
		ApplicationSecret: secret,
		TranscriptHash:    contextSnapshot.TranscriptHash[:],
		Suite:             suite,
	})
	if err != nil {
		return security.EnvelopeContextV1{}, nil, StrictSessionConfigV1{}, err
	}
	defer schedule.Destroy()
	envelopeContext := security.EnvelopeContextV1{
		EffectivePolicy: contextSnapshot.EffectivePolicy, MaxEnvelopeBytes: config.MaxEnvelopeBytes,
		EffectivePolicyHash: contextSnapshot.EffectivePolicyHash, TranscriptHash: contextSnapshot.TranscriptHash,
		CapabilityHash: contextSnapshot.SelectedCapabilityHash, ProfileHash: contextSnapshot.ClientProfileHash,
		FramingHash: contextSnapshot.ClientModeBinding.FramingPolicyHash, CarrierContextHash: contextSnapshot.ClientModeBinding.CarrierContextHash,
	}
	var codec *security.EnvelopeCodecV1
	if client {
		codec, err = security.NewClientEnvelopeV1(schedule, envelopeContext)
	} else {
		codec, err = security.NewRelayEnvelopeV1(schedule, envelopeContext)
	}
	if err != nil {
		return security.EnvelopeContextV1{}, nil, StrictSessionConfigV1{}, err
	}
	return envelopeContext, codec, config, nil
}

func (client *ProcessClientRecordEndpointV1) sealLockedV1(frameType uint8, outerStream uint32, innerSlot uint16, body []byte) ([]byte, error) {
	if client.sendCount >= client.maxMessages {
		return nil, ErrSessionMessageLimit
	}
	envelope, err := client.codec.SealApplicationV1(innerSlot, body)
	if err != nil {
		return nil, err
	}
	payload, err := encodeProcessEnvelopeV1(envelope)
	clear(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	encoded, err := wirev1.Encode(wirev1.Frame{
		Type: frameType, Flags: wirev1.FlagCritical, StreamID: outerStream,
		PlanDigest: client.digest, Payload: payload,
	})
	if err != nil {
		return nil, ErrRecordInvalid
	}
	client.sendCount++
	return encoded, nil
}

func (relay *ProcessRelayRecordEndpointV1) sealLockedV1(frameType uint8, outerStream uint32, innerSlot uint16, body []byte) ([]byte, error) {
	if relay.sendCount >= relay.maxMessages {
		return nil, ErrSessionMessageLimit
	}
	envelope, err := relay.codec.SealApplicationV1(innerSlot, body)
	if err != nil {
		return nil, err
	}
	payload, err := encodeProcessEnvelopeV1(envelope)
	clear(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	encoded, err := wirev1.Encode(wirev1.Frame{
		Type: frameType, Flags: wirev1.FlagCritical, StreamID: outerStream,
		PlanDigest: relay.digest, Payload: payload,
	})
	if err != nil {
		return nil, ErrRecordInvalid
	}
	relay.sendCount++
	return encoded, nil
}

func (client *ProcessClientRecordEndpointV1) openLockedV1(encoded []byte, frameType uint8, outerStream uint32, innerSlot uint16) ([]byte, security.AuthenticatedReplayV1, error) {
	if client.recvCount >= client.maxMessages {
		return nil, security.AuthenticatedReplayV1{}, ErrSessionMessageLimit
	}
	frame, envelope, err := decodeProcessRecordFrameV1(encoded, frameType, client.digest, applicationDirectionRelayV1, client.context.MaxEnvelopeBytes)
	if err != nil {
		return nil, security.AuthenticatedReplayV1{}, err
	}
	defer clear(envelope.Ciphertext)
	if frame.StreamID != outerStream || envelope.Slot != innerSlot {
		return nil, security.AuthenticatedReplayV1{}, ErrRecordInvalid
	}
	return client.codec.AuthenticateApplicationV1(envelope)
}

func (relay *ProcessRelayRecordEndpointV1) openLockedV1(encoded []byte, frameType uint8, outerStream uint32, innerSlot uint16) ([]byte, security.AuthenticatedReplayV1, error) {
	if relay.recvCount >= relay.maxMessages {
		return nil, security.AuthenticatedReplayV1{}, ErrSessionMessageLimit
	}
	frame, envelope, err := decodeProcessRecordFrameV1(encoded, frameType, relay.digest, applicationDirectionClientV1, relay.context.MaxEnvelopeBytes)
	if err != nil {
		return nil, security.AuthenticatedReplayV1{}, err
	}
	defer clear(envelope.Ciphertext)
	if frame.StreamID != outerStream || envelope.Slot != innerSlot {
		return nil, security.AuthenticatedReplayV1{}, ErrRecordInvalid
	}
	return relay.codec.AuthenticateApplicationV1(envelope)
}

func decodeProcessRecordFrameV1(encoded []byte, frameType uint8, digest [32]byte, direction uint16, maxEnvelope uint32) (wirev1.Frame, security.EnvelopeRecordV1, error) {
	frame, err := wirev1.Decode(encoded)
	if err != nil || frame.Type != frameType || frame.Flags != wirev1.FlagCritical || frame.PlanDigest != digest {
		clear(frame.Payload)
		return wirev1.Frame{}, security.EnvelopeRecordV1{}, ErrRecordInvalid
	}
	envelope, err := decodeProcessEnvelopeV1(frame.Payload, direction, maxEnvelope)
	clear(frame.Payload)
	frame.Payload = nil
	if err != nil {
		return wirev1.Frame{}, security.EnvelopeRecordV1{}, err
	}
	return frame, envelope, nil
}

func encodeProcessEnvelopeV1(record security.EnvelopeRecordV1) ([]byte, error) {
	if record.RecordType != RecordTypeApplicationFragmentV1 ||
		(record.Direction != applicationDirectionClientV1 && record.Direction != applicationDirectionRelayV1) ||
		record.Slot == 0 || record.SealedLength != uint32(len(record.Ciphertext)) ||
		len(record.Ciphertext) < processAEADOverheadV1 {
		return nil, ErrRecordInvalid
	}
	header := ApplicationHeaderV1{
		Version: ApplicationRecordVersionV1, Type: RecordTypeApplicationFragmentV1,
		Epoch: record.Epoch, Direction: record.Direction, StreamSlot: record.Slot,
		Sequence: record.Sequence, SealedLength: record.SealedLength,
	}
	rawHeader := encodeApplicationHeaderV1(header)
	out := make([]byte, 0, processEnvelopeHeaderBytes+len(record.Ciphertext))
	out = append(out, rawHeader[:]...)
	out = append(out, record.Ciphertext...)
	return out, nil
}

func decodeProcessEnvelopeV1(encoded []byte, direction uint16, maxEnvelope uint32) (security.EnvelopeRecordV1, error) {
	if len(encoded) < processEnvelopeHeaderBytes+processAEADOverheadV1 {
		return security.EnvelopeRecordV1{}, ErrRecordInvalid
	}
	header, err := parseApplicationHeaderV1(encoded[:processEnvelopeHeaderBytes])
	if err != nil || header.Version != ApplicationRecordVersionV1 || header.Type != RecordTypeApplicationFragmentV1 ||
		header.Direction != direction || header.StreamSlot == 0 || header.SealedLength < processAEADOverheadV1 ||
		header.SealedLength > maxEnvelope || uint64(processEnvelopeHeaderBytes)+uint64(header.SealedLength) != uint64(len(encoded)) {
		return security.EnvelopeRecordV1{}, ErrRecordInvalid
	}
	return security.EnvelopeRecordV1{
		RecordType: header.Type, Epoch: header.Epoch, Direction: header.Direction,
		Slot: header.StreamSlot, Sequence: header.Sequence, SealedLength: header.SealedLength,
		Ciphertext: append([]byte(nil), encoded[processEnvelopeHeaderBytes:]...),
	}, nil
}

func parseProcessDataV1(body []byte) ([32]byte, []byte, error) {
	if len(body) < processDataFixedBytesV1 || string(body[0:8]) != string(processDataMagicV1[:]) {
		return [32]byte{}, nil, ErrRecordInvalid
	}
	var id [32]byte
	copy(id[:], body[8:40])
	length := binary.BigEndian.Uint32(body[40:44])
	if id == ([32]byte{}) || uint64(processDataFixedBytesV1)+uint64(length) != uint64(len(body)) || length == 0 {
		return [32]byte{}, nil, ErrRecordInvalid
	}
	return id, append([]byte(nil), body[44:]...), nil
}

func parseProcessAckV1(body []byte) ([32]byte, uint64, error) {
	if len(body) != 48 || string(body[0:8]) != string(processAckMagicV1[:]) {
		return [32]byte{}, 0, ErrOperationAckInvalid
	}
	var id [32]byte
	copy(id[:], body[8:40])
	count := binary.BigEndian.Uint64(body[40:48])
	if id == ([32]byte{}) || count == 0 {
		return [32]byte{}, 0, ErrOperationAckInvalid
	}
	return id, count, nil
}

func (client *ProcessClientRecordEndpointV1) failLockedV1(err error) error {
	client.closeLockedV1()
	return normalizeProcessRecordErrorV1(err)
}

func (relay *ProcessRelayRecordEndpointV1) failLockedV1(err error) error {
	relay.closeLockedV1()
	return normalizeProcessRecordErrorV1(err)
}

func (client *ProcessClientRecordEndpointV1) closeLockedV1() {
	client.closed = true
	client.bound = false
	client.bindStarted = false
	client.codec = nil
	client.context = security.EnvelopeContextV1{}
	client.digest = [32]byte{}
	clear(client.outstanding)
}

func (relay *ProcessRelayRecordEndpointV1) closeLockedV1() {
	relay.closed = true
	relay.bound = false
	relay.codec = nil
	relay.context = security.EnvelopeContextV1{}
	relay.digest = [32]byte{}
	clear(relay.seen)
	if relay.pending != nil {
		relay.pending.done = true
		relay.pending = nil
	}
}

func normalizeProcessRecordErrorV1(err error) error {
	for _, admitted := range []error{
		ErrSecureChannel,
		ErrRecordInvalid,
		ErrOperationAckInvalid,
		ErrSessionMessageLimit,
		security.ErrAuthenticationFailed,
		security.ErrReplayDuplicate,
		security.ErrReplayStale,
		security.ErrReplayOutOfOrder,
		security.ErrReplayTooFarFuture,
		security.ErrReplayExhausted,
		security.ErrNonceMismatch,
		security.ErrNonceExhausted,
	} {
		if errors.Is(err, admitted) {
			return admitted
		}
	}
	return ErrSecureChannel
}
