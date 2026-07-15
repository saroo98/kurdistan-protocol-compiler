// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
)

type NonceManager struct {
	mu        sync.Mutex
	Direction string
	Base      []byte
	Counter   uint64
	Mode      string
}

func NewNonceManager(direction string, base []byte, mode string) *NonceManager {
	cp := append([]byte(nil), base...)
	if len(cp) != 12 {
		sum := sha256.Sum256(cp)
		cp = append([]byte(nil), sum[:12]...)
	}
	if mode == "" {
		mode = "directional_counter"
	}
	return &NonceManager{Direction: direction, Base: cp, Mode: mode}
}

func (n *NonceManager) Next() ([]byte, uint64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.Counter == math.MaxUint64 {
		return nil, 0, ErrNonceOverflow
	}
	n.Counter++
	nonce, err := n.nonceForLocked(n.Counter)
	if err != nil {
		return nil, 0, err
	}
	return nonce, n.Counter, nil
}

func (n *NonceManager) SetCounterForTest(counter uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Counter = counter
}

func (n *NonceManager) nonceForLocked(seq uint64) ([]byte, error) {
	switch n.Mode {
	case "counter_xor_base", "directional_counter", "stream_partitioned_counter":
		out := append([]byte(nil), n.Base...)
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], seq)
		for i := 0; i < 8; i++ {
			out[len(out)-8+i] ^= buf[i]
		}
		if n.Direction == "server" {
			out[0] ^= 0x80
		}
		return out, nil
	case "counter_append_base":
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], seq)
		sum := sha256.Sum256(append(append([]byte(n.Direction+"/"), n.Base...), buf[:]...))
		return append([]byte(nil), sum[:12]...), nil
	default:
		return nil, fmt.Errorf("%w: unknown nonce mode %q", ErrInvalidConfig, n.Mode)
	}
}

const (
	DirectionClientToRelayV1 uint16 = 0x0001
	DirectionRelayToClientV1 uint16 = 0x0002
)

const (
	NonceModeCounterXORBaseV1           = "counter_xor_base"
	NonceModeCounterAppendBaseV1        = "counter_append_base"
	NonceModeDirectionalCounterV1       = "directional_counter"
	NonceModeStreamPartitionedCounterV1 = "stream_partitioned_counter"
)

const nonceBytesV1 = 12

type nonceRecordClassV1 uint8

const (
	nonceControlRecordV1 nonceRecordClassV1 = iota + 1
	nonceApplicationRecordV1
)

// NonceAllocationV1 is a value-only result. Its nonce does not alias owner
// state. One owner binds exactly one key epoch and its two role-fixed bases.
type NonceAllocationV1 struct {
	Nonce     [nonceBytesV1]byte
	Sequence  uint64
	Epoch     uint64
	Direction uint16
	Slot      uint16
}

type nonceDirectionConfigV1 struct {
	base      [nonceBytesV1]byte
	mode      string
	epoch     uint64
	direction uint16
}

type nonceSequenceStateV1 struct {
	next      uint64
	exhausted bool
}

type nonceDirectionStateV1 struct {
	mu        sync.Mutex
	config    nonceDirectionConfigV1
	sequences map[uint16]nonceSequenceStateV1
}

// ClientNonceOwnerV1 fixes client outbound to c2s and expected inbound to s2c.
type ClientNonceOwnerV1 struct {
	outbound *nonceDirectionStateV1
	inbound  nonceDirectionConfigV1
}

// RelayNonceOwnerV1 fixes relay outbound to s2c and expected inbound to c2s.
type RelayNonceOwnerV1 struct {
	outbound *nonceDirectionStateV1
	inbound  nonceDirectionConfigV1
}

func NewClientNonceOwnerV1(schedule KeySchedule, mode string) (*ClientNonceOwnerV1, error) {
	material, err := nonceOwnerMaterialFromScheduleV1(schedule, mode)
	if err != nil {
		return nil, err
	}
	outbound, err := newNonceDirectionStateV1(material.epoch, DirectionClientToRelayV1, material.clientToRelay[:], mode)
	if err != nil {
		return nil, ErrNonceMismatch
	}
	inbound, err := newNonceDirectionConfigV1(material.epoch, DirectionRelayToClientV1, material.relayToClient[:], mode)
	if err != nil {
		return nil, ErrNonceMismatch
	}
	return &ClientNonceOwnerV1{outbound: outbound, inbound: inbound}, nil
}

func NewRelayNonceOwnerV1(schedule KeySchedule, mode string) (*RelayNonceOwnerV1, error) {
	material, err := nonceOwnerMaterialFromScheduleV1(schedule, mode)
	if err != nil {
		return nil, err
	}
	outbound, err := newNonceDirectionStateV1(material.epoch, DirectionRelayToClientV1, material.relayToClient[:], mode)
	if err != nil {
		return nil, ErrNonceMismatch
	}
	inbound, err := newNonceDirectionConfigV1(material.epoch, DirectionClientToRelayV1, material.clientToRelay[:], mode)
	if err != nil {
		return nil, ErrNonceMismatch
	}
	return &RelayNonceOwnerV1{outbound: outbound, inbound: inbound}, nil
}

type nonceOwnerMaterialV1 struct {
	epoch         uint64
	clientToRelay [nonceBytesV1]byte
	relayToClient [nonceBytesV1]byte
}

func nonceOwnerMaterialFromScheduleV1(schedule KeySchedule, mode string) (nonceOwnerMaterialV1, error) {
	// Mode is deliberately checked first so policy errors take precedence over
	// schedule provenance failures.
	if err := validateNonceModeV1(mode); err != nil {
		return nonceOwnerMaterialV1{}, err
	}
	if err := validateRatchetSourceV1(schedule); err != nil {
		return nonceOwnerMaterialV1{}, ErrNonceMismatch
	}
	var material nonceOwnerMaterialV1
	material.epoch = schedule.Epoch
	copy(material.clientToRelay[:], schedule.ClientNonceBase)
	copy(material.relayToClient[:], schedule.ServerNonceBase)
	return material, nil
}

func (o *ClientNonceOwnerV1) OutboundDirectionV1() uint16 {
	if o == nil || o.outbound == nil {
		return 0
	}
	return o.outbound.config.direction
}

func (o *ClientNonceOwnerV1) InboundDirectionV1() uint16 {
	if o == nil {
		return 0
	}
	return o.inbound.direction
}

func (o *RelayNonceOwnerV1) OutboundDirectionV1() uint16 {
	if o == nil || o.outbound == nil {
		return 0
	}
	return o.outbound.config.direction
}

func (o *RelayNonceOwnerV1) InboundDirectionV1() uint16 {
	if o == nil {
		return 0
	}
	return o.inbound.direction
}

func (o *ClientNonceOwnerV1) AllocateOutboundControlV1() (NonceAllocationV1, error) {
	if o == nil || o.outbound == nil {
		return NonceAllocationV1{}, ErrNonceMismatch
	}
	return o.outbound.allocateV1(nonceControlRecordV1, 0)
}

func (o *ClientNonceOwnerV1) AllocateOutboundApplicationV1(slot uint16) (NonceAllocationV1, error) {
	if o == nil || o.outbound == nil {
		return NonceAllocationV1{}, ErrNonceMismatch
	}
	return o.outbound.allocateV1(nonceApplicationRecordV1, slot)
}

func (o *ClientNonceOwnerV1) ExpectedInboundControlV1(sequence uint64) ([nonceBytesV1]byte, error) {
	if o == nil {
		return [nonceBytesV1]byte{}, ErrNonceMismatch
	}
	return o.inbound.expectedV1(nonceControlRecordV1, 0, sequence)
}

func (o *ClientNonceOwnerV1) ExpectedInboundApplicationV1(slot uint16, sequence uint64) ([nonceBytesV1]byte, error) {
	if o == nil {
		return [nonceBytesV1]byte{}, ErrNonceMismatch
	}
	return o.inbound.expectedV1(nonceApplicationRecordV1, slot, sequence)
}

func (o *RelayNonceOwnerV1) AllocateOutboundControlV1() (NonceAllocationV1, error) {
	if o == nil || o.outbound == nil {
		return NonceAllocationV1{}, ErrNonceMismatch
	}
	return o.outbound.allocateV1(nonceControlRecordV1, 0)
}

func (o *RelayNonceOwnerV1) AllocateOutboundApplicationV1(slot uint16) (NonceAllocationV1, error) {
	if o == nil || o.outbound == nil {
		return NonceAllocationV1{}, ErrNonceMismatch
	}
	return o.outbound.allocateV1(nonceApplicationRecordV1, slot)
}

func (o *RelayNonceOwnerV1) ExpectedInboundControlV1(sequence uint64) ([nonceBytesV1]byte, error) {
	if o == nil {
		return [nonceBytesV1]byte{}, ErrNonceMismatch
	}
	return o.inbound.expectedV1(nonceControlRecordV1, 0, sequence)
}

func (o *RelayNonceOwnerV1) ExpectedInboundApplicationV1(slot uint16, sequence uint64) ([nonceBytesV1]byte, error) {
	if o == nil {
		return [nonceBytesV1]byte{}, ErrNonceMismatch
	}
	return o.inbound.expectedV1(nonceApplicationRecordV1, slot, sequence)
}

func newNonceDirectionStateV1(epoch uint64, direction uint16, base []byte, mode string) (*nonceDirectionStateV1, error) {
	config, err := newNonceDirectionConfigV1(epoch, direction, base, mode)
	if err != nil {
		return nil, err
	}
	return &nonceDirectionStateV1{config: config, sequences: make(map[uint16]nonceSequenceStateV1)}, nil
}

func newNonceDirectionConfigV1(epoch uint64, direction uint16, base []byte, mode string) (nonceDirectionConfigV1, error) {
	if err := validateDirectionV1(direction); err != nil {
		return nonceDirectionConfigV1{}, err
	}
	if len(base) != nonceBytesV1 {
		return nonceDirectionConfigV1{}, ErrNonceMismatch
	}
	if err := validateNonceModeV1(mode); err != nil {
		return nonceDirectionConfigV1{}, err
	}
	var fixed [nonceBytesV1]byte
	copy(fixed[:], base)
	return nonceDirectionConfigV1{base: fixed, mode: mode, epoch: epoch, direction: direction}, nil
}

func validateDirectionV1(direction uint16) error {
	if direction != DirectionClientToRelayV1 && direction != DirectionRelayToClientV1 {
		return ErrNonceMismatch
	}
	return nil
}

func validateNonceModeV1(mode string) error {
	switch mode {
	case NonceModeCounterXORBaseV1, NonceModeCounterAppendBaseV1,
		NonceModeDirectionalCounterV1, NonceModeStreamPartitionedCounterV1:
		return nil
	default:
		return ErrPolicyInvalid
	}
}

func validateNonceSlotV1(class nonceRecordClassV1, slot uint16) error {
	switch class {
	case nonceControlRecordV1:
		if slot != 0 {
			return ErrNonceMismatch
		}
	case nonceApplicationRecordV1:
		if slot == 0 {
			return ErrNonceMismatch
		}
	default:
		return ErrNonceMismatch
	}
	return nil
}

func (s *nonceDirectionStateV1) allocateV1(class nonceRecordClassV1, slot uint16) (NonceAllocationV1, error) {
	if s == nil {
		return NonceAllocationV1{}, ErrNonceMismatch
	}
	if err := s.config.validateV1(); err != nil {
		return NonceAllocationV1{}, err
	}
	if err := validateNonceSlotV1(class, slot); err != nil {
		return NonceAllocationV1{}, err
	}

	stateSlot := uint16(0)
	if s.config.mode == NonceModeStreamPartitionedCounterV1 {
		stateSlot = slot
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.sequences[stateSlot]
	if state.exhausted {
		return NonceAllocationV1{}, ErrNonceExhausted
	}
	sequence := state.next
	if sequence == math.MaxUint64 {
		state.exhausted = true
	} else {
		state.next++
	}
	s.sequences[stateSlot] = state

	nonce, err := deriveNonceV1(s.config, slot, sequence)
	if err != nil {
		return NonceAllocationV1{}, err
	}
	return NonceAllocationV1{
		Nonce: nonce, Sequence: sequence, Epoch: s.config.epoch,
		Direction: s.config.direction, Slot: slot,
	}, nil
}

func (c nonceDirectionConfigV1) validateV1() error {
	if err := validateDirectionV1(c.direction); err != nil {
		return err
	}
	return validateNonceModeV1(c.mode)
}

func (c nonceDirectionConfigV1) expectedV1(class nonceRecordClassV1, slot uint16, sequence uint64) ([nonceBytesV1]byte, error) {
	if err := c.validateV1(); err != nil {
		return [nonceBytesV1]byte{}, err
	}
	if err := validateNonceSlotV1(class, slot); err != nil {
		return [nonceBytesV1]byte{}, err
	}
	return deriveNonceV1(c, slot, sequence)
}

func deriveNonceV1(config nonceDirectionConfigV1, slot uint16, sequence uint64) ([nonceBytesV1]byte, error) {
	if err := config.validateV1(); err != nil {
		return [nonceBytesV1]byte{}, err
	}
	var out [nonceBytesV1]byte
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], sequence)
	switch config.mode {
	case NonceModeCounterXORBaseV1:
		copy(out[:4], config.base[:4])
		for i := range encoded {
			out[4+i] = config.base[4+i] ^ encoded[i]
		}
	case NonceModeCounterAppendBaseV1:
		copy(out[:8], encoded[:])
		copy(out[8:], config.base[:4])
	case NonceModeDirectionalCounterV1:
		copy(out[:4], config.base[:4])
		copy(out[4:], encoded[:])
	case NonceModeStreamPartitionedCounterV1:
		copy(out[:2], config.base[:2])
		binary.BigEndian.PutUint16(out[2:4], slot)
		for i := range encoded {
			out[4+i] = config.base[4+i] ^ encoded[i]
		}
	default:
		return [nonceBytesV1]byte{}, ErrPolicyInvalid
	}
	return out, nil
}
