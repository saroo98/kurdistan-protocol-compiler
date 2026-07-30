// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"encoding/binary"
	"math"
	"sync"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/runtime/labfault"
)

// InProcessProtectedRecordV1 is an opaque, pair-bound protected record. It has
// no address or transport material and is useful only with its opposite role.
type InProcessProtectedRecordV1 struct {
	owner     *inProcessProtectedRelayV1
	direction uint8
	record    []byte
}

// InProcessProtectedAckV1 is an opaque, pair-bound authenticated Ack record.
type InProcessProtectedAckV1 struct {
	owner  *inProcessProtectedRelayV1
	record []byte
}

type InProcessProtectedClientV1 struct {
	self  *InProcessProtectedClientV1
	owner *inProcessProtectedRelayV1
}

type InProcessProtectedRelayV1 struct {
	self  *InProcessProtectedRelayV1
	owner *inProcessProtectedRelayV1
}

type inProcessProtectedRelayV1 struct {
	mu         sync.Mutex
	channel    *strictProtectedChannelV1
	client     *ClientAuthenticatedEndpointV1
	relay      *RelayAuthenticatedEndpointV1
	seamBytes  uint64
	sinkBytes  uint64
	lastSeam   []byte
	labPadding bool
}

var consumedProtectedPairsV1 sync.Map

// NewInProcessProtectedRelay consumes one configured authenticated pair once.
// It is strictly in-process: it accepts no address, listener, dialer, secret,
// codec, nonce, key, role selector, or restore state.
func NewInProcessProtectedRelay(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) (*InProcessProtectedClientV1, *InProcessProtectedRelayV1, error) {
	return newInProcessProtectedRelayCoreV1(client, relay, false)
}

func newInProcessProtectedRelayWithLabFaultV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, token labfault.Token) (*InProcessProtectedClientV1, *InProcessProtectedRelayV1, error) {
	want, _ := labfault.NewTokenV1("runtime_padding_only_diversity")
	if token != want {
		return nil, nil, ErrSecureChannel
	}
	return newInProcessProtectedRelayCoreV1(client, relay, true)
}

func newInProcessProtectedRelayCoreV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, labPadding bool) (*InProcessProtectedClientV1, *InProcessProtectedRelayV1, error) {
	if client == nil || relay == nil || client.state == nil || relay.state == nil || client.state.coordinator == nil || client.state.coordinator != relay.state.coordinator {
		return nil, nil, ErrSecureChannel
	}
	coordinator := client.state.coordinator
	if _, loaded := consumedProtectedPairsV1.LoadOrStore(coordinator, struct{}{}); loaded {
		return nil, nil, ErrSecureChannel
	}
	channel, err := newStrictProtectedChannelV1(client, relay)
	if err != nil {
		consumedProtectedPairsV1.Delete(coordinator)
		return nil, nil, err
	}
	coordinator.mu.Lock()
	previousDestroy := coordinator.destroy
	coordinator.destroy = func() {
		consumedProtectedPairsV1.Delete(coordinator)
		if previousDestroy != nil {
			previousDestroy()
		}
	}
	coordinator.mu.Unlock()
	owner := &inProcessProtectedRelayV1{channel: channel, client: client, relay: relay, labPadding: labPadding}
	clientEndpoint := &InProcessProtectedClientV1{owner: owner}
	relayEndpoint := &InProcessProtectedRelayV1{owner: owner}
	clientEndpoint.self = clientEndpoint
	relayEndpoint.self = relayEndpoint
	return clientEndpoint, relayEndpoint, nil
}

func (endpoint *InProcessProtectedClientV1) wrapWithPaddingV1(record InProcessProtectedRecordV1, padding []byte) (InProcessProtectedRecordV1, error) {
	if !endpoint.validV1() || !endpoint.owner.labPadding || record.owner != endpoint.owner || record.direction != 1 || len(record.record) == 0 || len(padding) == 0 {
		return InProcessProtectedRecordV1{}, ErrRecordInvalid
	}
	recordLen, paddingLen := uint64(len(record.record)), uint64(len(padding))
	total := uint64(8) + recordLen + paddingLen
	if recordLen > math.MaxUint32 || paddingLen > math.MaxUint32 || total > uint64(endpoint.owner.client.state.config.MaxFrameBytes) {
		return InProcessProtectedRecordV1{}, ErrRecordInvalid
	}
	out := make([]byte, int(total))
	binary.BigEndian.PutUint32(out[:4], uint32(recordLen))
	copy(out[4:4+recordLen], record.record)
	offset := 4 + recordLen
	binary.BigEndian.PutUint32(out[offset:offset+4], uint32(paddingLen))
	copy(out[offset+4:], padding)
	return InProcessProtectedRecordV1{owner: endpoint.owner, direction: 1, record: out}, nil
}

func clearPaddingFaultRecordV1(record *InProcessProtectedRecordV1) {
	if record != nil {
		clear(record.record)
		record.record = nil
		record.owner = nil
		record.direction = 0
	}
}

func (endpoint *InProcessProtectedClientV1) validV1() bool {
	return endpoint != nil && endpoint.self == endpoint && endpoint.owner != nil && endpoint.owner.channel != nil &&
		endpoint.owner.client.State() != auth.StateClosed && endpoint.owner.relay.State() != auth.StateClosed
}

func (endpoint *InProcessProtectedRelayV1) validV1() bool {
	return endpoint != nil && endpoint.self == endpoint && endpoint.owner != nil && endpoint.owner.channel != nil &&
		endpoint.owner.client.State() != auth.StateClosed && endpoint.owner.relay.State() != auth.StateClosed
}

func (endpoint *InProcessProtectedClientV1) Seal(slot uint16, plaintext []byte) (InProcessProtectedRecordV1, error) {
	if !endpoint.validV1() {
		return InProcessProtectedRecordV1{}, ErrSecureChannel
	}
	record, _, err := endpoint.owner.channel.sealClientApplicationV1(slot, plaintext)
	if err != nil {
		return InProcessProtectedRecordV1{}, err
	}
	return InProcessProtectedRecordV1{owner: endpoint.owner, direction: 1, record: record}, nil
}

func (endpoint *InProcessProtectedClientV1) SealFragments(slot uint16, plaintext []byte, fragmentLengths []uint32) ([]InProcessProtectedRecordV1, error) {
	if !endpoint.validV1() {
		return nil, ErrSecureChannel
	}
	records, _, err := endpoint.owner.channel.sealClientMultiFragmentV1(slot, plaintext, fragmentLengths)
	if err != nil {
		return nil, err
	}
	out := make([]InProcessProtectedRecordV1, len(records))
	for index, record := range records {
		out[index] = InProcessProtectedRecordV1{owner: endpoint.owner, direction: 1, record: record}
	}
	return out, nil
}

func (endpoint *InProcessProtectedRelayV1) Deliver(record InProcessProtectedRecordV1) ([]byte, InProcessProtectedAckV1, error) {
	if endpoint != nil && endpoint.owner != nil && endpoint.owner.labPadding {
		if !endpoint.validV1() || record.owner != endpoint.owner || record.direction != 1 {
			clearPaddingFaultRecordV1(&record)
			return nil, InProcessProtectedAckV1{}, ErrRecordInvalid
		}
		inner, err := endpoint.owner.unwrapPaddingFaultRecordV1(record.record)
		clearPaddingFaultRecordV1(&record)
		if err != nil {
			return nil, InProcessProtectedAckV1{}, ErrRecordInvalid
		}
		record = InProcessProtectedRecordV1{owner: endpoint.owner, direction: 1, record: inner}
	}
	if !endpoint.validV1() || record.owner != endpoint.owner || record.direction != 1 || len(record.record) == 0 {
		return nil, InProcessProtectedAckV1{}, ErrSecureChannel
	}
	endpoint.owner.mu.Lock()
	clear(endpoint.owner.lastSeam)
	endpoint.owner.lastSeam = append([]byte(nil), record.record...)
	endpoint.owner.seamBytes += uint64(len(record.record))
	endpoint.owner.mu.Unlock()
	payload, ack, err := endpoint.owner.channel.openClientApplicationV1(record.record)
	if err != nil || payload == nil {
		return nil, InProcessProtectedAckV1{}, err
	}
	ackRecord, err := endpoint.owner.channel.sealRelayAckV1(ack.OperationID, false)
	if err != nil {
		clear(payload)
		return nil, InProcessProtectedAckV1{}, err
	}
	endpoint.owner.mu.Lock()
	endpoint.owner.sinkBytes += uint64(len(payload))
	endpoint.owner.mu.Unlock()
	return payload, InProcessProtectedAckV1{owner: endpoint.owner, record: ackRecord}, nil
}

func (owner *inProcessProtectedRelayV1) unwrapPaddingFaultRecordV1(wrapper []byte) ([]byte, error) {
	max := uint64(owner.client.state.config.MaxFrameBytes)
	size := uint64(len(wrapper))
	if size < 8 || size > max {
		return nil, ErrRecordInvalid
	}
	recordLen := uint64(binary.BigEndian.Uint32(wrapper[:4]))
	if recordLen == 0 || 4+recordLen+4 > size {
		return nil, ErrRecordInvalid
	}
	offset := 4 + recordLen
	paddingLen := uint64(binary.BigEndian.Uint32(wrapper[offset : offset+4]))
	total := offset + 4 + paddingLen
	if paddingLen == 0 || total > max || total != size {
		return nil, ErrRecordInvalid
	}
	return append([]byte(nil), wrapper[4:4+recordLen]...), nil
}

func (endpoint *InProcessProtectedClientV1) AcceptAck(ack InProcessProtectedAckV1) error {
	if !endpoint.validV1() || ack.owner != endpoint.owner || len(ack.record) == 0 {
		return ErrSecureChannel
	}
	return endpoint.owner.channel.openRelayAckV1(ack.record)
}

func (endpoint *InProcessProtectedClientV1) Close() (InProcessProtectedRecordV1, error) {
	if !endpoint.validV1() {
		return InProcessProtectedRecordV1{}, ErrSecureChannel
	}
	record, err := endpoint.owner.channel.sealClientCloseV1()
	if err != nil {
		return InProcessProtectedRecordV1{}, err
	}
	return InProcessProtectedRecordV1{owner: endpoint.owner, direction: 1, record: record}, nil
}

func (endpoint *InProcessProtectedRelayV1) AcceptClose(record InProcessProtectedRecordV1) error {
	if endpoint == nil || endpoint.self != endpoint || endpoint.owner == nil || record.owner != endpoint.owner || record.direction != 1 || len(record.record) == 0 {
		return ErrSecureChannel
	}
	return endpoint.owner.channel.openClientCloseV1(record.record)
}
