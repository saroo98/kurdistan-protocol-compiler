// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"sync"

	"kurdistan/internal/crypto/auth"
)

// NetworkProtectedClientV1 exposes only complete authenticated Kurd records to
// a byte transport. It owns one endpoint of a consumed authenticated pair.
type NetworkProtectedClientV1 struct {
	self  *NetworkProtectedClientV1
	owner *networkProtectedPairV1
}

// NetworkProtectedRelayV1 exposes only complete authenticated Kurd records to
// a byte transport. It owns the opposite endpoint of the same consumed pair.
type NetworkProtectedRelayV1 struct {
	self  *NetworkProtectedRelayV1
	owner *networkProtectedPairV1
}

type networkProtectedPairV1 struct {
	mu      sync.Mutex
	channel *strictProtectedChannelV1
	client  *ClientAuthenticatedEndpointV1
	relay   *RelayAuthenticatedEndpointV1
	pending *NetworkDeliveryV1
}

// NetworkDeliveryV1 is a one-shot, pair-bound authorization to acknowledge
// one authenticated client record only after downstream delivery succeeds.
// Rejecting or abandoning delivery must terminally abort the pair.
type NetworkDeliveryV1 struct {
	self        *NetworkDeliveryV1
	owner       *networkProtectedPairV1
	operationID [32]byte
	closed      bool
}

// NewNetworkProtectedPairV1 consumes one configured authenticated pair once.
// It accepts no address, dialer, listener, codec, key, nonce, role selector, or
// restore state. The returned records remain opaque to the byte transport.
func NewNetworkProtectedPairV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) (*NetworkProtectedClientV1, *NetworkProtectedRelayV1, error) {
	if client == nil || relay == nil || client.state == nil || relay.state == nil || client.state.coordinator == nil ||
		client.state.coordinator != relay.state.coordinator {
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

	owner := &networkProtectedPairV1{channel: channel, client: client, relay: relay}
	clientEndpoint := &NetworkProtectedClientV1{owner: owner}
	relayEndpoint := &NetworkProtectedRelayV1{owner: owner}
	clientEndpoint.self = clientEndpoint
	relayEndpoint.self = relayEndpoint
	return clientEndpoint, relayEndpoint, nil
}

func (endpoint *NetworkProtectedClientV1) validV1() bool {
	return endpoint != nil && endpoint.self == endpoint && endpoint.owner != nil && endpoint.owner.channel != nil &&
		endpoint.owner.client.State() != auth.StateClosed && endpoint.owner.relay.State() != auth.StateClosed
}

func (endpoint *NetworkProtectedRelayV1) validV1() bool {
	return endpoint != nil && endpoint.self == endpoint && endpoint.owner != nil && endpoint.owner.channel != nil &&
		endpoint.owner.client.State() != auth.StateClosed && endpoint.owner.relay.State() != auth.StateClosed
}

// Seal returns a complete opaque client-to-relay Kurd record.
func (endpoint *NetworkProtectedClientV1) Seal(slot uint16, plaintext []byte) ([]byte, error) {
	if !endpoint.validV1() {
		return nil, ErrSecureChannel
	}
	record, _, err := endpoint.owner.channel.sealClientApplicationV1(slot, plaintext)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), record...), nil
}

// Open authenticates one complete client record before returning plaintext and
// a one-shot delivery authorization. It never acknowledges receipt by itself.
func (endpoint *NetworkProtectedRelayV1) Open(record []byte) ([]byte, *NetworkDeliveryV1, error) {
	if !endpoint.validV1() || len(record) == 0 {
		return nil, nil, ErrSecureChannel
	}
	owned := append([]byte(nil), record...)
	defer clear(owned)
	endpoint.owner.mu.Lock()
	defer endpoint.owner.mu.Unlock()
	if endpoint.owner.pending != nil {
		return nil, nil, ErrSecureChannel
	}
	payload, ack, err := endpoint.owner.channel.openClientApplicationV1(owned)
	if err != nil || payload == nil {
		return nil, nil, err
	}
	delivery := &NetworkDeliveryV1{owner: endpoint.owner, operationID: ack.OperationID}
	delivery.self = delivery
	endpoint.owner.pending = delivery
	return payload, delivery, nil
}

// Commit records successful downstream delivery and returns the authenticated
// acknowledgement. It is valid exactly once and only for its creating pair.
func (delivery *NetworkDeliveryV1) Commit() ([]byte, error) {
	if delivery == nil || delivery.self != delivery || delivery.owner == nil {
		return nil, ErrSecureChannel
	}
	owner := delivery.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if delivery.closed || owner.pending != delivery {
		return nil, ErrSecureChannel
	}
	delivery.closed = true
	owner.pending = nil
	record, err := owner.channel.sealRelayAckV1(delivery.operationID, false)
	if err != nil {
		owner.relay.Close()
		return nil, err
	}
	return append([]byte(nil), record...), nil
}

// Reject terminally aborts the pair after downstream delivery failure.
func (delivery *NetworkDeliveryV1) Reject() {
	if delivery == nil || delivery.self != delivery || delivery.owner == nil {
		return
	}
	owner := delivery.owner
	owner.mu.Lock()
	if delivery.closed || owner.pending != delivery {
		owner.mu.Unlock()
		return
	}
	delivery.closed = true
	owner.pending = nil
	owner.mu.Unlock()
	owner.relay.Close()
}

// AcceptAck authenticates and commits one relay acknowledgement.
func (endpoint *NetworkProtectedClientV1) AcceptAck(record []byte) error {
	if !endpoint.validV1() || len(record) == 0 {
		return ErrSecureChannel
	}
	owned := append([]byte(nil), record...)
	defer clear(owned)
	return endpoint.owner.channel.openRelayAckV1(owned)
}

// CloseRecord creates the terminal authenticated client close record.
func (endpoint *NetworkProtectedClientV1) CloseRecord() ([]byte, error) {
	if !endpoint.validV1() {
		return nil, ErrSecureChannel
	}
	record, err := endpoint.owner.channel.sealClientCloseV1()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), record...), nil
}

// AcceptClose authenticates a client close record and terminally closes both
// endpoints. Invalid close records also fail the pair closed.
func (endpoint *NetworkProtectedRelayV1) AcceptClose(record []byte) error {
	if endpoint == nil || endpoint.self != endpoint || endpoint.owner == nil || len(record) == 0 {
		return ErrSecureChannel
	}
	owned := append([]byte(nil), record...)
	defer clear(owned)
	return endpoint.owner.channel.openClientCloseV1(owned)
}

// Abort terminally destroys the pair after a carrier or downstream failure.
func (endpoint *NetworkProtectedClientV1) Abort() {
	if endpoint != nil && endpoint.self == endpoint && endpoint.owner != nil && endpoint.owner.client != nil {
		endpoint.owner.client.Close()
	}
}

// Abort terminally destroys the pair after a carrier or downstream failure.
func (endpoint *NetworkProtectedRelayV1) Abort() {
	if endpoint != nil && endpoint.self == endpoint && endpoint.owner != nil && endpoint.owner.relay != nil {
		endpoint.owner.relay.Close()
	}
}
