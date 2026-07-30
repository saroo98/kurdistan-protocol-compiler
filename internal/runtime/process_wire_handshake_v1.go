// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/protocol/wirev1"
)

// ProcessWireClientHandshakeV1 binds the role-separated authenticated client
// handshake to one immutable session-plan digest and canonical wire-v1 frames.
type ProcessWireClientHandshakeV1 struct {
	self   *ProcessWireClientHandshakeV1
	digest [32]byte
	auth   *auth.ClientProcessHandshakeV1
}

// ProcessWireRelayHandshakeV1 binds the role-separated authenticated relay
// handshake to the same immutable session-plan digest.
type ProcessWireRelayHandshakeV1 struct {
	self   *ProcessWireRelayHandshakeV1
	digest [32]byte
	auth   *auth.RelayProcessHandshakeV1
}

func NewProcessWireClientHandshakeV1(config auth.ProcessHandshakeConfigV1, dependencies auth.Dependencies, planDigest [32]byte) (*ProcessWireClientHandshakeV1, error) {
	if planDigest == ([32]byte{}) {
		return nil, ErrProfileIncompatible
	}
	handshake, err := auth.NewClientProcessHandshakeV1(config, dependencies)
	if err != nil {
		return nil, err
	}
	result := &ProcessWireClientHandshakeV1{digest: planDigest, auth: handshake}
	result.self = result
	return result, nil
}

func NewProcessWireRelayHandshakeV1(config auth.ProcessHandshakeConfigV1, dependencies auth.Dependencies, replay *auth.HandshakeReplayCache, planDigest [32]byte) (*ProcessWireRelayHandshakeV1, error) {
	if planDigest == ([32]byte{}) {
		return nil, ErrProfileIncompatible
	}
	handshake, err := auth.NewRelayProcessHandshakeV1(config, dependencies, replay)
	if err != nil {
		return nil, err
	}
	result := &ProcessWireRelayHandshakeV1{digest: planDigest, auth: handshake}
	result.self = result
	return result, nil
}

func (client *ProcessWireClientHandshakeV1) Start() ([]byte, error) {
	if !client.validV1() {
		return nil, ErrSecureChannel
	}
	message, err := client.auth.Start()
	if err != nil {
		client.Close()
		return nil, err
	}
	return encodeProcessHandshakeFrameV1(wirev1.TypeClientHello, client.digest, message)
}

func (relay *ProcessWireRelayHandshakeV1) AcceptClientHello(encoded []byte) ([]byte, error) {
	if !relay.validV1() {
		return nil, ErrSecureChannel
	}
	message, err := decodeProcessHandshakeFrameV1(encoded, wirev1.TypeClientHello, relay.digest)
	if err != nil {
		relay.Close()
		return nil, err
	}
	defer clear(message)
	response, err := relay.auth.AcceptClientHello(message)
	if err != nil {
		relay.Close()
		return nil, err
	}
	return encodeProcessHandshakeFrameV1(wirev1.TypeServerHello, relay.digest, response)
}

func (client *ProcessWireClientHandshakeV1) AcceptServerHello(encoded []byte) ([]byte, error) {
	if !client.validV1() {
		return nil, ErrSecureChannel
	}
	message, err := decodeProcessHandshakeFrameV1(encoded, wirev1.TypeServerHello, client.digest)
	if err != nil {
		client.Close()
		return nil, err
	}
	defer clear(message)
	response, err := client.auth.AcceptServerHello(message)
	if err != nil {
		client.Close()
		return nil, err
	}
	return encodeProcessHandshakeFrameV1(wirev1.TypeClientFinish, client.digest, response)
}

func (relay *ProcessWireRelayHandshakeV1) AcceptClientFinish(encoded []byte) ([]byte, *auth.ProcessHandshakeResultV1, error) {
	if !relay.validV1() {
		return nil, nil, ErrSecureChannel
	}
	message, err := decodeProcessHandshakeFrameV1(encoded, wirev1.TypeClientFinish, relay.digest)
	if err != nil {
		relay.Close()
		return nil, nil, err
	}
	defer clear(message)
	response, result, err := relay.auth.AcceptClientFinish(message)
	if err != nil {
		relay.Close()
		return nil, nil, err
	}
	encodedResponse, err := encodeProcessHandshakeFrameV1(wirev1.TypeServerFinish, relay.digest, response)
	if err != nil {
		result.Close()
		relay.Close()
		return nil, nil, err
	}
	relay.Close()
	return encodedResponse, result, nil
}

func (client *ProcessWireClientHandshakeV1) AcceptServerFinish(encoded []byte) (*auth.ProcessHandshakeResultV1, error) {
	if !client.validV1() {
		return nil, ErrSecureChannel
	}
	message, err := decodeProcessHandshakeFrameV1(encoded, wirev1.TypeServerFinish, client.digest)
	if err != nil {
		client.Close()
		return nil, err
	}
	defer clear(message)
	result, err := client.auth.AcceptServerFinish(message)
	client.Close()
	return result, err
}

func (client *ProcessWireClientHandshakeV1) Close() {
	if client == nil || client.self != client {
		return
	}
	if client.auth != nil {
		client.auth.Close()
	}
	client.auth = nil
	client.digest = [32]byte{}
	client.self = nil
}

func (relay *ProcessWireRelayHandshakeV1) Close() {
	if relay == nil || relay.self != relay {
		return
	}
	if relay.auth != nil {
		relay.auth.Close()
	}
	relay.auth = nil
	relay.digest = [32]byte{}
	relay.self = nil
}

func (client *ProcessWireClientHandshakeV1) validV1() bool {
	return client != nil && client.self == client && client.auth != nil && client.digest != ([32]byte{})
}

func (relay *ProcessWireRelayHandshakeV1) validV1() bool {
	return relay != nil && relay.self == relay && relay.auth != nil && relay.digest != ([32]byte{})
}

func encodeProcessHandshakeFrameV1(frameType uint8, digest [32]byte, message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, ErrRecordInvalid
	}
	encoded, err := wirev1.Encode(wirev1.Frame{
		Type:       frameType,
		Flags:      wirev1.FlagCritical,
		PlanDigest: digest,
		Payload:    append([]byte(nil), message...),
	})
	if err != nil {
		return nil, ErrRecordInvalid
	}
	return encoded, nil
}

func decodeProcessHandshakeFrameV1(encoded []byte, frameType uint8, digest [32]byte) ([]byte, error) {
	frame, err := wirev1.Decode(encoded)
	if err != nil || frame.Type != frameType || frame.Flags != wirev1.FlagCritical ||
		frame.StreamID != 0 || frame.PlanDigest != digest || len(frame.Payload) == 0 {
		clear(frame.Payload)
		return nil, ErrRecordInvalid
	}
	return frame.Payload, nil
}
