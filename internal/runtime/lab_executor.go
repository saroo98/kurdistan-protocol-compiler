// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/runtime/labfault"
)

type RuntimeLabFaultObservationV1 struct {
	UnsafeObserved bool
	Count          uint32
	Category       string
}

type runtimeLabFaultModeV1 uint8

const (
	runtimeLabReusedNonceV1 runtimeLabFaultModeV1 = iota + 1
	runtimeLabAcceptsReplayV1
	runtimeLabAcceptsRuntimeReplayV1
	runtimeLabNoStateValidationV1
	runtimeLabSecretTraceV1
	runtimeLabRuntimeSecretTraceV1
	runtimeLabRuntimePayloadTraceV1
	runtimeLabIgnoresBackpressureV1
	runtimeLabPaddingDiversityV1
)

func classifyRuntimeLabFaultV1(token labfault.Token) (runtimeLabFaultModeV1, bool) {
	if expected, _ := labfault.NewTokenV1("reused_nonce"); token == expected {
		return runtimeLabReusedNonceV1, true
	}
	if expected, _ := labfault.NewTokenV1("accepts_replay"); token == expected {
		return runtimeLabAcceptsReplayV1, true
	}
	if expected, _ := labfault.NewTokenV1("runtime_accepts_replay"); token == expected {
		return runtimeLabAcceptsRuntimeReplayV1, true
	}
	if expected, _ := labfault.NewTokenV1("runtime_no_state_validation"); token == expected {
		return runtimeLabNoStateValidationV1, true
	}
	if expected, _ := labfault.NewTokenV1("secret_trace_leak"); token == expected {
		return runtimeLabSecretTraceV1, true
	}
	if expected, _ := labfault.NewTokenV1("runtime_leaks_secret_trace"); token == expected {
		return runtimeLabRuntimeSecretTraceV1, true
	}
	if expected, _ := labfault.NewTokenV1("runtime_leaks_payload_trace"); token == expected {
		return runtimeLabRuntimePayloadTraceV1, true
	}
	if expected, _ := labfault.NewTokenV1("runtime_ignores_backpressure"); token == expected {
		return runtimeLabIgnoresBackpressureV1, true
	}
	if expected, _ := labfault.NewTokenV1("runtime_padding_only_diversity"); token == expected {
		return runtimeLabPaddingDiversityV1, true
	}
	return 0, false
}

type runtimeLabExecutorOpsV1 struct {
	afterProtectedProgress    func() error
	afterPaddingProgress      func() error
	afterBackpressureProgress func() error
}

func realRuntimeLabExecutorOpsV1() runtimeLabExecutorOpsV1 {
	return runtimeLabExecutorOpsV1{func() error { return nil }, func() error { return nil }, func() error { return nil }}
}

func ExecuteRuntimeLabFaultV1(token labfault.Token, client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) (RuntimeLabFaultObservationV1, error) {
	return executeRuntimeLabFaultWithOpsV1(token, client, relay, realRuntimeLabExecutorOpsV1())
}

func executeRuntimeLabFaultWithOpsV1(token labfault.Token, client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, ops runtimeLabExecutorOpsV1) (RuntimeLabFaultObservationV1, error) {
	mode, valid := classifyRuntimeLabFaultV1(token)
	if !valid {
		return RuntimeLabFaultObservationV1{}, errRuntimeTraceFaultInvalidV1
	}
	endpointFree := mode == runtimeLabSecretTraceV1 || mode == runtimeLabRuntimeSecretTraceV1 || mode == runtimeLabRuntimePayloadTraceV1 || mode == runtimeLabIgnoresBackpressureV1
	if endpointFree {
		if client != nil || relay != nil {
			return RuntimeLabFaultObservationV1{}, errRuntimeTraceFaultInvalidV1
		}
	} else if !validRuntimeLabPairV1(client, relay) {
		return RuntimeLabFaultObservationV1{}, errRuntimeTraceFaultInvalidV1
	}
	switch mode {
	case runtimeLabSecretTraceV1, runtimeLabRuntimeSecretTraceV1, runtimeLabRuntimePayloadTraceV1:
		secret, payload := []byte("lab-secret-canary"), []byte("lab-payload-canary")
		observation, err := newRuntimeTraceFaultObservationV1(token, secret, payload)
		if err != nil {
			return RuntimeLabFaultObservationV1{}, err
		}
		owner := runtimeTraceEventOwnerV1
		expected := secret
		if mode == runtimeLabSecretTraceV1 {
			owner = runtimeTraceWrapperOwnerV1
		}
		if mode == runtimeLabRuntimePayloadTraceV1 {
			expected = payload
		}
		matched := observation.detectAndClearV1(owner, expected)
		return RuntimeLabFaultObservationV1{UnsafeObserved: matched, Count: boolCountV1(matched), Category: "trace"}, nil
	case runtimeLabIgnoresBackpressureV1:
		link := newMemoryLinkWithLabFaultV1(1, token)
		if link == nil {
			return RuntimeLabFaultObservationV1{}, errRuntimeTraceFaultInvalidV1
		}
		defer func() {
			for link.QueueDepth("client_to_server") > 0 {
				_, _ = link.Deliver("client_to_server")
			}
			link.Close()
		}()
		accepted := uint32(0)
		for i := uint64(1); i <= 3; i++ {
			err := link.Send(LinkFrame{Direction: "client_to_server", Sequence: i, EnvelopeKind: "lab_metadata"})
			if err == nil {
				accepted++
				continue
			}
			if err != ErrLinkQueueFull {
				return RuntimeLabFaultObservationV1{}, err
			}
		}
		if err := ops.afterBackpressureProgress(); err != nil {
			return RuntimeLabFaultObservationV1{}, err
		}
		for link.QueueDepth("client_to_server") > 0 {
			if _, err := link.Deliver("client_to_server"); err != nil {
				return RuntimeLabFaultObservationV1{}, err
			}
		}
		return RuntimeLabFaultObservationV1{UnsafeObserved: accepted == 2, Count: accepted, Category: "backpressure"}, nil
	}
	defer closeEndpointPairV1(client, relay)
	if mode == runtimeLabPaddingDiversityV1 {
		ce, re, err := newInProcessProtectedRelayWithLabFaultV1(client, relay, token)
		if err != nil {
			return RuntimeLabFaultObservationV1{}, err
		}
		record, err := ce.Seal(1, []byte("lab"))
		if err != nil {
			return RuntimeLabFaultObservationV1{}, err
		}
		one, err := ce.wrapWithPaddingV1(record, []byte{1})
		if err != nil {
			return RuntimeLabFaultObservationV1{}, err
		}
		two, err := ce.wrapWithPaddingV1(record, []byte{2, 3})
		if err != nil {
			return RuntimeLabFaultObservationV1{}, err
		}
		defer clearPaddingFaultRecordV1(&one)
		defer clearPaddingFaultRecordV1(&two)
		if err := ops.afterPaddingProgress(); err != nil {
			return RuntimeLabFaultObservationV1{}, err
		}
		clearPaddingFaultRecordV1(&two)
		payload, _, err := re.Deliver(one)
		observed := err == nil && len(payload) == 3
		clear(payload)
		if err != nil {
			return RuntimeLabFaultObservationV1{}, err
		}
		return RuntimeLabFaultObservationV1{UnsafeObserved: observed, Count: 2, Category: "padding"}, nil
	}
	channel, err := newStrictProtectedChannelWithLabFaultV1(client, relay, token)
	if err != nil {
		return RuntimeLabFaultObservationV1{}, err
	}
	switch mode {
	case runtimeLabReusedNonceV1:
		_, _, err = channel.sealClientApplicationV1(1, []byte("a"))
		if err == nil {
			err = ops.afterProtectedProgress()
		}
		if err == nil {
			_, _, err = channel.sealClientApplicationV1(1, []byte("b"))
		}
		if err != nil {
			return RuntimeLabFaultObservationV1{}, err
		}
		s := channel.nonceSummaryV1()
		return RuntimeLabFaultObservationV1{UnsafeObserved: s.Collisions == 1, Count: uint32(s.Collisions), Category: "nonce"}, nil
	case runtimeLabAcceptsReplayV1:
		record, _, e := channel.sealClientApplicationV1(1, []byte("a"))
		if e != nil {
			return RuntimeLabFaultObservationV1{}, e
		}
		_, _, e = channel.openClientApplicationV1(record)
		if e != nil {
			return RuntimeLabFaultObservationV1{}, e
		}
		p, _, e := channel.openClientApplicationV1(record)
		ok := e == nil && len(p) > 0
		clear(p)
		if e != nil {
			return RuntimeLabFaultObservationV1{}, e
		}
		return RuntimeLabFaultObservationV1{ok, boolCountV1(ok), "security_replay"}, nil
	case runtimeLabAcceptsRuntimeReplayV1:
		record, id, e := channel.sealClientApplicationV1(1, []byte("a"))
		if e != nil {
			return RuntimeLabFaultObservationV1{}, e
		}
		_, _, e = channel.openClientApplicationV1(record)
		if e != nil {
			return RuntimeLabFaultObservationV1{}, e
		}
		retry, e := channel.retryClientApplicationV1(id, []byte("a"))
		if e != nil {
			return RuntimeLabFaultObservationV1{}, e
		}
		p, _, e := channel.openClientApplicationV1(retry)
		ok := e == nil && len(p) > 0
		clear(p)
		if e != nil {
			return RuntimeLabFaultObservationV1{}, e
		}
		return RuntimeLabFaultObservationV1{ok, boolCountV1(ok), "runtime_replay"}, nil
	case runtimeLabNoStateValidationV1:
		first, _, e := channel.sealClientApplicationV1(1, []byte("a"))
		if e != nil {
			return RuntimeLabFaultObservationV1{}, e
		}
		_, _, e = channel.openClientApplicationV1(first)
		if e != nil {
			return RuntimeLabFaultObservationV1{}, e
		}
		record, _, e := channel.sealRelayApplicationV1(1, []byte("b"))
		if e != nil {
			return RuntimeLabFaultObservationV1{}, e
		}
		client.state.life.state = auth.StateAuthenticating
		p, _, e := channel.openRelayApplicationV1(record)
		ok := e == nil && len(p) > 0
		clear(p)
		if e != nil {
			return RuntimeLabFaultObservationV1{}, e
		}
		return RuntimeLabFaultObservationV1{ok, boolCountV1(ok), "state"}, nil
	}
	return RuntimeLabFaultObservationV1{}, errRuntimeTraceFaultInvalidV1
}

func validRuntimeLabPairV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) bool {
	return client != nil && relay != nil && client.state != nil && relay.state != nil && client.state.life != nil && relay.state.life != nil && client.state.life.owner == relay.state.life.owner && client.State() != auth.StateClosed && relay.State() != auth.StateClosed
}
func boolCountV1(value bool) uint32 {
	if value {
		return 1
	}
	return 0
}
