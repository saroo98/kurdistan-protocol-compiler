// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

import "fmt"

type IngressLifecycleEvent struct {
	EventID       string `json:"event_id"`
	RequestID     string `json:"request_id"`
	OldState      string `json:"old_state"`
	NewState      string `json:"new_state"`
	ReasonBucket  string `json:"reason_bucket"`
	PayloadLogged bool   `json:"payload_logged"`
	SecretLogged  bool   `json:"secret_logged"`
}

func CanTransition(oldState, newState IngressRequestState) bool {
	switch oldState {
	case RequestCreated:
		return newState == RequestValidated || newState == RequestRejected
	case RequestValidated:
		return newState == RequestMapped || newState == RequestRejected
	case RequestMapped:
		return newState == RequestAccepted || newState == RequestRejected
	case RequestAccepted:
		return newState == RequestClosed || newState == RequestFailed
	case RequestClosed, RequestFailed, RequestRejected:
		return false
	default:
		return false
	}
}

func TransitionRequest(request SyntheticProxyRequest, newState IngressRequestState, reason string, index int) (SyntheticProxyRequest, IngressLifecycleEvent, error) {
	old := request.RequestState
	if !CanTransition(old, newState) {
		return request, IngressLifecycleEvent{}, fmt.Errorf("%w: %s to %s", ErrInvalidLifecycle, old, newState)
	}
	request.RequestState = newState
	event := IngressLifecycleEvent{
		EventID:      fmt.Sprintf("ingress_lifecycle_%03d", index),
		RequestID:    request.RequestID,
		OldState:     string(old),
		NewState:     string(newState),
		ReasonBucket: reason,
	}
	return request, event, nil
}

func LifecycleGolden(requests []SyntheticProxyRequest) []IngressLifecycleEvent {
	events := []IngressLifecycleEvent{}
	index := 0
	for _, request := range requests {
		for _, state := range []IngressRequestState{RequestValidated, RequestMapped, RequestAccepted, RequestClosed} {
			var event IngressLifecycleEvent
			var err error
			request, event, err = TransitionRequest(request, state, "happy_path", index)
			if err != nil {
				break
			}
			events = append(events, event)
			index++
		}
	}
	return events
}
