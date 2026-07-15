// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"unsafe"

	"kurdistan/internal/crypto/security"
	ktrace "kurdistan/internal/observe/trace"
	"kurdistan/internal/runtime/labfault"
)

var errRuntimeTraceFaultInvalidV1 = errors.New("runtime_trace_fault_invalid")

const (
	runtimeTraceWrapperOwnerV1 = "runtime_trace_wrapper_v1"
	runtimeTraceEventOwnerV1   = "runtime_trace_event_v1"
)

type runtimeTraceFaultObservationV1 struct {
	owner string
	owned []byte
	used  bool
}

func newRuntimeTraceFaultObservationV1(token labfault.Token, secretCanary, payloadCanary []byte) (*runtimeTraceFaultObservationV1, error) {
	if len(secretCanary) == 0 || len(payloadCanary) == 0 || len(secretCanary) > 64 || len(payloadCanary) > 64 ||
		bytes.Equal(secretCanary, payloadCanary) || slicesAliasV1(secretCanary, payloadCanary) {
		return nil, errRuntimeTraceFaultInvalidV1
	}
	wrapper, _ := labfault.NewTokenV1("secret_trace_leak")
	runtimeSecret, _ := labfault.NewTokenV1("runtime_leaks_secret_trace")
	runtimePayload, _ := labfault.NewTokenV1("runtime_leaks_payload_trace")
	observation := &runtimeTraceFaultObservationV1{}
	switch token {
	case wrapper:
		observation.owner, observation.owned = runtimeTraceWrapperOwnerV1, append([]byte(nil), secretCanary...)
	case runtimeSecret:
		observation.owner, observation.owned = runtimeTraceEventOwnerV1, append([]byte(nil), secretCanary...)
	case runtimePayload:
		observation.owner, observation.owned = runtimeTraceEventOwnerV1, append([]byte(nil), payloadCanary...)
	default:
		return nil, errRuntimeTraceFaultInvalidV1
	}
	return observation, nil
}

func slicesAliasV1(left, right []byte) bool {
	leftStart, leftEnd := uintptr(unsafe.Pointer(&left[0])), uintptr(unsafe.Pointer(&left[len(left)-1]))
	rightStart, rightEnd := uintptr(unsafe.Pointer(&right[0])), uintptr(unsafe.Pointer(&right[len(right)-1]))
	return leftStart <= rightEnd && rightStart <= leftEnd
}

func (observation *runtimeTraceFaultObservationV1) detectAndClearV1(expectedOwner string, expected []byte) bool {
	if observation == nil || observation.used || observation.owned == nil {
		return false
	}
	match := observation.owner == expectedOwner && bytes.Equal(observation.owned, expected)
	clear(observation.owned)
	observation.owned = nil
	observation.owner = ""
	observation.used = true
	return match
}

func RuntimeTraceEvent(profileID string, s *Session, eventType string) ktrace.Event {
	ev := ktrace.Event{
		Role:                    string(s.Role),
		EventType:               eventType,
		RuntimeRole:             string(s.Role),
		RuntimeState:            string(s.State),
		SessionState:            string(s.State),
		CapabilityMatch:         s.CapabilitiesHash() != "",
		SecurityContextResult:   "created",
		NegotiationResultBucket: "accepted",
		CompatibilityResult:     "compatible",
		PayloadHygiene:          true,
		SecretHygiene:           true,
	}
	if len(s.Events) > 0 {
		ev.LifecycleTransition = lifecycleBucketV1(s.Events[len(s.Events)-1].Transition)
	}
	if s.FailureReason != "" {
		ev.FailureReasonBucket = reasonBucketV1(s.FailureReason)
	}
	if s.CloseReason != "" {
		ev.CloseReasonBucket = reasonBucketV1(s.CloseReason)
	}
	return ev
}

func RuntimeDiagnosticEventV1(s *Session, eventClass string) (ktrace.DiagnosticEventV1, error) {
	if s == nil {
		return ktrace.DiagnosticEventV1{}, ktrace.ErrDiagnosticEventInvalidV1
	}
	event := ktrace.DiagnosticEventV1{SchemaVersion: ktrace.DiagnosticSchemaV1, EventClass: eventClass, RoleBucket: diagnosticRoleBucketV1(s.Role), StateBucket: diagnosticStateBucketV1(s.State), OutcomeBucket: "accepted", HygieneResult: "redacted"}
	if s.FailureReason != "" {
		event.EventClass, event.OutcomeBucket, event.ReasonBucket = "failure", "rejected", reasonBucketV1(s.FailureReason)
	}
	if s.CloseReason != "" {
		event.EventClass, event.OutcomeBucket, event.ReasonBucket = "close", "completed", reasonBucketV1(s.CloseReason)
		if event.ReasonBucket == "close" {
			event.ReasonBucket = "closed"
		}
	}
	if err := ktrace.ValidateDiagnosticEventV1(event); err != nil {
		return ktrace.DiagnosticEventV1{}, err
	}
	return event, nil
}

func LinkDiagnosticEventV1(frame LinkFrame) (ktrace.DiagnosticEventV1, error) {
	direction := "client_to_relay"
	if frame.Direction == "server_to_client" {
		direction = "relay_to_client"
	}
	event := ktrace.DiagnosticEventV1{SchemaVersion: ktrace.DiagnosticSchemaV1, EventClass: "channel", DirectionBucket: direction, CountBucket: "one", HygieneResult: "redacted"}
	if err := ktrace.ValidateDiagnosticEventV1(event); err != nil {
		return ktrace.DiagnosticEventV1{}, err
	}
	return event, nil
}

func SecureDiagnosticEventV1(ctx security.SecurityContext, env security.SecureEnvelope, role Role) (ktrace.DiagnosticEventV1, error) {
	event, err := security.SecureEnvelopeDiagnosticV1(ctx, env)
	if err != nil {
		return ktrace.DiagnosticEventV1{}, err
	}
	event.RoleBucket = diagnosticRoleBucketV1(role)
	if err := ktrace.ValidateDiagnosticEventV1(event); err != nil {
		return ktrace.DiagnosticEventV1{}, err
	}
	return event, nil
}

func diagnosticRoleBucketV1(role Role) string {
	if role == RoleServer {
		return "relay"
	}
	return "client"
}

func diagnosticStateBucketV1(state SessionState) string {
	text := strings.ToLower(string(state))
	if strings.Contains(text, "close") || strings.Contains(text, "fail") {
		return "terminal"
	}
	if strings.Contains(text, "start") || strings.Contains(text, "init") {
		return "starting"
	}
	return "active"
}

func LinkTraceEvent(profileID string, frame LinkFrame) ktrace.Event {
	return ktrace.Event{
		EventType:            "runtime_link_frame",
		Direction:            frame.Direction,
		RuntimeFrameBucket:   frame.EnvelopeKind,
		RuntimeFrameCount:    "one",
		RuntimeRole:          roleFromDirection(frame.Direction),
		FrameDirectionBucket: frame.Direction,
		PayloadHygiene:       true,
		SecretHygiene:        true,
	}
}

func SecureTraceEvent(ctx security.SecurityContext, env security.SecureEnvelope, role Role) ktrace.Event {
	ev := security.SecureEnvelopeTrace(ctx, env)
	ev.EventType = "runtime_secure_envelope"
	ev.RuntimeRole = string(role)
	ev.SecurityContextResult = "created"
	ev.TranscriptMatch = true
	ev.CapabilityMatch = true
	ev.PayloadHygiene = true
	ev.SecretHygiene = true
	return ev
}

func TraceHasSensitive(events []ktrace.Event, sensitive ...[]byte) bool {
	if ktrace.ContainsSensitiveValue(events, sensitive...) {
		return true
	}
	raw, _ := json.Marshal(events)
	for _, item := range sensitive {
		if len(item) > 0 && bytes.Contains(raw, item) {
			return true
		}
	}
	text := strings.ToLower(string(raw))
	for _, marker := range []string{"payload must not leak", "secret:", "nonce_base", "auth_tag", "proof_material"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func lifecycleBucketV1(value string) string {
	if value == "" {
		return ""
	}
	if strings.Contains(value, "close") || strings.Contains(value, "fail") || strings.Contains(value, "reject") {
		return "terminal"
	}
	return "state_change"
}

func reasonBucketV1(value string) string {
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	for _, class := range []string{"replay", "policy", "profile", "capability", "config", "resource", "timeout", "close"} {
		if strings.Contains(lower, class) {
			return class
		}
	}
	return "other"
}

func (s *Session) CapabilitiesHash() string {
	hash, _ := s.Capabilities.Hash()
	return hash
}

func roleFromDirection(direction string) string {
	if direction == "server_to_client" {
		return string(RoleServer)
	}
	return string(RoleClient)
}
