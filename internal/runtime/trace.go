// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"encoding/json"
	"strings"

	"kurdistan/internal/security"
	ktrace "kurdistan/internal/trace"
)

func RuntimeTraceEvent(profileID string, s *Session, eventType string) ktrace.Event {
	ev := ktrace.Event{
		Role:                    string(s.Role),
		ProfileID:               profileID,
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
		ev.LifecycleTransition = s.Events[len(s.Events)-1].Transition
	}
	if s.FailureReason != "" {
		ev.FailureReasonBucket = s.FailureReason
	}
	if s.CloseReason != "" {
		ev.CloseReasonBucket = s.CloseReason
	}
	return ev
}

func LinkTraceEvent(profileID string, frame LinkFrame) ktrace.Event {
	return ktrace.Event{
		ProfileID:            profileID,
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
