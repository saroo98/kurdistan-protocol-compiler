// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

type SessionState string

const (
	SessionNew         SessionState = "new"
	SessionNegotiating SessionState = "negotiating"
	SessionSecuring    SessionState = "securing"
	SessionOpen        SessionState = "open"
	SessionDraining    SessionState = "draining"
	SessionClosed      SessionState = "closed"
	SessionFailed      SessionState = "failed"
)

func terminalState(s SessionState) bool {
	return s == SessionClosed || s == SessionFailed
}

type Event struct {
	RuntimeRole       Role         `json:"runtime_role"`
	RuntimeID         string       `json:"runtime_id"`
	SessionID         string       `json:"session_id"`
	State             SessionState `json:"state"`
	Transition        string       `json:"transition,omitempty"`
	NegotiationResult string       `json:"negotiation_result,omitempty"`
	FailureReason     string       `json:"failure_reason,omitempty"`
	CloseReason       string       `json:"close_reason,omitempty"`
}
