// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fsm

import (
	"fmt"

	"kurdistan/internal/ir"
)

type Interpreter struct {
	profile *ir.Profile
	role    string
	state   string
}

func New(p *ir.Profile, role string) (*Interpreter, error) {
	if err := ir.Validate(p); err != nil {
		return nil, err
	}
	if role != ir.RoleClient && role != ir.RoleServer {
		return nil, fmt.Errorf("invalid fsm role %q", role)
	}
	return &Interpreter{profile: p, role: role, state: p.FirstContact.StartState}, nil
}

func (i *Interpreter) State() string {
	return i.state
}

func (i *Interpreter) Apply(message string) error {
	return i.ApplyAuthenticated(message, false)
}

func (i *Interpreter) ApplyAuthenticated(message string, authenticated bool) error {
	for _, tr := range i.profile.Transitions {
		if tr.From == i.state && tr.OnMessage == message {
			if tr.Role != i.role {
				return fmt.Errorf("transition %q requires role %q", message, tr.Role)
			}
			if tr.RequiresAuth && !authenticated {
				return fmt.Errorf("transition %q requires authenticated proof", message)
			}
			i.state = tr.To
			return nil
		}
	}
	return fmt.Errorf("invalid transition from %q on %q", i.state, message)
}

func (i *Interpreter) RelayReady() bool {
	return i.state == i.profile.FirstContact.RelayReadyState
}

func (i *Interpreter) SetStateForPeer(state string) error {
	for _, st := range i.profile.States {
		if st.ID == state {
			i.state = state
			return nil
		}
	}
	return fmt.Errorf("unknown peer state %q", state)
}

func (i *Interpreter) Terminal() bool {
	for _, st := range i.profile.States {
		if st.ID == i.state {
			return st.Terminal
		}
	}
	return false
}

func RunFirstContactPath(p *ir.Profile) ([]string, error) {
	client, err := New(p, ir.RoleClient)
	if err != nil {
		return nil, err
	}
	server, err := New(p, ir.RoleServer)
	if err != nil {
		return nil, err
	}
	path := []string{p.FirstContact.StartState}
	for _, step := range p.FirstContact.Steps {
		var active *Interpreter
		if step.Role == ir.RoleClient {
			active = client
		} else {
			active = server
		}
		if active.state != step.FromState {
			active.state = step.FromState
		}
		if err := active.ApplyAuthenticated(step.Message, step.Proof); err != nil {
			return nil, err
		}
		client.state = step.ToState
		server.state = step.ToState
		path = append(path, step.ToState)
	}
	if !client.RelayReady() || !server.RelayReady() {
		return nil, fmt.Errorf("first-contact path did not reach relay-ready")
	}
	return path, nil
}
