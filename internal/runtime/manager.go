// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"fmt"

	"kurdistan/internal/ir"
)

type Runtime struct {
	Config  RuntimeConfig
	Profile *ir.Profile
	events  []Event
	nextID  int
}

type Manager struct {
	Runtime  *Runtime
	Sessions map[string]*Session
}

func NewRuntime(cfg RuntimeConfig, p *ir.Profile) (*Runtime, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if err := ValidateLoadedProfile(p); err != nil {
		return nil, err
	}
	if cfg.ProfileID != "" && cfg.ProfileID != p.ID {
		return nil, fmt.Errorf("%w: runtime profile id mismatch", ErrCompatibility)
	}
	return &Runtime{Config: cfg, Profile: p}, nil
}

func NewRuntimeFromPath(cfg RuntimeConfig) (*Runtime, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	p, err := LoadProfile(cfg.ProfilePath, cfg.ProfileID)
	if err != nil {
		return nil, err
	}
	return NewRuntime(cfg, p)
}

func NewManager(rt *Runtime) *Manager {
	return &Manager{Runtime: rt, Sessions: map[string]*Session{}}
}

func (m *Manager) CreateSession() (*Session, error) {
	if m == nil || m.Runtime == nil {
		return nil, fmt.Errorf("%w: nil manager", ErrLifecycle)
	}
	if len(m.Sessions) >= m.Runtime.Config.MaxSessions {
		return nil, ErrSessionLimit
	}
	m.Runtime.nextID++
	id := fmt.Sprintf("%s_session_%03d", m.Runtime.Config.RuntimeID, m.Runtime.nextID)
	s, err := NewSession(id, m.Runtime.Config.RuntimeID, m.Runtime.Config.Role)
	if err != nil {
		return nil, err
	}
	m.Sessions[id] = s
	return s, nil
}

func (m *Manager) CloseSession(id, reason string) error {
	s, ok := m.Sessions[id]
	if !ok {
		return fmt.Errorf("%w: unknown session", ErrLifecycle)
	}
	return s.Close(reason)
}
