// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"fmt"

	"kurdistan/internal/ir"
	"kurdistan/internal/proxysem"
	kstream "kurdistan/internal/stream"
)

type StreamManager struct {
	session *Session
	profile *ir.Profile
	intents map[uint32]proxysem.RelayIntent
}

func NewStreamManager(s *Session, p *ir.Profile) (*StreamManager, error) {
	if s == nil || p == nil {
		return nil, fmt.Errorf("%w: nil stream manager input", ErrLifecycle)
	}
	if s.StreamSession == nil {
		streamSession, err := kstream.NewSession(kstream.ConfigFromProfile(p))
		if err != nil {
			return nil, err
		}
		s.StreamSession = streamSession
	}
	return &StreamManager{session: s, profile: p, intents: map[uint32]proxysem.RelayIntent{}}, nil
}

func (m *StreamManager) OpenStream(priority string, intent proxysem.RelayIntent) (uint32, error) {
	if m.session.State != SessionOpen {
		return 0, fmt.Errorf("%w: session not open", ErrLifecycle)
	}
	id, err := m.session.StreamSession.OpenStream(priority)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrStreamLimit, err)
	}
	intent.StreamID = uint64(id)
	if intent.Target.Class != "" {
		if intent.MaxRequestBytes == 0 {
			intent.MaxRequestBytes = m.profile.ProxySemantics.MaxRequestBytes
		}
		if intent.MaxResponseBytes == 0 {
			intent.MaxResponseBytes = m.profile.ProxySemantics.MaxResponseBytes
		}
		if err := proxysem.ValidateRelayIntent(intent); err != nil {
			return 0, err
		}
		m.intents[id] = intent
	}
	return id, nil
}

func (m *StreamManager) CloseStream(id uint32) error {
	if m.session.State == SessionClosed {
		return fmt.Errorf("%w: session closed", ErrLifecycle)
	}
	if err := m.session.StreamSession.CloseLocal(id); err != nil {
		return err
	}
	if err := m.session.StreamSession.CloseRemote(id); err != nil {
		return err
	}
	return nil
}

func (m *StreamManager) ResetStream(id uint32, reason string) error {
	if m.session.State == SessionClosed {
		return fmt.Errorf("%w: session closed", ErrLifecycle)
	}
	return m.session.StreamSession.Reset(id, reason)
}
