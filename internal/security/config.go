// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type redactedValue string

func (r redactedValue) MarshalJSON() ([]byte, error) {
	return []byte(`"<redacted>"`), nil
}

type SecurityConfig struct {
	ProfileID        string   `json:"profile_id"`
	ProfileHash      string   `json:"profile_hash"`
	InputSecret      []byte   `json:"input_secret,omitempty"`
	Suite            Suite    `json:"suite"`
	ReplayWindow     int      `json:"replay_window"`
	MaxEnvelopeBytes int      `json:"max_envelope_bytes"`
	QueueDepth       int      `json:"queue_depth"`
	Capabilities     []string `json:"capabilities"`
	TranscriptHash   string   `json:"transcript_hash"`
	CapabilityHash   string   `json:"capability_hash"`
	Debug            bool     `json:"debug,omitempty"`
}

func ValidateConfig(cfg SecurityConfig) error {
	if cfg.ProfileID == "" || cfg.ProfileHash == "" {
		return fmt.Errorf("%w: missing profile identity", ErrInvalidConfig)
	}
	if len(cfg.InputSecret) == 0 {
		return fmt.Errorf("%w: missing secret", ErrInvalidConfig)
	}
	if bytes.Equal(cfg.InputSecret, make([]byte, len(cfg.InputSecret))) {
		return fmt.Errorf("%w: all-zero secret", ErrInvalidConfig)
	}
	if !SuiteSupported(cfg.Suite) {
		return ErrInvalidSuite
	}
	if cfg.ReplayWindow <= 1 || cfg.ReplayWindow > 4096 {
		return fmt.Errorf("%w: replay window", ErrInvalidConfig)
	}
	if cfg.MaxEnvelopeBytes <= 0 || cfg.MaxEnvelopeBytes > 1<<20 {
		return fmt.Errorf("%w: max envelope bytes", ErrInvalidConfig)
	}
	if cfg.QueueDepth <= 0 || cfg.QueueDepth > 1024 {
		return fmt.Errorf("%w: queue depth", ErrInvalidConfig)
	}
	if cfg.Debug {
		return fmt.Errorf("%w: unsafe debug flag", ErrInvalidConfig)
	}
	if _, err := canonicalCapabilities(cfg.Capabilities); err != nil {
		return err
	}
	return nil
}

func RedactConfig(cfg SecurityConfig) map[string]any {
	redacted := json.RawMessage(`"<redacted>"`)
	return map[string]any{
		"profile_id":         cfg.ProfileID,
		"profile_hash":       cfg.ProfileHash,
		"input_secret":       redacted,
		"suite":              cfg.Suite,
		"replay_window":      cfg.ReplayWindow,
		"max_envelope_bytes": cfg.MaxEnvelopeBytes,
		"queue_depth":        cfg.QueueDepth,
		"capabilities":       append([]string(nil), cfg.Capabilities...),
		"transcript_hash":    cfg.TranscriptHash,
		"capability_hash":    cfg.CapabilityHash,
		"debug":              cfg.Debug,
	}
}
