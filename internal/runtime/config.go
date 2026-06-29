// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"

	"kurdistan/internal/security"
)

type RuntimeConfig struct {
	Role             Role     `json:"role"`
	ProfilePath      string   `json:"profile_path,omitempty"`
	ProfileID        string   `json:"profile_id,omitempty"`
	RuntimeID        string   `json:"runtime_id"`
	RequiredFeatures []string `json:"required_features,omitempty"`
	SecuritySecret   []byte   `json:"-"`
	MaxSessions      int      `json:"max_sessions"`
	MaxStreams       int      `json:"max_streams"`
	MaxEvents        int      `json:"max_events"`
	TraceEnabled     bool     `json:"trace_enabled"`
}

func DefaultConfig(role Role, runtimeID string, secret []byte) RuntimeConfig {
	return RuntimeConfig{
		Role:             role,
		RuntimeID:        runtimeID,
		RequiredFeatures: security.DefaultCapabilities().Features,
		SecuritySecret:   append([]byte(nil), secret...),
		MaxSessions:      4,
		MaxStreams:       16,
		MaxEvents:        4096,
		TraceEnabled:     true,
	}
}

func ValidateConfig(cfg RuntimeConfig) error {
	if err := ValidateRole(cfg.Role); err != nil {
		return err
	}
	if cfg.RuntimeID == "" {
		return fmt.Errorf("%w: missing runtime id", ErrInvalidConfig)
	}
	if len(cfg.SecuritySecret) == 0 {
		return fmt.Errorf("%w: missing security secret", ErrInvalidConfig)
	}
	if bytes.Equal(cfg.SecuritySecret, make([]byte, len(cfg.SecuritySecret))) {
		return fmt.Errorf("%w: all-zero security secret", ErrInvalidConfig)
	}
	if cfg.MaxSessions <= 0 || cfg.MaxSessions > 64 {
		return fmt.Errorf("%w: max sessions", ErrInvalidConfig)
	}
	if cfg.MaxStreams <= 0 || cfg.MaxStreams > 256 {
		return fmt.Errorf("%w: max streams", ErrInvalidConfig)
	}
	if cfg.MaxEvents <= 0 || cfg.MaxEvents > 1<<20 {
		return fmt.Errorf("%w: max events", ErrInvalidConfig)
	}
	if len(cfg.RequiredFeatures) == 0 {
		return fmt.Errorf("%w: missing required features", ErrInvalidConfig)
	}
	if _, err := (security.CapabilitySet{Features: cfg.RequiredFeatures}).Hash(); err != nil {
		return err
	}
	return nil
}

func RedactConfig(cfg RuntimeConfig) map[string]any {
	return map[string]any{
		"role":              cfg.Role,
		"profile_path":      cfg.ProfilePath,
		"profile_id":        cfg.ProfileID,
		"runtime_id":        cfg.RuntimeID,
		"required_features": append([]string(nil), cfg.RequiredFeatures...),
		"security_secret":   json.RawMessage(`"<redacted>"`),
		"max_sessions":      cfg.MaxSessions,
		"max_streams":       cfg.MaxStreams,
		"max_events":        cfg.MaxEvents,
		"trace_enabled":     cfg.TraceEnabled,
	}
}
