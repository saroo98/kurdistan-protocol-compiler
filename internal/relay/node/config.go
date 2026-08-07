// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"errors"
	"path/filepath"
	"time"
)

var ErrConfig = errors.New("relay node: invalid configuration")

type Config struct {
	DataDir, TUNName, ControlSocket string
	ListenerPort                    uint16
	MaxHandshakeWorkers             int
	MaxSessions                     int
	SessionQueuePackets             int
	HandshakeTimeout                time.Duration
	SessionIdleTimeout              time.Duration
	ReloadInterval                  time.Duration
	SessionBufferBudget             uint64
	DNSReady                        func(context.Context) bool
	Now                             func() time.Time
}

func DefaultConfig(dataDir string, listenerPort uint16) Config {
	return Config{
		DataDir: dataDir, TUNName: "kurd0", ControlSocket: filepath.Join(dataDir, "relay.control.sock"), ListenerPort: listenerPort,
		MaxHandshakeWorkers: 32, MaxSessions: 256, SessionQueuePackets: 64,
		HandshakeTimeout: 10 * time.Second, SessionIdleTimeout: 10 * time.Minute, ReloadInterval: 5 * time.Second,
		SessionBufferBudget: 8 << 20, Now: func() time.Time { return time.Now().UTC() },
	}
}

func (config Config) Validate() error {
	if config.DataDir == "" || !filepath.IsAbs(config.DataDir) || config.TUNName != "kurd0" ||
		config.ControlSocket == "" || !filepath.IsAbs(config.ControlSocket) || config.ListenerPort == 0 ||
		config.MaxHandshakeWorkers <= 0 || config.MaxHandshakeWorkers > 256 ||
		config.MaxSessions < config.MaxHandshakeWorkers || config.MaxSessions > 4096 ||
		config.SessionQueuePackets <= 0 || config.SessionQueuePackets > 4096 ||
		config.HandshakeTimeout < time.Second || config.HandshakeTimeout > time.Minute ||
		config.SessionIdleTimeout < 5*time.Second || config.SessionIdleTimeout > 24*time.Hour ||
		config.ReloadInterval < time.Second || config.ReloadInterval > time.Hour ||
		config.SessionBufferBudget < 64<<10 || config.SessionBufferBudget > 1<<30 ||
		config.DNSReady == nil || config.Now == nil || config.Now().IsZero() {
		return ErrConfig
	}
	return nil
}
