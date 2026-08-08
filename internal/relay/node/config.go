// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"time"

	"kurdistan/internal/selfhost"
)

var ErrConfig = errors.New("relay node: invalid configuration")

type Config struct {
	DataDir, TUNName, ControlSocket string
	ListenerPort                    uint16
	MaxHandshakeWorkers             int
	MaxSessions                     int
	SessionQueuePackets             int
	MaxSourceEntries                int
	MaxSourceAttempts               int
	ControlWorkers                  int
	HandshakeTimeout                time.Duration
	SessionIdleTimeout              time.Duration
	ReloadInterval                  time.Duration
	SourceWindow                    time.Duration
	ControlTimeout                  time.Duration
	SessionBufferBudget             uint64
	DNSReady                        func(context.Context) bool
	Now                             func() time.Time
	LoadSnapshot                    func(string, time.Time) (RelaySnapshotV1, error)
	SessionRejected                 func(SessionRejectCodeV1)
	Entropy                         io.Reader
}

func DefaultConfig(dataDir string, listenerPort uint16) Config {
	return Config{
		DataDir: dataDir, TUNName: "kurd0", ControlSocket: filepath.Join(dataDir, "control.sock"), ListenerPort: listenerPort,
		MaxHandshakeWorkers: 32, MaxSessions: 256, SessionQueuePackets: 64,
		MaxSourceEntries: 4096, MaxSourceAttempts: 20, ControlWorkers: 4,
		HandshakeTimeout: 10 * time.Second, SessionIdleTimeout: 10 * time.Minute, ReloadInterval: 5 * time.Second,
		SourceWindow: time.Minute, ControlTimeout: 2 * time.Second,
		SessionBufferBudget: 8 << 20, Now: func() time.Time { return time.Now().UTC() },
		LoadSnapshot: func(dataDir string, now time.Time) (RelaySnapshotV1, error) {
			return selfhost.OpenRelayRuntimeSnapshotV1(dataDir, now)
		},
		Entropy: rand.Reader,
	}
}

func (config Config) Validate() error {
	if config.DataDir == "" || !filepath.IsAbs(config.DataDir) || config.TUNName != "kurd0" ||
		config.ControlSocket == "" || !filepath.IsAbs(config.ControlSocket) || config.ListenerPort == 0 ||
		config.MaxHandshakeWorkers <= 0 || config.MaxHandshakeWorkers > 256 ||
		config.MaxSessions < config.MaxHandshakeWorkers || config.MaxSessions > 4096 ||
		config.SessionQueuePackets <= 0 || config.SessionQueuePackets > 4096 ||
		config.MaxSourceEntries <= 0 || config.MaxSourceEntries > 65536 ||
		config.MaxSourceAttempts <= 0 || config.MaxSourceAttempts > 1024 ||
		config.ControlWorkers <= 0 || config.ControlWorkers > 32 ||
		config.HandshakeTimeout < time.Second || config.HandshakeTimeout > time.Minute ||
		config.SessionIdleTimeout < 5*time.Second || config.SessionIdleTimeout > 24*time.Hour ||
		config.ReloadInterval < time.Second || config.ReloadInterval > time.Hour ||
		config.SourceWindow < time.Second || config.SourceWindow > time.Hour ||
		config.ControlTimeout < 100*time.Millisecond || config.ControlTimeout > 10*time.Second ||
		config.SessionBufferBudget < 64<<10 || config.SessionBufferBudget > 1<<30 ||
		config.DNSReady == nil || config.Now == nil || config.Now().IsZero() || config.LoadSnapshot == nil || config.Entropy == nil {
		return ErrConfig
	}
	return nil
}
