// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigV1RejectsUnsafeOrUnboundedValues(t *testing.T) {
	valid := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
	valid.DNSReady = func(context.Context) bool { return true }
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"relative data":       func(c *Config) { c.DataDir = "relative" },
		"wrong tun":           func(c *Config) { c.TUNName = "tun0" },
		"zero port":           func(c *Config) { c.ListenerPort = 0 },
		"workers":             func(c *Config) { c.MaxHandshakeWorkers = 0 },
		"sessions":            func(c *Config) { c.MaxSessions = c.MaxHandshakeWorkers - 1 },
		"queue":               func(c *Config) { c.SessionQueuePackets = 0 },
		"source entries":      func(c *Config) { c.MaxSourceEntries = 0 },
		"source attempts":     func(c *Config) { c.MaxSourceAttempts = 0 },
		"control workers":     func(c *Config) { c.ControlWorkers = 0 },
		"short handshake":     func(c *Config) { c.HandshakeTimeout = 100 * time.Millisecond },
		"long idle":           func(c *Config) { c.SessionIdleTimeout = 25 * time.Hour },
		"short reload":        func(c *Config) { c.ReloadInterval = 100 * time.Millisecond },
		"short source window": func(c *Config) { c.SourceWindow = 100 * time.Millisecond },
		"short control":       func(c *Config) { c.ControlTimeout = 10 * time.Millisecond },
		"small buffer":        func(c *Config) { c.SessionBufferBudget = 1024 },
		"missing dns health":  func(c *Config) { c.DNSReady = nil },
		"missing loader":      func(c *Config) { c.LoadSnapshot = nil },
		"missing entropy":     func(c *Config) { c.Entropy = nil },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("unsafe relay configuration accepted")
			}
		})
	}
}

func TestHealthMachineV1RequiresEveryRuntimeDependency(t *testing.T) {
	health := NewHealthMachine()
	if got := health.Snapshot(); got.State != HealthStarting {
		t.Fatalf("initial state=%s", got.State)
	}
	ready := HealthRequirements{Listener: true, Tunnel: true, VerifiedState: true, TLSIdentity: true, RelayIdentity: true, DNS: true}
	health.Update(ready)
	if got := health.Snapshot(); got.State != HealthReady || !got.AcceptingSessions {
		t.Fatalf("ready state=%+v", got)
	}
	health.SetDrain(true)
	if got := health.Snapshot(); got.State != HealthDraining || got.AcceptingSessions {
		t.Fatalf("drain state=%+v", got)
	}
	health.SetDrain(false)
	health.Update(HealthRequirements{Listener: true, Tunnel: true, VerifiedState: true, TLSIdentity: true, RelayIdentity: true})
	if got := health.Snapshot(); got.State != HealthDegraded || got.AcceptingSessions || got.Missing != 1 {
		t.Fatalf("degraded state=%+v", got)
	}
	health.SetDisabled(true)
	if got := health.Snapshot(); got.State != HealthDisabled || got.AcceptingSessions {
		t.Fatalf("disabled state=%+v", got)
	}
	health.SetDisabled(false)
	health.Stop()
	health.Update(ready)
	if got := health.Snapshot(); got.State != HealthStopping || got.AcceptingSessions {
		t.Fatalf("terminal stop state=%+v", got)
	}
}
