// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"os"
	"path/filepath"
	"testing"

	ktrace "kurdistan/internal/trace"
)

func FuzzRuntimeConfigValidation(f *testing.F) {
	f.Add("client", "runtime-a", []byte("secret"), 4, 8, 64)
	f.Add("server", "runtime-b", []byte("secret"), 1, 1, 1)
	f.Add("bad", "", []byte{}, 0, 0, 0)
	f.Fuzz(func(t *testing.T, roleValue, runtimeID string, secret []byte, maxSessions, maxStreams, maxEvents int) {
		if len(secret) > 1024 || len(runtimeID) > 256 {
			t.Skip()
		}
		cfg := RuntimeConfig{
			Role:             Role(roleValue),
			RuntimeID:        runtimeID,
			RequiredFeatures: []string{"multi_stream"},
			SecuritySecret:   append([]byte(nil), secret...),
			MaxSessions:      maxSessions,
			MaxStreams:       maxStreams,
			MaxEvents:        maxEvents,
			TraceEnabled:     true,
		}
		_ = ValidateConfig(cfg)
		_ = RedactConfig(cfg)
	})
}

func FuzzProfileLoaderInvalidJSON(f *testing.F) {
	f.Add([]byte(`{"id":"bad"}`))
	f.Add([]byte(`not json`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			t.Skip()
		}
		path := filepath.Join(t.TempDir(), "profile.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = LoadProfile(path, "")
	})
}

func FuzzRuntimeTraceHygiene(f *testing.F) {
	f.Add("client", "open", "payload", "secret")
	f.Add("server", "closed", "", "")
	f.Fuzz(func(t *testing.T, roleValue, stateValue, payload, secret string) {
		if len(payload) > 512 || len(secret) > 512 {
			t.Skip()
		}
		session := &Session{ID: "fuzz", RuntimeID: "rt", Role: Role(roleValue), State: SessionState(stateValue)}
		events := []ktrace.Event{
			RuntimeTraceEvent("profile", session, "runtime_state"),
		}
		_ = TraceHasSensitive(events, []byte(payload), []byte(secret))
	})
}
