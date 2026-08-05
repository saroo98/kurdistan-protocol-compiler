// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package authn

import (
	"sync"
)

const MaxReplayEntries = 4096

type MemoryReplayGuard struct {
	mu      sync.Mutex
	clock   Clock
	entries map[string]int64
}

func NewMemoryReplayGuard(clock Clock) *MemoryReplayGuard {
	return &MemoryReplayGuard{clock: clock, entries: make(map[string]int64)}
}

func (guard *MemoryReplayGuard) UseOnce(actorID, tokenID string, expiresAt int64) error {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.clock == nil {
		return ErrReplay
	}
	now := guard.clock.Now().Unix()
	for key, expiry := range guard.entries {
		if expiry <= now {
			delete(guard.entries, key)
		}
	}
	key := actorID + "\x00" + tokenID
	if _, exists := guard.entries[key]; exists || expiresAt <= now || len(guard.entries) >= MaxReplayEntries {
		return ErrReplay
	}
	guard.entries[key] = expiresAt
	return nil
}
