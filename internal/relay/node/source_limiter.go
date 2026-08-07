// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

var ErrSourceLimiterConfig = errors.New("relay node: invalid source limiter configuration")

type sourceLimitEntryV1 struct {
	windowStart time.Time
	attempts    int
}

type SourceLimiterV1 struct {
	mu          sync.Mutex
	key         []byte
	entries     map[[32]byte]sourceLimitEntryV1
	capacity    int
	maxAttempts int
	window      time.Duration
	now         func() time.Time
	closed      bool
}

func NewSourceLimiterV1(key []byte, capacity, maxAttempts int, window time.Duration, now func() time.Time) (*SourceLimiterV1, error) {
	if len(key) != 32 || capacity <= 0 || capacity > 65536 || maxAttempts <= 0 || maxAttempts > 1024 ||
		window < time.Second || window > time.Hour || now == nil || now().IsZero() {
		return nil, ErrSourceLimiterConfig
	}
	return &SourceLimiterV1{
		key: append([]byte(nil), key...), entries: make(map[[32]byte]sourceLimitEntryV1),
		capacity: capacity, maxAttempts: maxAttempts, window: window, now: now,
	}, nil
}

func (limiter *SourceLimiterV1) Allow(remote net.Addr) bool {
	if limiter == nil {
		return false
	}
	address, ok := canonicalRemoteIPV1(remote)
	if !ok {
		return false
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.closed || len(limiter.key) != 32 {
		return false
	}
	digest := keyedSourceDigestV1(limiter.key, address)
	now := limiter.now().UTC()
	entry, exists := limiter.entries[digest]
	if exists && now.Sub(entry.windowStart) >= limiter.window {
		delete(limiter.entries, digest)
		exists = false
	}
	if !exists && len(limiter.entries) >= limiter.capacity {
		limiter.removeExpiredV1(now)
	}
	if !exists && len(limiter.entries) >= limiter.capacity {
		return false
	}
	if !exists {
		entry = sourceLimitEntryV1{windowStart: now}
	}
	if entry.attempts >= limiter.maxAttempts {
		return false
	}
	entry.attempts++
	limiter.entries[digest] = entry
	return true
}

func (limiter *SourceLimiterV1) Close() {
	if limiter == nil {
		return
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.closed {
		return
	}
	clear(limiter.key)
	limiter.key = nil
	clear(limiter.entries)
	limiter.entries = nil
	limiter.closed = true
}

func (limiter *SourceLimiterV1) removeExpiredV1(now time.Time) {
	for digest, entry := range limiter.entries {
		if now.Sub(entry.windowStart) >= limiter.window {
			delete(limiter.entries, digest)
		}
	}
}

func canonicalRemoteIPV1(remote net.Addr) ([]byte, bool) {
	tcpAddress, ok := remote.(*net.TCPAddr)
	if !ok || tcpAddress == nil || tcpAddress.IP == nil || tcpAddress.Zone != "" {
		return nil, false
	}
	address, ok := netip.AddrFromSlice(tcpAddress.IP)
	if !ok {
		return nil, false
	}
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() {
		return nil, false
	}
	return append([]byte(nil), address.AsSlice()...), true
}

func keyedSourceDigestV1(key, address []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("kurd-relay-source-limit-v1\x00"))
	_, _ = mac.Write(address)
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}
