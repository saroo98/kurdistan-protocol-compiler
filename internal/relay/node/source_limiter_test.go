// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestSourceLimiterV1RetainsOnlyKeyedDigestsAndFailsClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	key := bytes.Repeat([]byte{0x42}, 32)
	limiter, err := NewSourceLimiterV1(key, 2, 2, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer limiter.Close()
	first := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 2000}
	second := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 11), Port: 2001}
	third := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 12), Port: 2002}
	if !limiter.Allow(first) || !limiter.Allow(first) || limiter.Allow(first) {
		t.Fatal("per-source attempt limit not enforced")
	}
	if !limiter.Allow(second) || limiter.Allow(third) {
		t.Fatal("bounded source capacity not enforced")
	}
	if len(limiter.entries) != 2 {
		t.Fatalf("entries=%d", len(limiter.entries))
	}
	now = now.Add(2 * time.Minute)
	if !limiter.Allow(third) {
		t.Fatal("expired entries were not released")
	}
}

func TestSourceLimiterV1RejectsMalformedAndCanBeDestroyed(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	limiter, err := NewSourceLimiterV1(key, 4, 2, time.Minute, func() time.Time { return time.Unix(1_800_000_000, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	if limiter.Allow(&net.UnixAddr{Name: "canary.example", Net: "unix"}) || limiter.Allow(nil) {
		t.Fatal("non-IP source accepted")
	}
	limiter.Close()
	if limiter.Allow(&net.TCPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 2000}) {
		t.Fatal("closed limiter accepted source")
	}
	if bytes.Contains(limiter.key, []byte{0x24}) {
		t.Fatal("limiter key not destroyed")
	}
}
