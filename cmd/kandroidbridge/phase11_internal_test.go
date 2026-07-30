//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"sync"
	"testing"

	"kurdistan/internal/androidbridge"
)

func TestPhase11InternalRoundTripUsesAuthenticatedTransport(t *testing.T) {
	payload := []byte("phase11-android-flow")
	result, code := phase11RoundTrip(payload)
	if code != androidbridge.CodeOK || !bytes.Equal(result, payload) {
		t.Fatalf("code=%d result=%q", code, result)
	}
	clear(result)
}

func TestPhase11InternalRoundTripRejectsBounds(t *testing.T) {
	for _, payload := range [][]byte{nil, make([]byte, phase11MaximumPayloadBytes+1)} {
		if result, code := phase11RoundTrip(payload); result != nil || code == androidbridge.CodeOK {
			t.Fatalf("invalid payload accepted: code=%d bytes=%d", code, len(result))
		}
	}
}

func TestPhase11InternalRoundTripIsConcurrencyIsolated(t *testing.T) {
	const count = 8
	var wait sync.WaitGroup
	failures := make(chan int, count)
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(value byte) {
			defer wait.Done()
			payload := bytes.Repeat([]byte{value}, 257)
			result, code := phase11RoundTrip(payload)
			if code != androidbridge.CodeOK || !bytes.Equal(result, payload) {
				failures <- int(value)
			}
			clear(result)
			clear(payload)
		}(byte(index + 1))
	}
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Fatalf("isolated round trip %d failed", failure)
	}
}
