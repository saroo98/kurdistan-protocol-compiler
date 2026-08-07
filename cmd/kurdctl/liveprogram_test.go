// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestLiveProgramCapabilityConventionIsPinned(t *testing.T) {
	want := []string{
		"multi_stream", "proxy_semantics", "carrier_abstraction", "adapter_interface", "carrier_loss_recovery",
		"carrier_backpressure", "generated_backend", "transcript_binding", "replay_window", "nonce_schedule",
	}
	if !equalStringsV1(liveProgramCapabilitiesV1, want) {
		t.Fatalf("live capability convention=%v want=%v", liveProgramCapabilitiesV1, want)
	}
}

func TestCompileLiveProgramRetriesOnlyForbiddenMaterialCollision(t *testing.T) {
	random := bytes.NewReader([]byte{
		0, 0, 0, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 2,
	})
	calls := 0
	encoded, err := compileLiveProgramWithV1(random, func(seed int64) ([]byte, bool, error) {
		calls++
		if calls == 1 {
			return nil, true, nil
		}
		if seed != 2 {
			t.Fatalf("second seed=%d want=2", seed)
		}
		return []byte{0x01, 0x02}, false, nil
	})
	if err != nil || !bytes.Equal(encoded, []byte{0x01, 0x02}) || calls != 2 {
		t.Fatalf("encoded=%x calls=%d err=%v", encoded, calls, err)
	}
}

func TestCompileLiveProgramStopsOnCandidateFailure(t *testing.T) {
	want := errors.New("candidate failed")
	calls := 0
	_, err := compileLiveProgramWithV1(bytes.NewReader(make([]byte, 16)), func(int64) ([]byte, bool, error) {
		calls++
		return nil, false, want
	})
	if !errors.Is(err, want) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestCompileLiveProgramFailsClosedAfterCollisionBudget(t *testing.T) {
	calls := 0
	_, err := compileLiveProgramWithV1(bytes.NewReader(make([]byte, 8*maxLiveProgramCompileAttemptsV1)), func(int64) ([]byte, bool, error) {
		calls++
		return nil, true, nil
	})
	if !errors.Is(err, errCLIInvalidInput) || calls != maxLiveProgramCompileAttemptsV1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
