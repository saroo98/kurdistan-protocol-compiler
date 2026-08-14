// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"
	"time"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/protocol/liveprogram"
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

func TestCompileLiveProgramCandidateClassifiesUnsafeProjectionAsCollision(t *testing.T) {
	encoded, collision, err := compileLiveProgramCandidateV1(1_610_178_124_615_707_266)
	if err != nil || !collision || len(encoded) != 0 {
		t.Fatalf("encoded=%x collision=%v err=%v", encoded, collision, err)
	}
}

func TestCompileLiveProgramHighRangeCandidatesAreUsableOrRetryable(t *testing.T) {
	rng := rand.New(rand.NewSource(17017))
	collisions := 0
	for index := 0; index < 2048; index++ {
		seed := rng.Int63()
		if seed == 0 {
			seed = 1
		}
		encoded, collision, err := compileLiveProgramCandidateV1(seed)
		if err != nil {
			t.Fatalf("candidate %d failed: %v", index, err)
		}
		if collision {
			collisions++
			if len(encoded) != 0 {
				t.Fatalf("candidate %d returned bytes with collision", index)
			}
			continue
		}
		if _, err := liveprogram.DecodeV1(encoded); err != nil {
			t.Fatalf("candidate %d decode: %v", index, err)
		}
	}
	if collisions == 0 {
		t.Fatal("high-range sample did not exercise a retryable projection collision")
	}
}

func TestCompileLiveProgramCandidateUsesLiveSessionBounds(t *testing.T) {
	for _, seed := range []int64{72_623_859_790_382_856, 144_964_032_628_459_529, 217_304_205_466_536_202} {
		encoded, collision, err := compileLiveProgramCandidateV1(seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if collision {
			t.Fatalf("seed %d: product-safe candidate reported a forbidden collision", seed)
		}
		program, err := liveprogram.DecodeV1(encoded)
		if err != nil {
			t.Fatalf("seed %d decode: %v", seed, err)
		}
		if got, want := time.Duration(program.Limits.MaxSessionMillis)*time.Millisecond, 24*time.Hour; got != want {
			t.Fatalf("seed %d session lifetime=%s want=%s", seed, got, want)
		}
		if program.Limits.MaxSessionMessages != 1<<24 {
			t.Fatalf("seed %d session messages=%d want=%d", seed, program.Limits.MaxSessionMessages, 1<<24)
		}
		if program.Limits.MaxKeyLifetimeMessages != 1<<16 {
			t.Fatalf("seed %d key lifetime messages=%d want=%d", seed, program.Limits.MaxKeyLifetimeMessages, 1<<16)
		}
		if program.Security.Policy.MaxSessionMessages != program.Limits.MaxSessionMessages ||
			program.Security.Policy.MaxKeyLifetimeMessages != program.Limits.MaxKeyLifetimeMessages {
			t.Fatalf("seed %d security and live limits diverged", seed)
		}
	}
}

func TestCompileLiveProgramCandidateBuildsProjectedProcessHandshake(t *testing.T) {
	for seed := int64(1); seed <= 512; seed++ {
		encoded, collision, err := compileLiveProgramCandidateV1(seed)
		if err != nil {
			t.Fatalf("seed %d compile: %v", seed, err)
		}
		if collision {
			continue
		}
		program, err := liveprogram.DecodeV1(encoded)
		if err != nil {
			t.Fatalf("seed %d decode: %v", seed, err)
		}
		if _, err := auth.NewProjectedProcessHandshakeConfigV1("client.phase17", "relay.phase17", program, "tls13-tcp"); err != nil {
			t.Fatalf("seed %d projected process handshake rejected live program: %v", seed, err)
		}
	}
}
