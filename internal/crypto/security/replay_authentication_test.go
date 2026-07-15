// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
)

func TestReplayStateCommitsOnlyAfterAuthentication(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*SecureEnvelope)
	}{
		{name: "ciphertext", mutate: func(env *SecureEnvelope) { env.Ciphertext[0] ^= 0x80 }},
		{name: "tag", mutate: func(env *SecureEnvelope) { env.Ciphertext[len(env.Ciphertext)-1] ^= 0x80 }},
		{name: "aad stream", mutate: func(env *SecureEnvelope) { env.StreamID++ }},
		{name: "aad semantic", mutate: func(env *SecureEnvelope) { env.Semantic = "close_stream" }},
		{name: "nonce", mutate: func(env *SecureEnvelope) { env.Nonce[0] ^= 0x80 }},
		{name: "transcript identity", mutate: func(env *SecureEnvelope) { env.TranscriptHash = otherHash(env.TranscriptHash) }},
		{name: "capability identity", mutate: func(env *SecureEnvelope) { env.CapabilityHash = otherHash(env.CapabilityHash) }},
	}

	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			sender, receiver := replayCodecPair(t)
			valid := sealReplayTestEnvelope(t, sender, 1)
			forged := cloneSecureEnvelope(valid)
			tt.mutate(&forged)

			before := receiver.replay.Metadata()
			for attempt := 0; attempt < 2; attempt++ {
				if _, err := receiver.Open(forged); err == nil {
					t.Fatal("forged envelope authenticated")
				}
			}
			after := receiver.replay.Metadata()
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("forgery mutated replay state: before=%v after=%v", before, after)
			}
			if _, err := receiver.Open(valid); err != nil {
				t.Fatalf("legitimate retry at the forged sequence failed: %v", err)
			}
		})
	}
}

func TestReplayWindowEdgeForgeryDoesNotConsumeState(t *testing.T) {
	sender, receiver := replayCodecPair(t)
	var edge SecureEnvelope
	for sequence := uint64(1); sequence <= 64; sequence++ {
		edge = sealReplayTestEnvelope(t, sender, sequence)
	}
	forged := cloneSecureEnvelope(edge)
	forged.Ciphertext[len(forged.Ciphertext)-1] ^= 0x01
	before := receiver.replay.Metadata()
	if _, err := receiver.Open(forged); err == nil {
		t.Fatal("forged edge envelope authenticated")
	}
	if after := receiver.replay.Metadata(); !reflect.DeepEqual(after, before) {
		t.Fatalf("edge forgery mutated replay state: before=%v after=%v", before, after)
	}
	if _, err := receiver.Open(edge); err != nil {
		t.Fatalf("valid edge envelope failed after forgery: %v", err)
	}

	_, fresh := replayCodecPair(t)
	tooFar := sealReplayTestEnvelope(t, sender, 65)
	before = fresh.replay.Metadata()
	if _, err := fresh.Open(tooFar); !errors.Is(err, ErrReplay) {
		t.Fatalf("too-far-future envelope error = %v, want ErrReplay", err)
	}
	if after := fresh.replay.Metadata(); !reflect.DeepEqual(after, before) {
		t.Fatalf("too-far-future attempt mutated replay state: before=%v after=%v", before, after)
	}
}

func TestReplayAuthenticatedDuplicateRejectedForSafePolicies(t *testing.T) {
	for _, policy := range []string{"ordered_only", "strict_no_reorder", "bounded_reorder", "windowed_replay"} {
		t.Run(policy, func(t *testing.T) {
			window := NewReplayWindow(policy, 64)
			if err := window.Accept(1); err != nil {
				t.Fatal(err)
			}
			if err := window.Accept(1); !errors.Is(err, ErrReplay) {
				t.Fatalf("authenticated duplicate error = %v, want ErrReplay", err)
			}
		})
	}
}

func TestReplayConcurrentAuthenticatedDuplicateCommitsOnce(t *testing.T) {
	sender, receiver := replayCodecPair(t)
	env := sealReplayTestEnvelope(t, sender, 1)
	const attempts = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := receiver.Open(cloneSecureEnvelope(env)); err == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("authenticated duplicate successes = %d, want 1", successes.Load())
	}
	state := receiver.replay.Metadata()
	if state["highest"] != uint64(1) || state["seen_count"] != 1 {
		t.Fatalf("unexpected committed replay state: %v", state)
	}
}

func replayCodecPair(t *testing.T) (*EnvelopeCodec, *EnvelopeCodec) {
	t.Helper()
	ctx, keys := validContextIdentityFixture(t)
	sender, err := NewEnvelopeCodec(ctx, keys, "client")
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewEnvelopeCodec(ctx, keys, "client")
	if err != nil {
		t.Fatal(err)
	}
	return sender, receiver
}

func sealReplayTestEnvelope(t *testing.T, sender *EnvelopeCodec, sequence uint64) SecureEnvelope {
	t.Helper()
	env, err := sender.Seal(EnvelopeMetadata{
		StreamID:      7,
		Semantic:      "data",
		CarrierFamily: "stream_carrier",
		MetadataClass: "replay-test",
	}, []byte{byte(sequence), 0x42, 0x24})
	if err != nil {
		t.Fatal(err)
	}
	if env.Sequence != sequence {
		t.Fatalf("envelope sequence = %d, want %d", env.Sequence, sequence)
	}
	return env
}

func cloneSecureEnvelope(env SecureEnvelope) SecureEnvelope {
	clone := env
	clone.Nonce = append([]byte(nil), env.Nonce...)
	clone.Ciphertext = append([]byte(nil), env.Ciphertext...)
	return clone
}

func otherHash(value string) string {
	if value[0] == 'a' {
		return "b" + value[1:]
	}
	return "a" + value[1:]
}
