// SPDX-License-Identifier: AGPL-3.0-or-later
package security

import (
	"errors"
	"testing"
)

func TestReplayPolicyEnvelopeV1(t *testing.T) {
	for _, window := range []int{2, 4, 4096} {
		t.Run("ordered_only", func(t *testing.T) {
			_, relay, records := replayRecordsV1(t, ReplayPolicyOrderedOnlyV1, window, window+3)
			mustOpenApplicationV1(t, relay, records[0])
			if plaintext, err := relay.OpenApplicationV1(records[2]); plaintext != nil || !errors.Is(err, ErrReplayOutOfOrder) {
				t.Fatalf("ordered out-of-order window=%d: %q %v", window, plaintext, err)
			}
			if plaintext, err := relay.OpenApplicationV1(records[window+2]); plaintext != nil || !errors.Is(err, ErrReplayTooFarFuture) {
				t.Fatalf("ordered future window=%d: %q %v", window, plaintext, err)
			}
			if plaintext, err := relay.OpenApplicationV1(records[0]); plaintext != nil || !errors.Is(err, ErrReplayDuplicate) {
				t.Fatalf("ordered duplicate: %q %v", plaintext, err)
			}
			for i := 1; i <= window+1; i++ {
				mustOpenApplicationV1(t, relay, records[i])
			}
			if plaintext, err := relay.OpenApplicationV1(records[0]); plaintext != nil || !errors.Is(err, ErrReplayStale) {
				t.Fatalf("ordered stale: %q %v", plaintext, err)
			}
		})
		t.Run("bounded_reorder", func(t *testing.T) {
			_, relay, records := replayRecordsV1(t, ReplayPolicyBoundedReorderV1, window, 2*window+2)
			mustOpenApplicationV1(t, relay, records[0])
			mustOpenApplicationV1(t, relay, records[window])
			if plaintext, err := relay.OpenApplicationV1(records[window]); plaintext != nil || !errors.Is(err, ErrReplayDuplicate) {
				t.Fatalf("bounded duplicate: %q %v", plaintext, err)
			}
			if plaintext, err := relay.OpenApplicationV1(records[2*window+1]); plaintext != nil || !errors.Is(err, ErrReplayTooFarFuture) {
				t.Fatalf("bounded future: %q %v", plaintext, err)
			}
			for i := window + 1; i <= 2*window; i++ {
				mustOpenApplicationV1(t, relay, records[i])
			}
			if plaintext, err := relay.OpenApplicationV1(records[0]); plaintext != nil || !errors.Is(err, ErrReplayStale) {
				t.Fatalf("bounded stale: %q %v", plaintext, err)
			}
		})
		t.Run("windowed_replay", func(t *testing.T) {
			_, relay, records := replayRecordsV1(t, ReplayPolicyWindowedReplayV1, window, window+2)
			mustOpenApplicationV1(t, relay, records[window+1])
			mustOpenApplicationV1(t, relay, records[window])
			if plaintext, err := relay.OpenApplicationV1(records[window]); plaintext != nil || !errors.Is(err, ErrReplayDuplicate) {
				t.Fatalf("window duplicate: %q %v", plaintext, err)
			}
			if plaintext, err := relay.OpenApplicationV1(records[0]); plaintext != nil || !errors.Is(err, ErrReplayStale) {
				t.Fatalf("window stale: %q %v", plaintext, err)
			}
		})
	}
}

func TestPolicyMatrixEnvelopeClassOwnerWitnessAuthenticatedContextV1(t *testing.T) {
	ownerIDs := map[string]string{"metadata_authenticated": "pm-owner:envelope/metadata_authenticated", "synthetic_aead_test": "pm-owner:envelope/synthetic_aead_test", "full_context_bound_envelope": "pm-owner:envelope/full_context_bound_envelope"}
	type row struct {
		name, mode      string
		wantClass       uint16
		contextMutation bool
		mutate          func(*EnvelopeContextV1, *EnvelopeRecordV1)
		want            error
	}
	rows := []row{
		{"metadata/class1-cross-class", "metadata_authenticated", RecordClassApplicationV1, false, func(_ *EnvelopeContextV1, r *EnvelopeRecordV1) { r.RecordType = 2 }, ErrNonceMismatch},
		{"synthetic/class2-cross-class", "synthetic_aead_test", RecordClassSyntheticV1, false, func(_ *EnvelopeContextV1, r *EnvelopeRecordV1) { r.RecordType = 2 }, ErrNonceMismatch},
		{"full-context/class1-context-hash", "full_context_bound_envelope", RecordClassApplicationV1, true, func(c *EnvelopeContextV1, _ *EnvelopeRecordV1) { c.CarrierContextHash[0] ^= 1 }, ErrAuthenticationFailed},
		{"metadata/class1-aead", "metadata_authenticated", RecordClassApplicationV1, false, func(_ *EnvelopeContextV1, r *EnvelopeRecordV1) { r.Ciphertext[len(r.Ciphertext)-1] ^= 1 }, ErrAuthenticationFailed},
	}
	for _, tc := range rows {
		t.Run(ownerIDs[tc.mode]+"/"+tc.name, func(t *testing.T) {
			schedule := mustNonceScheduleV1(t)
			defer schedule.Destroy()
			context := envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 4, tc.mode)
			client, relay := envelopePairV1(t, schedule, context)
			if class, err := client.ExpectedClassV1(); err != nil || class != tc.wantClass {
				t.Fatalf("valid owner class=%d err=%v", class, err)
			}
			record, err := client.SealApplicationV1(3, []byte("owner-valid"))
			if err != nil {
				t.Fatal(err)
			}
			mutatedContext := context
			mutatedRecord := cloneEnvelopeRecordV1(record)
			mutations := 0
			tc.mutate(&mutatedContext, &mutatedRecord)
			mutations++
			if tc.contextMutation {
				var createErr error
				relay, createErr = NewRelayEnvelopeV1(schedule, mutatedContext)
				if createErr != nil {
					t.Fatalf("single context mutation rejected before production open: %v", createErr)
				}
			}
			plaintext, actual := relay.OpenApplicationV1(mutatedRecord)
			if mutations != 1 || plaintext != nil || actual == nil || !errors.Is(actual, tc.want) || actual.Error() != tc.want.Error() {
				t.Fatalf("mutations=%d plaintext=%q error=%v want=%v", mutations, plaintext, actual, tc.want)
			}
		})
	}

	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	invalid := envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 4, "full_context_bound_envelope")
	invalid.FramingHash = [32]byte{}
	_, err := NewClientEnvelopeV1(KeySchedule{}, invalid)
	if err == nil || !errors.Is(err, ErrEnvelopeContextInvalid) || err.Error() != ErrEnvelopeContextInvalid.Error() {
		t.Fatalf("context precedence error=%v", err)
	}
}

func TestReplayPolicyAuthenticationBeforeLazyCommitV1(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeStreamPartitionedCounterV1, ReplayPolicyWindowedReplayV1, 4, "metadata_authenticated"))
	record, err := client.SealApplicationV1(9, []byte("valid"))
	if err != nil {
		t.Fatal(err)
	}
	bad := cloneEnvelopeRecordV1(record)
	bad.Ciphertext[len(bad.Ciphertext)-1] ^= 1
	if plaintext, err := relay.OpenApplicationV1(bad); plaintext != nil || !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("forged open: %q %v", plaintext, err)
	}
	if len(relay.state.replay) != 0 {
		t.Fatalf("failed authentication installed %d replay domains", len(relay.state.replay))
	}
	if _, err := relay.OpenApplicationV1(record); err != nil {
		t.Fatalf("valid empty record after size reject: %v", err)
	}
	if len(relay.state.replay) != 1 || relay.state.replay[9].MetadataV1().Highest != 0 {
		t.Fatal("valid sequence zero did not commit exactly once")
	}
}

func TestEnvelopeV1PolicyAuthorityBoundsAndErrorPath(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	base := envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 4, "metadata_authenticated")
	for _, mutate := range []func(*EnvelopeContextV1){
		func(v *EnvelopeContextV1) { v.EffectivePolicy.NonceMode = "unknown" },
		func(v *EnvelopeContextV1) { v.EffectivePolicy.ReplayPolicy = "unknown" },
		func(v *EnvelopeContextV1) { v.EffectivePolicy.ReplayWindowSize = 1 },
		func(v *EnvelopeContextV1) { v.EffectivePolicy.SecureEnvelopeMode = "unknown" },
		func(v *EnvelopeContextV1) { v.EffectivePolicy.AEADSuite = "unknown" },
	} {
		bad := base
		mutate(&bad)
		if _, err := NewClientEnvelopeV1(schedule, bad); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("invalid effective policy: %v", err)
		}
		if _, err := NewClientEnvelopeV1(KeySchedule{}, bad); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("policy precedence over invalid schedule: %v", err)
		}
	}
	missingFull := envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 4, "full_context_bound_envelope")
	missingFull.ProfileHash = [32]byte{}
	if _, err := NewRelayEnvelopeV1(KeySchedule{}, missingFull); !errors.Is(err, ErrEnvelopeContextInvalid) {
		t.Fatalf("context precedence over invalid schedule: %v", err)
	}
	base.MaxEnvelopeBytes = 16
	client, relay := envelopePairV1(t, schedule, base)
	if _, err := client.SealApplicationV1(1, []byte{1}); !errors.Is(err, ErrAEADInvalid) {
		t.Fatalf("oversized seal: %v", err)
	}
	record, err := client.SealApplicationV1(1, nil)
	if err != nil || record.Sequence != 0 {
		t.Fatalf("size reject allocated sequence: %+v %v", record, err)
	}
	undersized := cloneEnvelopeRecordV1(record)
	undersized.Ciphertext = undersized.Ciphertext[:15]
	undersized.SealedLength = 15
	if plaintext, err := relay.OpenApplicationV1(undersized); plaintext != nil || !errors.Is(err, ErrAEADInvalid) {
		t.Fatalf("undersized open: %q %v", plaintext, err)
	}
	if len(relay.state.replay) != 0 {
		t.Fatal("invalid size created replay state")
	}
	if _, err := relay.OpenApplicationV1(record); err != nil {
		t.Fatalf("valid empty record after size reject: %v", err)
	}
}

func TestEnvelopeModeFullContextTamperV1(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	context := envelopeContextFixtureV1(NonceModeCounterAppendBaseV1, ReplayPolicyWindowedReplayV1, 4, "full_context_bound_envelope")
	client, _ := envelopePairV1(t, schedule, context)
	record, err := client.SealApplicationV1(1, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*EnvelopeContextV1){
		func(v *EnvelopeContextV1) { v.CapabilityHash[0] ^= 1 },
		func(v *EnvelopeContextV1) { v.ProfileHash[0] ^= 1 },
		func(v *EnvelopeContextV1) { v.FramingHash[0] ^= 1 },
		func(v *EnvelopeContextV1) { v.CarrierContextHash[0] ^= 1 },
	} {
		peerContext := context
		mutate(&peerContext)
		peer, err := NewRelayEnvelopeV1(schedule, peerContext)
		if err != nil {
			t.Fatal(err)
		}
		if plaintext, err := peer.OpenApplicationV1(record); plaintext != nil || !errors.Is(err, ErrAuthenticationFailed) || len(peer.state.replay) != 0 {
			t.Fatalf("context tamper: %q %v replay=%d", plaintext, err, len(peer.state.replay))
		}
	}
}

func replayRecordsV1(t *testing.T, policy string, window, count int) (*EnvelopeCodecV1, *EnvelopeCodecV1, []EnvelopeRecordV1) {
	t.Helper()
	schedule := mustNonceScheduleV1(t)
	t.Cleanup(schedule.Destroy)
	client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, policy, window, "metadata_authenticated"))
	records := make([]EnvelopeRecordV1, count)
	for i := range records {
		var err error
		records[i], err = client.SealApplicationV1(1, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	return client, relay, records
}

func mustOpenApplicationV1(t *testing.T, codec *EnvelopeCodecV1, record EnvelopeRecordV1) {
	t.Helper()
	plaintext, err := codec.OpenApplicationV1(record)
	if err != nil || plaintext == nil {
		t.Fatalf("open sequence %d: %x %v", record.Sequence, plaintext, err)
	}
}
