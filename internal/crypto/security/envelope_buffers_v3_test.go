// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package security

import (
	"bytes"
	"errors"
	"testing"
)

func TestEnvelopeBuffersV3ParityAndPreflight(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	for _, mode := range []string{"metadata_authenticated", "synthetic_aead_test", "full_context_bound_envelope"} {
		for _, n := range []int{0, 1, 4080} {
			context := envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, mode)
			old, _ := envelopePairV1(t, schedule, context)
			client, relay := envelopePairV1(t, schedule, context)
			payload := bytes.Repeat([]byte{42}, n)
			dst := bytes.Repeat([]byte{99}, n+16)
			if _, err := client.SealApplicationIntoV1(dst[:len(dst)-1], 2, payload); !errors.Is(err, ErrAEADInvalid) {
				t.Fatal("short seal", err)
			}
			if !bytes.Equal(dst, bytes.Repeat([]byte{99}, len(dst))) {
				t.Fatal("short seal wrote")
			}
			record, err := client.SealApplicationIntoV1(dst, 2, payload)
			if err != nil {
				t.Fatal(err)
			}
			want, err := old.SealApplicationV1(2, payload)
			if err != nil || record.Sequence != 0 || !bytes.Equal(record.Ciphertext, want.Ciphertext) || cap(record.Ciphertext) != len(dst) || &record.Ciphertext[0] != &dst[0] {
				t.Fatal("seal parity/borrow", err)
			}
			out := bytes.Repeat([]byte{99}, n)
			if n > 0 {
				if _, g, e := relay.AuthenticateApplicationIntoV1(out[:n-1], record); g.state != nil || !errors.Is(e, ErrAEADInvalid) {
					t.Fatal("short open", e)
				}
			}
			bad := cloneEnvelopeRecordV1(record)
			bad.Ciphertext[len(bad.Ciphertext)-1] ^= 1
			if p, g, e := relay.AuthenticateApplicationIntoV1(out, bad); p != nil || g.state != nil || !errors.Is(e, ErrAuthenticationFailed) {
				t.Fatal("tag failure", e)
			}
			if !bytes.Equal(out, make([]byte, n)) {
				t.Fatal("tag failure did not clear")
			}
			p, g, e := relay.AuthenticateApplicationIntoV1(out, record)
			if e != nil || !bytes.Equal(p, payload) || cap(p) != n {
				t.Fatal("open parity", e)
			}
			if g.Commit() != nil {
				t.Fatal("commit")
			}
		}
	}
}

func TestEnvelopeBuffersV3RejectOverlapAndBurnFailure(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	client, relay := envelopePairV1(t, schedule, envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated"))
	slab := bytes.Repeat([]byte{3}, 100)
	before := bytes.Clone(slab)
	for _, pair := range [][2][]byte{{slab[:80], slab[:30]}, {slab[1:81], slab[:30]}, {slab[:80], slab[70:90]}} {
		if _, err := client.SealApplicationIntoV1(pair[0], 2, pair[1]); !errors.Is(err, ErrAEADInvalid) {
			t.Fatal("overlap", err)
		}
		if !bytes.Equal(slab, before) {
			t.Fatal("overlap write")
		}
	}
	client.state.sealFail = func() error { return ErrAEADInvalid }
	if _, err := client.SealApplicationIntoV1(slab, 2, []byte{1}); !errors.Is(err, ErrAEADInvalid) {
		t.Fatal(err)
	}
	client.state.sealFail = nil
	record, err := client.SealApplicationIntoV1(slab, 2, []byte{1})
	if err != nil || record.Sequence != 1 {
		t.Fatal("burn", err)
	}
	if _, g, e := relay.AuthenticateApplicationIntoV1(record.Ciphertext[:1], record); g.state != nil || !errors.Is(e, ErrAEADInvalid) {
		t.Fatal("open overlap", e)
	}
}

func TestEnvelopeBuffersV3WarmAllocationAndFailedAuthStorage(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	context := envelopeContextFixtureV1(NonceModeStreamPartitionedCounterV1, ReplayPolicyWindowedReplayV1, 65, "full_context_bound_envelope")
	c, e := NewClientEnvelopeBoundedV3(schedule, context)
	if e != nil {
		t.Fatal(e)
	}
	defer c.DestroyBoundedV3()
	r, e := NewRelayEnvelopeBoundedV3(schedule, context)
	if e != nil {
		t.Fatal(e)
	}
	defer r.DestroyBoundedV3()
	payload := make([]byte, 1536)
	dst := make([]byte, 1552)
	out := make([]byte, 1536)
	seal := testing.AllocsPerRun(1000, func() {
		if _, e := c.SealApplicationIntoV1(dst, 7, payload); e != nil {
			panic(e)
		}
	})
	record, e := c.SealApplicationIntoV1(dst, 7, payload)
	if e != nil {
		t.Fatal(e)
	}
	before := r.state.windows[7].MetadataV1()
	bits := append([]uint64(nil), r.state.windows[7].state.bitmap...)
	record.Ciphertext[len(record.Ciphertext)-1] ^= 1
	if p, g, e := r.AuthenticateApplicationIntoV1(out, record); e == nil || p != nil || g.state != nil {
		t.Fatal("bad tag")
	}
	if before != r.state.windows[7].MetadataV1() {
		t.Fatal("unauthenticated presence")
	}
	for i, v := range bits {
		if r.state.windows[7].state.bitmap[i] != v {
			t.Fatal("unauthenticated bit")
		}
	}
	record.Ciphertext[len(record.Ciphertext)-1] ^= 1
	auth := testing.AllocsPerRun(1000, func() {
		_, g, e := r.AuthenticateApplicationIntoV1(out, record)
		if e != nil {
			panic(e)
		}
		if e = g.Discard(); e != nil {
			panic(e)
		}
	})
	t.Logf("warm seal=%g allocations; authenticate+fresh grant+discard=%g allocations", seal, auth)
	// Per-call nonce/AAD scratch may escape. Authentication additionally creates
	// fresh state and grant identities; neither owns plaintext output backing.
	if seal > 3 || auth > 5 {
		t.Fatal("unexpected per-record allocation growth")
	}
}
