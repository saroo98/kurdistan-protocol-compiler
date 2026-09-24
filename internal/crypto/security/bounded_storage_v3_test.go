// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package security

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"reflect"
	goruntime "runtime"
	"strings"
	"testing"
	"unsafe"
)

func TestEnvelopeStorageOwnedBytesV3PolicyParityAndContextBoundary(t *testing.T) {
	for _, mode := range []string{NonceModeCounterXORBaseV1, NonceModeCounterAppendBaseV1, NonceModeDirectionalCounterV1, NonceModeStreamPartitionedCounterV1} {
		for _, replay := range []string{ReplayPolicyOrderedOnlyV1, ReplayPolicyBoundedReorderV1, ReplayPolicyWindowedReplayV1} {
			for _, window := range []int{2, 64, 65, 4096} {
				c := envelopeContextFixtureV1(mode, replay, window, "full_context_bound_envelope")
				got, err := EnvelopeStorageOwnedBytesV3(c.EffectivePolicy)
				want, actualErr := EnvelopeOwnedBytesV3(c)
				if err != nil || actualErr != nil || got != want {
					t.Fatalf("parity %s/%s/%d %d %d %v %v", mode, replay, window, got, want, err, actualErr)
				}
				p := c.EffectivePolicy
				p.ProfileID += "x"
				grown, err := EnvelopeStorageOwnedBytesV3(p)
				if err != nil || grown != got+1 {
					t.Fatal("policy text not charged", err)
				}
				c.TranscriptHash = [32]byte{}
				if _, err := EnvelopeOwnedBytesV3(c); !errors.Is(err, ErrEnvelopeContextInvalid) {
					t.Fatal("real context validation weakened", err)
				}
			}
		}
	}
	c := envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated")
	c.EffectivePolicy.ProfileID = strings.Repeat("x", 257)
	if _, err := EnvelopeStorageOwnedBytesV3(c.EffectivePolicy); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal("uncapped text", err)
	}
}

// Catches storage selection changing nonce domains, ciphertext or replay commitment.
func TestBoundedStorageV3Parity(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	for _, mode := range []string{NonceModeCounterXORBaseV1, NonceModeCounterAppendBaseV1, NonceModeDirectionalCounterV1, NonceModeStreamPartitionedCounterV1} {
		for _, policy := range []string{ReplayPolicyOrderedOnlyV1, ReplayPolicyBoundedReorderV1, ReplayPolicyWindowedReplayV1} {
			t.Run(mode+"/"+policy, func(t *testing.T) {
				context := envelopeContextFixtureV1(mode, policy, 7, "full_context_bound_envelope")
				oldClient, oldRelay := envelopePairV1(t, schedule, context)
				client, err := NewClientEnvelopeBoundedV3(schedule, context)
				if err != nil {
					t.Fatal(err)
				}
				relay, err := NewRelayEnvelopeBoundedV3(schedule, context)
				if err != nil {
					t.Fatal(err)
				}
				defer client.DestroyBoundedV3()
				defer relay.DestroyBoundedV3()
				for _, pair := range [][4]*EnvelopeCodecV1{{oldClient, client, oldRelay, relay}, {oldRelay, relay, oldClient, client}} {
					copied := *pair[1]
					for i, slot := range []uint16{1, 65535, 1, 2, 65534, 1} {
						payload := []byte{byte(i), 42}
						a, e1 := pair[0].SealApplicationV1(slot, payload)
						b, e2 := copied.SealApplicationV1(slot, payload)
						if e1 != nil || e2 != nil || a.Sequence != b.Sequence || a.Slot != b.Slot || a.Direction != b.Direction || !bytes.Equal(a.Ciphertext, b.Ciphertext) {
							t.Fatalf("seal parity %v %v", e1, e2)
						}
						pa, ga, e1 := pair[2].AuthenticateApplicationV1(a)
						pb, gb, e2 := pair[3].AuthenticateApplicationV1(b)
						if e1 != nil || e2 != nil || !bytes.Equal(pa, pb) {
							t.Fatalf("auth parity %v %v", e1, e2)
						}
						if ga.Commit() != nil || gb.Commit() != nil {
							t.Fatal("commit")
						}
						if !errors.Is(gb.Commit(), ErrReplayDuplicate) {
							t.Fatal("reused capability")
						}
						_, _, e1 = pair[2].AuthenticateApplicationV1(a)
						_, _, e2 = pair[3].AuthenticateApplicationV1(b)
						if e1 != e2 {
							t.Fatalf("replay parity %v %v", e1, e2)
						}
					}
				}
			})
		}
	}
}

func TestBoundedStorageV3ReplayDifferential(t *testing.T) {
	for _, policy := range []string{ReplayPolicyOrderedOnlyV1, ReplayPolicyBoundedReorderV1, ReplayPolicyWindowedReplayV1} {
		for _, window := range []int{2, 3, 7, 8, 32, 64, 65, 128, 256, 4095, 4096} {
			t.Run(fmt.Sprintf("%s/%d", policy, window), func(t *testing.T) {
				old, _ := NewReplayWindowV1(policy, window)
				slots := newReplayArenaV3(envelopeContextFixtureV1(NonceModeDirectionalCounterV1, policy, window, "metadata_authenticated"))
				bounded := &slots[0]
				values := []uint64{0, 0, uint64(window), uint64(window) + 1, 1, uint64(window * 2), uint64(window*2 + 1), 1, math.MaxUint64 - uint64(window), math.MaxUint64 - 1, math.MaxUint64, math.MaxUint64, 0}
				for i := 0; i < window*3; i++ {
					values = append(values, uint64(i))
					if i%3 == 0 {
						values = append(values, uint64(i/2))
					}
				}
				for _, n := range values {
					if a, b := old.Plausible(n), bounded.Plausible(n); a != b {
						t.Fatalf("precheck %d %v %v", n, a, b)
					}
					if a, b := old.CommitAuthenticated(n), bounded.CommitAuthenticated(n); a != b {
						t.Fatalf("commit %d %v %v", n, a, b)
					}
					if old.MetadataV1() != bounded.MetadataV1() {
						t.Fatalf("metadata %d", n)
					}
				}
				old.state.initialized = true
				old.state.highest = math.MaxUint64 - 1
				clear(old.state.seen)
				bounded.state.initialized = true
				bounded.state.highest = math.MaxUint64 - 1
				clear(bounded.state.bitmap)
				for _, n := range []uint64{math.MaxUint64, math.MaxUint64, 0} {
					if old.CommitAuthenticated(n) != bounded.CommitAuthenticated(n) || old.MetadataV1() != bounded.MetadataV1() {
						t.Fatal("uint64 boundary")
					}
				}
			})
		}
	}
}

func TestBoundedStorageV3ArenasExhaustionAndAccounting(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	for _, mode := range []string{NonceModeCounterXORBaseV1, NonceModeCounterAppendBaseV1, NonceModeDirectionalCounterV1, NonceModeStreamPartitionedCounterV1} {
		context := envelopeContextFixtureV1(mode, ReplayPolicyWindowedReplayV1, 4096, "metadata_authenticated")
		c, err := NewClientEnvelopeBoundedV3(schedule, context)
		if err != nil {
			t.Fatal(err)
		}
		s := c.state
		n := s.boundedClient.outbound
		d := nonceDomainsV3(mode)
		if s.replay != nil || n.sequences != nil || len(s.windows) != d || cap(s.windows) != d || len(n.fixed) != d || cap(n.fixed) != d {
			t.Fatal("wrong arenas")
		}
		var previous uintptr
		for i := range s.windows {
			w := s.windows[i].state
			if w.seen != nil || len(w.bitmap) != 64 || cap(w.bitmap) != 64 {
				t.Fatal("bitmap")
			}
			address := uintptr(unsafe.Pointer(&w.bitmap[0]))
			if i > 0 && address-previous != 512 {
				t.Fatal("bitmap overlap/gap")
			}
			previous = address
			if i > 0 && uintptr(unsafe.Pointer(w))-uintptr(unsafe.Pointer(s.windows[i-1].state)) != unsafe.Sizeof(*w) {
				t.Fatal("state unstable")
			}
		}
		for _, slot := range []uint16{1, 65535} {
			key := uint16(0)
			if d > 1 {
				key = slot
			}
			n.fixed[key] = nonceSequenceStateV1{next: math.MaxUint64}
			last, e := c.SealApplicationV1(slot, nil)
			if e != nil || last.Sequence != math.MaxUint64 {
				t.Fatal("last", e)
			}
			if _, e = c.SealApplicationV1(slot, nil); !errors.Is(e, ErrNonceExhausted) {
				t.Fatal("exhaustion")
			}
		}
		estimate, e := EnvelopeOwnedBytesV3(context)
		if e != nil {
			t.Fatal(e)
		}
		arena := uint64(d) * (uint64(unsafe.Sizeof(nonceSequenceStateV1{})) + uint64(unsafe.Sizeof(ReplayWindowV1{})) + uint64(unsafe.Sizeof(replayWindowStateV1{})) + 512)
		textBytes := uint64(0)
		policy := reflect.ValueOf(c.context.EffectivePolicy)
		for i := 0; i < policy.NumField(); i++ {
			v := policy.Field(i)
			if v.Kind() == reflect.String {
				textBytes += uint64(v.Len())
			}
		}
		descriptors := uint64(0)
		for _, list := range [][]string{c.context.EffectivePolicy.ClientMandatoryCapabilities, c.context.EffectivePolicy.ServerMandatoryCapabilities, c.context.EffectivePolicy.SelectedCapabilities} {
			if len(list) != cap(list) {
				t.Fatal("descriptor capacity")
			}
			descriptors += uint64(cap(list)) * uint64(unsafe.Sizeof(""))
			for _, v := range list {
				textBytes += uint64(len(v))
			}
		}
		// The four captured methods each retain code+receiver words. Shared receiver
		// and arena views are charged exactly once, plus one fresh live state/grant.
		fixed := uint64(unsafe.Sizeof(*c)) + uint64(unsafe.Sizeof(*s)) + uint64(unsafe.Sizeof(*s.boundedClient)) + uint64(unsafe.Sizeof(*n)) + uint64(unsafe.Sizeof(*s.replayAuthority)) + 8*uint64(unsafe.Sizeof(uintptr(0))) + uint64(unsafe.Sizeof(authenticatedReplayStateV1{})) + uint64(unsafe.Sizeof(authenticatedReplayGrantV1{})) + boundedAESAllowanceV3 + 444 + uint64(unsafe.Sizeof(NonceAllocationV1{})) + 12 + descriptors + textBytes
		if estimate != arena+fixed {
			t.Fatalf("estimator=%d actual capacities+fixed=%d", estimate, arena+fixed)
		}
		t.Logf("mode=%s nonceState=%d replayWindow=%d replayState=%d fixed=%d arenas=%d owned=%d scratch=%d", mode, unsafe.Sizeof(nonceSequenceStateV1{}), unsafe.Sizeof(ReplayWindowV1{}), unsafe.Sizeof(replayWindowStateV1{}), fixed, arena, estimate, boundedEnvelopeScratchV3)
		nonceView := n.fixed
		bitmapView := s.windows[d-1].state.bitmap
		_ = c.DestroyBoundedV3()
		if !reflect.DeepEqual(nonceView, make([]nonceSequenceStateV1, d)) || !reflect.DeepEqual(bitmapView, make([]uint64, 64)) {
			t.Fatal("retained arenas not cleared")
		}
	}
}

func TestBoundedStorageV3NoCounterOrReplayGrowth(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	context := envelopeContextFixtureV1(NonceModeStreamPartitionedCounterV1, ReplayPolicyWindowedReplayV1, 65, "metadata_authenticated")
	c, err := NewClientEnvelopeBoundedV3(schedule, context)
	if err != nil {
		t.Fatal(err)
	}
	defer c.DestroyBoundedV3()
	n := c.state.boundedClient
	window := &c.state.windows[65534]
	sequence := uint64(0)
	if got := testing.AllocsPerRun(1000, func() {
		_, e := n.AllocateOutboundApplicationV1(65534)
		if e != nil {
			panic(e)
		}
		if e = window.CommitAuthenticated(sequence); e != nil {
			panic(e)
		}
		sequence++
	}); got != 0 {
		t.Fatalf("storage allocs=%g", got)
	}
}

func TestBoundedStorageV3AESAllowance(t *testing.T) {
	key := make([]byte, 32)
	a, e := newAEADV1(key)
	if e != nil {
		t.Fatal(e)
	}
	size := reflect.TypeOf(a).Elem().Size()
	if 2*uint64(size) > boundedAESAllowanceV3 {
		t.Fatal("retained crypto exceeds allowance")
	}
	var before, after goruntime.MemStats
	goruntime.GC()
	goruntime.ReadMemStats(&before)
	for i := 0; i < 100; i++ {
		a, e = newAEADV1(key)
		if e != nil {
			t.Fatal(e)
		}
	}
	goruntime.ReadMemStats(&after)
	goruntime.KeepAlive(a)
	perPair := 2 * (after.TotalAlloc - before.TotalAlloc) / 100
	t.Logf("AEAD concrete=%d bytes; measured pair construction=%d bytes", size, perPair)
	if perPair > boundedAESAllowanceV3 {
		t.Fatal("crypto construction allowance needs review")
	}
}

func TestBoundedStorageV3DestroyCopiesAndLegacy(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	context := envelopeContextFixtureV1(NonceModeDirectionalCounterV1, ReplayPolicyWindowedReplayV1, 64, "metadata_authenticated")
	old, _ := envelopePairV1(t, schedule, context)
	if !errors.Is(old.DestroyBoundedV3(), ErrInvalidConfig) {
		t.Fatal("destroy legacy")
	}
	if _, err := old.SealApplicationV1(2, []byte{1}); err != nil {
		t.Fatal(err)
	}
	client, err := NewClientEnvelopeBoundedV3(schedule, context)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewRelayEnvelopeBoundedV3(schedule, context)
	if err != nil {
		t.Fatal(err)
	}
	record, err := client.SealApplicationV1(2, []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	_, grant, err := relay.AuthenticateApplicationV1(record)
	if err != nil {
		t.Fatal(err)
	}
	copied := *relay
	if err = relay.DestroyBoundedV3(); err != nil {
		t.Fatal(err)
	}
	if err = relay.DestroyBoundedV3(); err != nil {
		t.Fatal(err)
	}
	if grant.Commit() == nil {
		t.Fatal("destroyed authority committed")
	}
	if _, _, err = copied.AuthenticateApplicationV1(record); err == nil {
		t.Fatal("destroyed copy authenticated")
	}
	if _, err = copied.SealApplicationV1(2, nil); err == nil {
		t.Fatal("destroyed copy sealed")
	}
	_ = client.DestroyBoundedV3()
}
