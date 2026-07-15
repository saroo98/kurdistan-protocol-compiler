// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
)

func TestNonceV1LegacyCharacterization(t *testing.T) {
	t.Run("exact-base-empty-mode", func(t *testing.T) {
		base := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
		legacy := NewNonceManager("client", base, "")
		base[0] ^= 0xff
		if legacy.Mode != "directional_counter" || !bytes.Equal(legacy.Base, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}) {
			t.Fatalf("exact base/empty mode = (%q,%x)", legacy.Mode, legacy.Base)
		}
	})
	for _, tc := range []struct {
		name string
		base []byte
	}{
		{"empty-base-explicit-mode", nil},
		{"short-base-explicit-mode", []byte("short")},
		{"long-base-explicit-mode", []byte("a deliberately long nonce base")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := append([]byte(nil), tc.base...)
			wantHash := sha256.Sum256(input)
			legacy := NewNonceManager("client", input, "counter_xor_base")
			if len(input) != 0 {
				input[0] ^= 0xff
			}
			if legacy.Mode != "counter_xor_base" || !bytes.Equal(legacy.Base, wantHash[:nonceBytesV1]) {
				t.Fatalf("malformed base/explicit mode = (%q,%x), want (counter_xor_base,%x)", legacy.Mode, legacy.Base, wantHash[:nonceBytesV1])
			}
		})
	}

	base := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	var one [8]byte
	binary.BigEndian.PutUint64(one[:], 1)
	wantXOR := append([]byte(nil), base...)
	for i := range one {
		wantXOR[4+i] ^= one[i]
	}
	for _, mode := range []string{"counter_xor_base", "directional_counter", "stream_partitioned_counter"} {
		client := NewNonceManager("client", base, mode)
		got, seq, err := client.Next()
		if err != nil || seq != 1 || !bytes.Equal(got, wantXOR) {
			t.Fatalf("mode %s client = (%x,%d,%v), want (%x,1,nil)", mode, got, seq, err, wantXOR)
		}
		serverWant := append([]byte(nil), wantXOR...)
		serverWant[0] ^= 0x80
		server := NewNonceManager("server", base, mode)
		got, seq, err = server.Next()
		if err != nil || seq != 1 || !bytes.Equal(got, serverWant) {
			t.Fatalf("mode %s server = (%x,%d,%v), want (%x,1,nil)", mode, got, seq, err, serverWant)
		}
	}

	appendManager := NewNonceManager("server", base, "counter_append_base")
	got, seq, err := appendManager.Next()
	if err != nil || seq != 1 {
		t.Fatalf("counter append = (%x,%d,%v)", got, seq, err)
	}
	input := append(append([]byte("server/"), base...), one[:]...)
	wantAppend := sha256.Sum256(input)
	if !bytes.Equal(got, wantAppend[:12]) {
		t.Fatalf("counter append = %x, want %x", got, wantAppend[:12])
	}

	unknown := NewNonceManager("client", base, "unknown")
	if _, seq, err = unknown.Next(); !errors.Is(err, ErrInvalidConfig) || seq != 0 || err.Error() != `invalid security config: unknown nonce mode "unknown"` || unknown.Counter != 1 {
		t.Fatalf("unknown mode = (seq=%d counter=%d err=%v)", seq, unknown.Counter, err)
	}

	overflow := NewNonceManager("client", base, "directional_counter")
	overflow.SetCounterForTest(math.MaxUint64)
	if nonce, seq, err := overflow.Next(); nonce != nil || seq != 0 || !errors.Is(err, ErrNonceOverflow) || err.Error() != "nonce counter overflow" || overflow.Counter != math.MaxUint64 {
		t.Fatalf("overflow = (%x,%d,%v,counter=%d)", nonce, seq, err, overflow.Counter)
	}

	oracleBase := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	for _, role := range []struct {
		direction string
		xor       string
		append    string
	}{
		{"client", "000102030405060708090a0a", "0a96b83be08d829b1c05dec3"},
		{"server", "800102030405060708090a0a", "710d9ee497b563717a41d246"},
	} {
		for _, mode := range []string{"counter_xor_base", "directional_counter", "stream_partitioned_counter"} {
			got, _, err := NewNonceManager(role.direction, oracleBase, mode).Next()
			if err != nil || !bytes.Equal(got, mustDecodeNonceHexV1(t, role.xor)) {
				t.Fatalf("legacy %s/%s = %x, %v", role.direction, mode, got, err)
			}
		}
		got, _, err := NewNonceManager(role.direction, oracleBase, "counter_append_base").Next()
		if err != nil || !bytes.Equal(got, mustDecodeNonceHexV1(t, role.append)) {
			t.Fatalf("legacy %s/append = %x, %v", role.direction, got, err)
		}
	}
}

func TestPolicyMatrixOwnerWitnessLiteralNonceSentinelV1(t *testing.T) {
	caseIDs := []string{"pm-owner:nonce/counter_xor_base", "pm-owner:nonce/counter_append_base", "pm-owner:nonce/directional_counter", "pm-owner:nonce/stream_partitioned_counter"}
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	for index, mode := range []string{NonceModeCounterXORBaseV1, NonceModeCounterAppendBaseV1, NonceModeDirectionalCounterV1, NonceModeStreamPartitionedCounterV1} {
		id := caseIDs[index]
		t.Run(id, func(t *testing.T) {
			owner, err := NewClientNonceOwnerV1(schedule, mode)
			if err != nil {
				t.Fatal(err)
			}
			valid, err := owner.AllocateOutboundApplicationV1(7)
			if err != nil || valid.Nonce != independentNonceFormulaV1(schedule.ClientNonceBase, mode, 7, 0) {
				t.Fatalf("valid nonce owner reached=%#v err=%v", valid, err)
			}
			mutations := 0
			var actual error
			switch index {
			case 0:
				_, actual = owner.AllocateOutboundApplicationV1(0)
				mutations++
			case 1:
				owner.outbound.config.direction = 0
				mutations++
				_, actual = owner.AllocateOutboundControlV1()
			case 2:
				owner.outbound.config.mode = "unknown"
				mutations++
				_, actual = owner.AllocateOutboundControlV1()
			case 3:
				owner.outbound.sequences[7] = nonceSequenceStateV1{exhausted: true}
				mutations++
				_, actual = owner.AllocateOutboundApplicationV1(7)
			}
			want := []error{ErrNonceMismatch, ErrNonceMismatch, ErrPolicyInvalid, ErrNonceExhausted}[index]
			if mutations != 1 || actual == nil || !errors.Is(actual, want) || actual.Error() != want.Error() {
				t.Fatalf("%s mutations=%d error=%v want=%v", id, mutations, actual, want)
			}
		})
	}
}

func TestNonceV1FormulaVectorsAndDirectionV1(t *testing.T) {
	if DirectionClientToRelayV1 != 0x0001 || DirectionRelayToClientV1 != 0x0002 {
		t.Fatalf("direction constants = %#04x/%#04x", DirectionClientToRelayV1, DirectionRelayToClientV1)
	}
	clientBase := mustDecodeNonceHexV1(t, "9a82475a1929c9f333ab769c")
	relayBase := mustDecodeNonceHexV1(t, "98a074755c9e48deaa89e071")
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	epoch := schedule.Epoch
	for _, mode := range []string{
		NonceModeCounterXORBaseV1,
		NonceModeCounterAppendBaseV1,
		NonceModeDirectionalCounterV1,
		NonceModeStreamPartitionedCounterV1,
	} {
		t.Run(mode, func(t *testing.T) {
			client, err := NewClientNonceOwnerV1(schedule, mode)
			if err != nil {
				t.Fatal(err)
			}
			relay, err := NewRelayNonceOwnerV1(schedule, mode)
			if err != nil {
				t.Fatal(err)
			}
			if client.OutboundDirectionV1() != DirectionClientToRelayV1 || client.InboundDirectionV1() != DirectionRelayToClientV1 ||
				relay.OutboundDirectionV1() != DirectionRelayToClientV1 || relay.InboundDirectionV1() != DirectionClientToRelayV1 {
				t.Fatal("role-fixed direction ownership changed")
			}

			c2r, err := client.AllocateOutboundControlV1()
			if err != nil {
				t.Fatal(err)
			}
			r2c, err := relay.AllocateOutboundControlV1()
			if err != nil {
				t.Fatal(err)
			}
			if c2r.Sequence != 0 || c2r.Epoch != epoch || c2r.Direction != DirectionClientToRelayV1 || c2r.Slot != 0 ||
				r2c.Sequence != 0 || r2c.Epoch != epoch || r2c.Direction != DirectionRelayToClientV1 || r2c.Slot != 0 {
				t.Fatalf("zero allocation metadata = %#v / %#v", c2r, r2c)
			}
			wantC2R := independentNonceFormulaV1(clientBase, mode, 0, 0)
			wantR2C := independentNonceFormulaV1(relayBase, mode, 0, 0)
			if c2r.Nonce != wantC2R || r2c.Nonce != wantR2C {
				t.Fatalf("zero formulas = %x/%x, want %x/%x", c2r.Nonce, r2c.Nonce, wantC2R, wantR2C)
			}
			gotC2R, err := relay.ExpectedInboundControlV1(0)
			if err != nil || gotC2R != wantC2R {
				t.Fatalf("relay expected c2r = %x, %v", gotC2R, err)
			}
			gotR2C, err := client.ExpectedInboundControlV1(0)
			if err != nil || gotR2C != wantR2C {
				t.Fatalf("client expected r2c = %x, %v", gotR2C, err)
			}
		})
	}

	vectors := []struct {
		name      string
		direction uint16
		base      string
		mode      string
		want      [3]string
	}{
		{"c2r/xor", 1, "9a82475a1929c9f333ab769c", NonceModeCounterXORBaseV1, [3]string{"9a82475a1929c9f333ab769c", "9a82475a182bcaf736ad7194", "9a82475ae6d6360ccc548963"}},
		{"c2r/append", 1, "9a82475a1929c9f333ab769c", NonceModeCounterAppendBaseV1, [3]string{"00000000000000009a82475a", "01020304050607089a82475a", "ffffffffffffffff9a82475a"}},
		{"c2r/directional", 1, "9a82475a1929c9f333ab769c", NonceModeDirectionalCounterV1, [3]string{"9a82475a0000000000000000", "9a82475a0102030405060708", "9a82475affffffffffffffff"}},
		{"c2r/stream", 1, "9a82475a1929c9f333ab769c", NonceModeStreamPartitionedCounterV1, [3]string{"9a8212341929c9f333ab769c", "9a821234182bcaf736ad7194", "9a821234e6d6360ccc548963"}},
		{"r2c/xor", 2, "98a074755c9e48deaa89e071", NonceModeCounterXORBaseV1, [3]string{"98a074755c9e48deaa89e071", "98a074755d9c4bdaaf8fe779", "98a07475a361b72155761f8e"}},
		{"r2c/append", 2, "98a074755c9e48deaa89e071", NonceModeCounterAppendBaseV1, [3]string{"000000000000000098a07475", "010203040506070898a07475", "ffffffffffffffff98a07475"}},
		{"r2c/directional", 2, "98a074755c9e48deaa89e071", NonceModeDirectionalCounterV1, [3]string{"98a074750000000000000000", "98a074750102030405060708", "98a07475ffffffffffffffff"}},
		{"r2c/stream", 2, "98a074755c9e48deaa89e071", NonceModeStreamPartitionedCounterV1, [3]string{"98a012345c9e48deaa89e071", "98a012345d9c4bdaaf8fe779", "98a01234a361b72155761f8e"}},
	}
	sequences := [3]uint64{0, 0x0102030405060708, math.MaxUint64}
	for _, vector := range vectors {
		t.Run(vector.name+"/hard-coded", func(t *testing.T) {
			base := mustDecodeNonceHexV1(t, vector.base)
			config, err := newNonceDirectionConfigV1(11, vector.direction, base, vector.mode)
			if err != nil {
				t.Fatal(err)
			}
			for i, sequence := range sequences {
				got, err := deriveNonceV1(config, 0x1234, sequence)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(got[:]) != vector.want[i] {
					t.Fatalf("sequence %#x = %x, want %s", sequence, got, vector.want[i])
				}
			}

			var ownerState *nonceDirectionStateV1
			var allocate func(uint16) (NonceAllocationV1, error)
			if vector.direction == DirectionClientToRelayV1 {
				owner, err := NewClientNonceOwnerV1(schedule, vector.mode)
				if err != nil {
					t.Fatal(err)
				}
				ownerState = owner.outbound
				allocate = owner.AllocateOutboundApplicationV1
			} else {
				owner, err := NewRelayNonceOwnerV1(schedule, vector.mode)
				if err != nil {
					t.Fatal(err)
				}
				ownerState = owner.outbound
				allocate = owner.AllocateOutboundApplicationV1
			}
			stateSlot := uint16(0)
			if vector.mode == NonceModeStreamPartitionedCounterV1 {
				stateSlot = 0x1234
			}
			ownerState.sequences[stateSlot] = nonceSequenceStateV1{next: math.MaxUint64}
			last, err := allocate(0x1234)
			if err != nil || last.Sequence != math.MaxUint64 || hex.EncodeToString(last.Nonce[:]) != vector.want[2] {
				t.Fatalf("MaxUint64 allocation = %#v, %v", last, err)
			}
			if _, err := allocate(0x1234); !errors.Is(err, ErrNonceExhausted) {
				t.Fatalf("post-Max allocation = %v", err)
			}
		})
	}
}

func TestNonceV1ScheduleAuthorityAndIsolation(t *testing.T) {
	valid := mustNonceScheduleV1(t)
	defer valid.Destroy()

	type constructorResult struct {
		constructed bool
		err         error
	}
	constructors := []struct {
		name string
		make func(KeySchedule, string) constructorResult
	}{
		{"client", func(schedule KeySchedule, mode string) constructorResult {
			owner, err := NewClientNonceOwnerV1(schedule, mode)
			return constructorResult{owner != nil, err}
		}},
		{"relay", func(schedule KeySchedule, mode string) constructorResult {
			owner, err := NewRelayNonceOwnerV1(schedule, mode)
			return constructorResult{owner != nil, err}
		}},
	}

	invalidSchedules := []struct {
		name   string
		mutate func(*KeySchedule)
	}{
		{"all-zero-schedule", func(schedule *KeySchedule) { *schedule = KeySchedule{} }},
		{"non-exact", func(schedule *KeySchedule) { schedule.exactV1 = false }},
		{"epoch-mismatch", func(schedule *KeySchedule) { schedule.Epoch++ }},
		{"all-zero-client-nonce", func(schedule *KeySchedule) { schedule.ClientNonceBase = make([]byte, nonceBytesV1) }},
		{"all-zero-server-nonce", func(schedule *KeySchedule) { schedule.ServerNonceBase = make([]byte, nonceBytesV1) }},
		{"collapsed-nonce-bases", func(schedule *KeySchedule) {
			schedule.ServerNonceBase = append([]byte(nil), schedule.ClientNonceBase...)
		}},
		{"client-nonce-empty", func(schedule *KeySchedule) { schedule.ClientNonceBase = nil }},
		{"client-nonce-short", func(schedule *KeySchedule) { schedule.ClientNonceBase = make([]byte, nonceBytesV1-1) }},
		{"client-nonce-long", func(schedule *KeySchedule) { schedule.ClientNonceBase = make([]byte, nonceBytesV1+1) }},
		{"server-nonce-empty", func(schedule *KeySchedule) { schedule.ServerNonceBase = nil }},
		{"server-nonce-short", func(schedule *KeySchedule) { schedule.ServerNonceBase = make([]byte, nonceBytesV1-1) }},
		{"server-nonce-long", func(schedule *KeySchedule) { schedule.ServerNonceBase = make([]byte, nonceBytesV1+1) }},
	}
	for _, constructor := range constructors {
		for _, tc := range invalidSchedules {
			t.Run(constructor.name+"/"+tc.name, func(t *testing.T) {
				schedule := valid
				tc.mutate(&schedule)
				result := constructor.make(schedule, NonceModeCounterXORBaseV1)
				if result.constructed || result.err != ErrNonceMismatch || result.err.Error() != "nonce_mismatch" {
					t.Fatalf("rejected construction = (constructed=%v, err=%v), want (false, nonce_mismatch)", result.constructed, result.err)
				}
			})
		}
		t.Run(constructor.name+"/mode-precedence", func(t *testing.T) {
			invalid := KeySchedule{}
			result := constructor.make(invalid, "unknown")
			if result.constructed || result.err != ErrPolicyInvalid {
				t.Fatalf("mode precedence = (constructed=%v, err=%v), want (false, policy_invalid)", result.constructed, result.err)
			}
		})
	}

	source := mustNonceScheduleV1(t)
	wantEpoch := source.Epoch
	wantClientBase := append([]byte(nil), source.ClientNonceBase...)
	wantServerBase := append([]byte(nil), source.ServerNonceBase...)
	client, err := NewClientNonceOwnerV1(source, NonceModeCounterXORBaseV1)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewRelayNonceOwnerV1(source, NonceModeCounterXORBaseV1)
	if err != nil {
		t.Fatal(err)
	}
	for i := range source.ClientNonceBase {
		source.ClientNonceBase[i] ^= 0xff
		source.ServerNonceBase[i] ^= 0xff
	}
	source.Epoch++
	source.Destroy()

	c2r, err := client.AllocateOutboundControlV1()
	if err != nil {
		t.Fatal(err)
	}
	r2c, err := relay.AllocateOutboundControlV1()
	if err != nil {
		t.Fatal(err)
	}
	clientInbound, err := client.ExpectedInboundControlV1(0)
	if err != nil {
		t.Fatal(err)
	}
	relayInbound, err := relay.ExpectedInboundControlV1(0)
	if err != nil {
		t.Fatal(err)
	}
	wantC2R := independentNonceFormulaV1(wantClientBase, NonceModeCounterXORBaseV1, 0, 0)
	wantR2C := independentNonceFormulaV1(wantServerBase, NonceModeCounterXORBaseV1, 0, 0)
	if c2r.Epoch != wantEpoch || r2c.Epoch != wantEpoch || c2r.Nonce != wantC2R || r2c.Nonce != wantR2C ||
		clientInbound != wantR2C || relayInbound != wantC2R {
		t.Fatalf("owner changed after source mutation/destroy: c2r=%#v r2c=%#v inbound=%x/%x", c2r, r2c, clientInbound, relayInbound)
	}
}

func TestNonceV1ExpectedInboundApplicationHardCodedVectors(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	sequences := [3]uint64{0, 0x0102030405060708, math.MaxUint64}
	type inboundOwner interface {
		ExpectedInboundApplicationV1(uint16, uint64) ([nonceBytesV1]byte, error)
	}
	vectors := []struct {
		name        string
		role        string
		mode        string
		wantSlot1   [3]string
		wantSlotMax [3]string
	}{
		{"client/xor", "client", NonceModeCounterXORBaseV1,
			[3]string{"98a074755c9e48deaa89e071", "98a074755d9c4bdaaf8fe779", "98a07475a361b72155761f8e"},
			[3]string{"98a074755c9e48deaa89e071", "98a074755d9c4bdaaf8fe779", "98a07475a361b72155761f8e"}},
		{"client/append", "client", NonceModeCounterAppendBaseV1,
			[3]string{"000000000000000098a07475", "010203040506070898a07475", "ffffffffffffffff98a07475"},
			[3]string{"000000000000000098a07475", "010203040506070898a07475", "ffffffffffffffff98a07475"}},
		{"client/directional", "client", NonceModeDirectionalCounterV1,
			[3]string{"98a074750000000000000000", "98a074750102030405060708", "98a07475ffffffffffffffff"},
			[3]string{"98a074750000000000000000", "98a074750102030405060708", "98a07475ffffffffffffffff"}},
		{"client/stream", "client", NonceModeStreamPartitionedCounterV1,
			[3]string{"98a000015c9e48deaa89e071", "98a000015d9c4bdaaf8fe779", "98a00001a361b72155761f8e"},
			[3]string{"98a0ffff5c9e48deaa89e071", "98a0ffff5d9c4bdaaf8fe779", "98a0ffffa361b72155761f8e"}},
		{"relay/xor", "relay", NonceModeCounterXORBaseV1,
			[3]string{"9a82475a1929c9f333ab769c", "9a82475a182bcaf736ad7194", "9a82475ae6d6360ccc548963"},
			[3]string{"9a82475a1929c9f333ab769c", "9a82475a182bcaf736ad7194", "9a82475ae6d6360ccc548963"}},
		{"relay/append", "relay", NonceModeCounterAppendBaseV1,
			[3]string{"00000000000000009a82475a", "01020304050607089a82475a", "ffffffffffffffff9a82475a"},
			[3]string{"00000000000000009a82475a", "01020304050607089a82475a", "ffffffffffffffff9a82475a"}},
		{"relay/directional", "relay", NonceModeDirectionalCounterV1,
			[3]string{"9a82475a0000000000000000", "9a82475a0102030405060708", "9a82475affffffffffffffff"},
			[3]string{"9a82475a0000000000000000", "9a82475a0102030405060708", "9a82475affffffffffffffff"}},
		{"relay/stream", "relay", NonceModeStreamPartitionedCounterV1,
			[3]string{"9a8200011929c9f333ab769c", "9a820001182bcaf736ad7194", "9a820001e6d6360ccc548963"},
			[3]string{"9a82ffff1929c9f333ab769c", "9a82ffff182bcaf736ad7194", "9a82ffffe6d6360ccc548963"}},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			var owner inboundOwner
			var state *nonceDirectionStateV1
			var allocate func(uint16) (NonceAllocationV1, error)
			if vector.role == "client" {
				client, err := NewClientNonceOwnerV1(schedule, vector.mode)
				if err != nil {
					t.Fatal(err)
				}
				owner, state, allocate = client, client.outbound, client.AllocateOutboundApplicationV1
			} else {
				relay, err := NewRelayNonceOwnerV1(schedule, vector.mode)
				if err != nil {
					t.Fatal(err)
				}
				owner, state, allocate = relay, relay.outbound, relay.AllocateOutboundApplicationV1
			}
			for _, slotVector := range []struct {
				slot uint16
				want [3]string
			}{{1, vector.wantSlot1}, {math.MaxUint16, vector.wantSlotMax}} {
				for i, sequence := range sequences {
					got, err := owner.ExpectedInboundApplicationV1(slotVector.slot, sequence)
					if err != nil || hex.EncodeToString(got[:]) != slotVector.want[i] {
						t.Fatalf("slot=%d sequence=%#x got=%x err=%v want=%s", slotVector.slot, sequence, got, err, slotVector.want[i])
					}
					again, err := owner.ExpectedInboundApplicationV1(slotVector.slot, sequence)
					if err != nil || again != got {
						t.Fatalf("repeat slot=%d sequence=%#x got=%x err=%v want=%x", slotVector.slot, sequence, again, err, got)
					}
				}
			}
			if len(state.sequences) != 0 {
				t.Fatalf("expected inbound mutated outbound state: %v", state.sequences)
			}
			first, err := allocate(1)
			if err != nil || first.Sequence != 0 {
				t.Fatalf("first outbound allocation after expected calls = %#v, %v", first, err)
			}
		})
	}
}

func TestNonceV1ExpectedNonceSlotsAndSequenceZero(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	clientBase := append([]byte(nil), schedule.ClientNonceBase...)

	stream, err := NewClientNonceOwnerV1(schedule, NonceModeStreamPartitionedCounterV1)
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range []uint16{1, math.MaxUint16} {
		before := len(stream.outbound.sequences)
		want := independentNonceFormulaV1(clientBase, NonceModeStreamPartitionedCounterV1, slot, 0)
		got, err := stream.outbound.config.expectedV1(nonceApplicationRecordV1, slot, 0)
		if err != nil || got != want {
			t.Fatalf("slot %d expected = %x, %v; want %x", slot, got, err, want)
		}
		if len(stream.outbound.sequences) != before {
			t.Fatal("expected nonce mutated allocation state")
		}
		allocated, err := stream.AllocateOutboundApplicationV1(slot)
		if err != nil || allocated.Sequence != 0 || allocated.Nonce != want {
			t.Fatalf("slot %d first allocation = %#v, %v", slot, allocated, err)
		}
	}
	control, err := stream.AllocateOutboundControlV1()
	if err != nil || control.Sequence != 0 || control.Slot != 0 {
		t.Fatalf("control zero allocation = %#v, %v", control, err)
	}

	global, err := NewClientNonceOwnerV1(schedule, NonceModeDirectionalCounterV1)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := global.AllocateOutboundControlV1()
	b, _ := global.AllocateOutboundApplicationV1(1)
	c, _ := global.AllocateOutboundControlV1()
	if a.Sequence != 0 || b.Sequence != 1 || c.Sequence != 2 {
		t.Fatalf("non-stream sequence domain split = %d,%d,%d", a.Sequence, b.Sequence, c.Sequence)
	}
	schedule.Destroy()
}

func TestNonceV1BurnRetryAndExhaust(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	owner, err := NewClientNonceOwnerV1(schedule, NonceModeCounterAppendBaseV1)
	if err != nil {
		t.Fatal(err)
	}
	failedAttempt, err := owner.AllocateOutboundApplicationV1(1)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate Seal/use failure after allocation: retry must burn sequence zero.
	retry, err := owner.AllocateOutboundApplicationV1(1)
	if err != nil || failedAttempt.Sequence != 0 || retry.Sequence != 1 || failedAttempt.Nonce == retry.Nonce {
		t.Fatalf("burn/retry = %#v / %#v / %v", failedAttempt, retry, err)
	}

	owner.outbound.mu.Lock()
	owner.outbound.sequences[0] = nonceSequenceStateV1{next: math.MaxUint64}
	owner.outbound.mu.Unlock()
	last, err := owner.AllocateOutboundControlV1()
	if err != nil || last.Sequence != math.MaxUint64 || last.Nonce != independentNonceFormulaV1(schedule.ClientNonceBase, NonceModeCounterAppendBaseV1, 0, math.MaxUint64) {
		t.Fatalf("last allocation = %#v, %v", last, err)
	}
	if _, err := owner.AllocateOutboundControlV1(); !errors.Is(err, ErrNonceExhausted) || !errors.Is(err, ErrNonceOverflow) || err.Error() != "nonce_exhausted" {
		t.Fatalf("exhaustion error = %v", err)
	}
}

func TestNonceV1ConcurrentAllocation(t *testing.T) {
	schedule := mustNonceScheduleV1(t)
	defer schedule.Destroy()
	owner, err := NewClientNonceOwnerV1(schedule, NonceModeStreamPartitionedCounterV1)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 64
	sequences := make(chan uint64, workers)
	errorsOut := make(chan error, workers)
	var group sync.WaitGroup
	for i := 0; i < workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			allocation, err := owner.AllocateOutboundApplicationV1(7)
			if err != nil {
				errorsOut <- err
				return
			}
			sequences <- allocation.Sequence
		}()
	}
	group.Wait()
	close(sequences)
	close(errorsOut)
	for err := range errorsOut {
		t.Fatal(err)
	}
	seen := make(map[uint64]bool, workers)
	for sequence := range sequences {
		if seen[sequence] {
			t.Fatalf("duplicate concurrent sequence %d", sequence)
		}
		seen[sequence] = true
	}
	for sequence := uint64(0); sequence < workers; sequence++ {
		if !seen[sequence] {
			t.Fatalf("missing concurrent sequence %d", sequence)
		}
	}

	maxOwner, err := NewClientNonceOwnerV1(schedule, NonceModeStreamPartitionedCounterV1)
	if err != nil {
		t.Fatal(err)
	}
	maxOwner.outbound.sequences[7] = nonceSequenceStateV1{next: math.MaxUint64}
	copiedOwner := *maxOwner
	handles := [2]*ClientNonceOwnerV1{maxOwner, &copiedOwner}
	type allocationResult struct {
		allocation NonceAllocationV1
		err        error
	}
	maxResults := make(chan allocationResult, workers)
	for i := 0; i < workers; i++ {
		group.Add(1)
		handle := handles[i%len(handles)]
		go func(target *ClientNonceOwnerV1) {
			defer group.Done()
			allocation, err := target.AllocateOutboundApplicationV1(7)
			maxResults <- allocationResult{allocation, err}
		}(handle)
	}
	group.Wait()
	close(maxResults)
	successes, exhausted := 0, 0
	for result := range maxResults {
		switch {
		case result.err == nil:
			successes++
			if result.allocation.Sequence != math.MaxUint64 || result.allocation.Nonce != independentNonceFormulaV1(schedule.ClientNonceBase, NonceModeStreamPartitionedCounterV1, 7, math.MaxUint64) {
				t.Fatalf("Max allocation = %#v", result.allocation)
			}
		case errors.Is(result.err, ErrNonceExhausted):
			exhausted++
		default:
			t.Fatalf("copied-handle Max result = %#v, %v", result.allocation, result.err)
		}
	}
	if successes != 1 || exhausted != workers-1 {
		t.Fatalf("copied-handle Max outcomes = success %d exhausted %d", successes, exhausted)
	}
}

func TestNonceV1ValidationAndSentinels(t *testing.T) {
	validSchedule := mustNonceScheduleV1(t)
	defer validSchedule.Destroy()
	for _, tc := range []struct {
		name string
		make func() error
		want error
	}{
		{"empty mode", func() error { _, err := NewClientNonceOwnerV1(validSchedule, ""); return err }, ErrPolicyInvalid},
		{"unknown mode", func() error { _, err := NewClientNonceOwnerV1(validSchedule, "unknown"); return err }, ErrPolicyInvalid},
		{"zero direction", func() error {
			_, err := newNonceDirectionStateV1(0, 0, validSchedule.ClientNonceBase, NonceModeCounterXORBaseV1)
			return err
		}, ErrNonceMismatch},
		{"unknown direction", func() error {
			_, err := newNonceDirectionStateV1(0, 3, validSchedule.ClientNonceBase, NonceModeCounterXORBaseV1)
			return err
		}, ErrNonceMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.make(); !errors.Is(err, tc.want) || err.Error() != tc.want.Error() {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}

	owner, err := NewClientNonceOwnerV1(validSchedule, NonceModeCounterXORBaseV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.AllocateOutboundApplicationV1(0); !errors.Is(err, ErrNonceMismatch) || len(owner.outbound.sequences) != 0 {
		t.Fatalf("application slot zero = %v state=%v", err, owner.outbound.sequences)
	}
	if _, err := owner.outbound.allocateV1(nonceControlRecordV1, 1); !errors.Is(err, ErrNonceMismatch) || len(owner.outbound.sequences) != 0 {
		t.Fatalf("control nonzero slot = %v state=%v", err, owner.outbound.sequences)
	}
	if _, err := owner.ExpectedInboundApplicationV1(0, 0); !errors.Is(err, ErrNonceMismatch) || len(owner.outbound.sequences) != 0 {
		t.Fatalf("expected application slot zero = %v state=%v", err, owner.outbound.sequences)
	}
	owner.outbound.config.direction = 0
	if _, err := owner.AllocateOutboundControlV1(); !errors.Is(err, ErrNonceMismatch) || len(owner.outbound.sequences) != 0 {
		t.Fatalf("corrupt direction = %v state=%v", err, owner.outbound.sequences)
	}
	owner.outbound.config.direction = DirectionClientToRelayV1
	owner.outbound.config.mode = "unknown"
	if _, err := owner.AllocateOutboundControlV1(); !errors.Is(err, ErrPolicyInvalid) || len(owner.outbound.sequences) != 0 {
		t.Fatalf("corrupt mode = %v state=%v", err, owner.outbound.sequences)
	}
	for name, action := range map[string]func() error{
		"client control": func() error { _, err := (&ClientNonceOwnerV1{}).AllocateOutboundControlV1(); return err },
		"client app":     func() error { _, err := (&ClientNonceOwnerV1{}).AllocateOutboundApplicationV1(1); return err },
		"relay control":  func() error { _, err := (&RelayNonceOwnerV1{}).AllocateOutboundControlV1(); return err },
		"relay app":      func() error { _, err := (&RelayNonceOwnerV1{}).AllocateOutboundApplicationV1(1); return err },
	} {
		if err := action(); !errors.Is(err, ErrNonceMismatch) {
			t.Fatalf("zero owner %s = %v", name, err)
		}
	}

	var nilClient *ClientNonceOwnerV1
	var nilRelay *RelayNonceOwnerV1
	emptyClient := &ClientNonceOwnerV1{}
	emptyRelay := &RelayNonceOwnerV1{}
	for _, tc := range []struct {
		name string
		call func() ([nonceBytesV1]byte, error)
	}{
		{"nil client control", func() ([nonceBytesV1]byte, error) { return nilClient.ExpectedInboundControlV1(0) }},
		{"nil client app", func() ([nonceBytesV1]byte, error) { return nilClient.ExpectedInboundApplicationV1(1, 0) }},
		{"nil relay control", func() ([nonceBytesV1]byte, error) { return nilRelay.ExpectedInboundControlV1(0) }},
		{"nil relay app", func() ([nonceBytesV1]byte, error) { return nilRelay.ExpectedInboundApplicationV1(1, 0) }},
		{"empty client control", func() ([nonceBytesV1]byte, error) { return emptyClient.ExpectedInboundControlV1(0) }},
		{"empty client app", func() ([nonceBytesV1]byte, error) { return emptyClient.ExpectedInboundApplicationV1(1, 0) }},
		{"empty relay control", func() ([nonceBytesV1]byte, error) { return emptyRelay.ExpectedInboundControlV1(0) }},
		{"empty relay app", func() ([nonceBytesV1]byte, error) { return emptyRelay.ExpectedInboundApplicationV1(1, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.call()
			if got != ([nonceBytesV1]byte{}) || err != ErrNonceMismatch || err.Error() != "nonce_mismatch" {
				t.Fatalf("expected inbound = (%x,%v), want (zero,nonce_mismatch)", got, err)
			}
		})
	}

	validInbound, err := NewClientNonceOwnerV1(validSchedule, NonceModeCounterXORBaseV1)
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []uint16{0, 3} {
		t.Run(fmt.Sprintf("inbound direction %d", direction), func(t *testing.T) {
			config := validInbound.inbound
			config.direction = direction
			before := len(validInbound.outbound.sequences)
			got, err := config.expectedV1(nonceApplicationRecordV1, 1, 0)
			if got != ([nonceBytesV1]byte{}) || err != ErrNonceMismatch || err.Error() != "nonce_mismatch" {
				t.Fatalf("invalid inbound direction = (%x,%v), want (zero,nonce_mismatch)", got, err)
			}
			if len(validInbound.outbound.sequences) != before {
				t.Fatalf("invalid inbound direction mutated outbound state: before=%d after=%d", before, len(validInbound.outbound.sequences))
			}
		})
	}

	for sentinel, want := range map[error]string{
		ErrPolicyInvalid: "policy_invalid", ErrNonceExhausted: "nonce_exhausted",
		ErrNonceMismatch: "nonce_mismatch", ErrAuthenticationFailed: "authentication_failed",
	} {
		if sentinel.Error() != want {
			t.Fatalf("sentinel = %q, want %q", sentinel, want)
		}
		assertSafeSentinelFormattingV1(t, sentinel, want)
	}
	if !errors.Is(ErrPolicyInvalid, ErrInvalidConfig) || !errors.Is(ErrNonceExhausted, ErrNonceOverflow) {
		t.Fatal("strict nonce sentinel broad classification changed")
	}
}

func TestNonceV1KDFDirectionOwnershipVectors(t *testing.T) {
	vector := manualProjectVector()
	schedule, err := DeriveKeyScheduleV1(KeyScheduleInput{
		ApplicationSecret: append([]byte(nil), vector.epochPRK0...),
		TranscriptHash:    append([]byte(nil), vector.transcript...), Suite: DefaultSuite(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer schedule.Destroy()
	if !bytes.Equal(schedule.ClientNonceBase, mustDecodeNonceHexV1(t, "9a82475a1929c9f333ab769c")) ||
		!bytes.Equal(schedule.ServerNonceBase, mustDecodeNonceHexV1(t, "98a074755c9e48deaa89e071")) {
		t.Fatalf("epoch-zero nonce bases changed: %x/%x", schedule.ClientNonceBase, schedule.ServerNonceBase)
	}
	if keyLabelC2SNonce != "kurdistan/hkdf/v1/c2s-nonce" || keyLabelS2CNonce != "kurdistan/hkdf/v1/s2c-nonce" {
		t.Fatalf("nonce KDF labels changed: %q/%q", keyLabelC2SNonce, keyLabelS2CNonce)
	}

	next, err := RatchetKeyScheduleV1(schedule)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Destroy()
	if !bytes.Equal(next.ClientNonceBase, mustDecodeNonceHexV1(t, "5d5c260c7d1314129290454d")) ||
		!bytes.Equal(next.ServerNonceBase, mustDecodeNonceHexV1(t, "5e3d60181390c87f81bfa263")) {
		t.Fatalf("epoch-one nonce bases changed: %x/%x", next.ClientNonceBase, next.ServerNonceBase)
	}

	client, err := NewClientNonceOwnerV1(schedule, NonceModeCounterXORBaseV1)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewRelayNonceOwnerV1(schedule, NonceModeCounterXORBaseV1)
	if err != nil {
		t.Fatal(err)
	}
	c2r, _ := client.AllocateOutboundControlV1()
	r2c, _ := relay.AllocateOutboundControlV1()
	if c2r.Direction != 1 || r2c.Direction != 2 || c2r.Nonce != independentNonceFormulaV1(schedule.ClientNonceBase, NonceModeCounterXORBaseV1, 0, 0) ||
		r2c.Nonce != independentNonceFormulaV1(schedule.ServerNonceBase, NonceModeCounterXORBaseV1, 0, 0) {
		t.Fatalf("direction-to-KDF ownership changed: %#v/%#v", c2r, r2c)
	}
}

func independentNonceFormulaV1(base []byte, mode string, slot uint16, sequence uint64) [12]byte {
	var out [12]byte
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], sequence)
	switch mode {
	case NonceModeCounterXORBaseV1:
		copy(out[:4], base[:4])
		for i := range encoded {
			out[4+i] = base[4+i] ^ encoded[i]
		}
	case NonceModeCounterAppendBaseV1:
		copy(out[:8], encoded[:])
		copy(out[8:], base[:4])
	case NonceModeDirectionalCounterV1:
		copy(out[:4], base[:4])
		copy(out[4:], encoded[:])
	case NonceModeStreamPartitionedCounterV1:
		copy(out[:2], base[:2])
		binary.BigEndian.PutUint16(out[2:4], slot)
		for i := range encoded {
			out[4+i] = base[4+i] ^ encoded[i]
		}
	}
	return out
}

func mustNonceScheduleV1(t *testing.T) KeySchedule {
	t.Helper()
	vector := manualProjectVector()
	schedule, err := DeriveKeyScheduleV1(KeyScheduleInput{
		ApplicationSecret: append([]byte(nil), vector.epochPRK0...),
		TranscriptHash:    append([]byte(nil), vector.transcript...),
		Suite:             DefaultSuite(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return schedule
}

func mustDecodeNonceHexV1(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertSafeSentinelFormattingV1(t *testing.T, sentinel error, text string) {
	t.Helper()
	for format, want := range map[string]string{
		"%v":  text,
		"%s":  text,
		"%q":  `"` + text + `"`,
		"%#v": text,
	} {
		if got := fmt.Sprintf(format, sentinel); got != want {
			t.Fatalf("format %s = %q, want %q", format, got, want)
		}
	}
}
