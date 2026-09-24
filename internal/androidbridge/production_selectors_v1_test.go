// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"kurdistan/internal/product/runtimepolicy"
)

func productionSelectorFixtureV1() productionSelectorSetV1 {
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index + 1)
	}
	var value productionSelectorSetV1
	value.profileGeneration = 0x8000000000000001
	value.planDigest = digest
	value.strategyCount = 1
	value.strategyIDs[0] = []byte("strategy-kurd-tls13-tcp")
	value.probeCount = 2
	value.probeIDs[0] = []byte("probe-1")
	value.probeIDs[1] = []byte("probe-10")
	return value
}

func TestProductionSelectorsV1NoComparisonOwners(t *testing.T) {
	value := productionSelectorFixtureV1()
	value.probeIDs[0] = []byte("probe-9")
	value.probeIDs[1] = []byte("probe-10")
	before0, before1 := bytes.Clone(value.probeIDs[0]), bytes.Clone(value.probeIDs[1])
	allocations := testing.AllocsPerRun(20, func() {
		if _, status := validateProductionSelectorsV1(value); status != productionSuccessV1 {
			panic("length-prefixed ordering rejected")
		}
	})
	if allocations != 0 {
		t.Fatalf("comparison mutable owners: allocations=%v", allocations)
	}
	var out [512]byte
	if _, status := encodeProductionSelectorsV1(value, out[:]); status != productionSuccessV1 {
		t.Fatal(status)
	}
	if !bytes.Equal(value.probeIDs[0], before0) || !bytes.Equal(value.probeIDs[1], before1) {
		t.Fatal("caller ID changed")
	}
	value.probeIDs[0], value.probeIDs[1] = value.probeIDs[1], value.probeIDs[0]
	if _, status := validateProductionSelectorsV1(value); status != productionInvalidRequestV1 {
		t.Fatal("byte-only ordering admitted")
	}
}

func productionSelectorGoldenBytesV1() []byte {
	value := productionSelectorFixtureV1()
	total := 12 + 8 + 32 + 1 + 1 + len(value.strategyIDs[0]) + 1 + 1 + len(value.probeIDs[0]) + 1 + len(value.probeIDs[1])
	out := make([]byte, 0, total)
	out = append(out, 'K', 'P', 'A', '1', 1, 1, 0, 0)
	var scalar [8]byte
	binary.BigEndian.PutUint32(scalar[:4], uint32(total))
	out = append(out, scalar[:4]...)
	binary.BigEndian.PutUint64(scalar[:], value.profileGeneration)
	out = append(out, scalar[:]...)
	out = append(out, value.planDigest[:]...)
	out = append(out, 1, byte(len(value.strategyIDs[0])))
	out = append(out, value.strategyIDs[0]...)
	out = append(out, 2, byte(len(value.probeIDs[0])))
	out = append(out, value.probeIDs[0]...)
	out = append(out, byte(len(value.probeIDs[1])))
	out = append(out, value.probeIDs[1]...)
	return out
}

func TestProductionSelectorsV1IndependentGoldenAndBorrowing(t *testing.T) {
	value := productionSelectorFixtureV1()
	want := productionSelectorGoldenBytesV1()
	output := bytes.Repeat([]byte{0xa5}, 512)
	written, status := encodeProductionSelectorsV1(value, output)
	if status != productionSuccessV1 || written != len(want) || !bytes.Equal(output[:written], want) {
		t.Fatalf("encode: written=%d status=%d bytes=%x", written, status, output[:max(written, 0)])
	}
	decoded, status := decodeProductionSelectorsV1(want)
	if status != productionSuccessV1 || decoded.profileGeneration != value.profileGeneration || decoded.planDigest != value.planDigest || decoded.strategyCount != 1 || string(decoded.strategyIDs[0]) != "strategy-kurd-tls13-tcp" || decoded.probeCount != 2 || string(decoded.probeIDs[1]) != "probe-10" {
		t.Fatalf("decode: status=%d value=%+v", status, decoded)
	}
	strategyOffset := bytes.Index(want, []byte("strategy-kurd-tls13-tcp"))
	if strategyOffset < 0 || &decoded.strategyIDs[0][0] != &want[strategyOffset] {
		t.Fatal("selector decode copied a protected selector")
	}
	if !decoded.matches(value.profileGeneration, value.planDigest) || decoded.matches(value.profileGeneration+1, value.planDigest) {
		t.Fatal("generation scope was not enforced")
	}
	changed := value.planDigest
	changed[0] ^= 1
	if decoded.matches(value.profileGeneration, changed) {
		t.Fatal("plan scope was not enforced")
	}
}

func TestProductionSelectorsV1FailureNeverWritesOrReturnsPartialValue(t *testing.T) {
	value := productionSelectorFixtureV1()
	for name, test := range map[string]struct {
		mutate func(*productionSelectorSetV1)
		status productionStatusV1
	}{
		"zero-generation":     {func(v *productionSelectorSetV1) { v.profileGeneration = 0 }, productionInvalidRequestV1},
		"zero-digest":         {func(v *productionSelectorSetV1) { v.planDigest = [32]byte{} }, productionInvalidRequestV1},
		"wrong-strategy":      {func(v *productionSelectorSetV1) { v.strategyIDs[0] = []byte("strategy-other") }, productionInvalidRequestV1},
		"too-many-strategies": {func(v *productionSelectorSetV1) { v.strategyCount = 2 }, productionSizeLimitV1},
		"too-many-probes":     {func(v *productionSelectorSetV1) { v.probeCount = 17 }, productionSizeLimitV1},
		"bad-probe":           {func(v *productionSelectorSetV1) { v.probeIDs[0] = []byte("probe-01") }, productionInvalidRequestV1},
		"wrong-order":         {func(v *productionSelectorSetV1) { v.probeIDs[0], v.probeIDs[1] = v.probeIDs[1], v.probeIDs[0] }, productionInvalidRequestV1},
	} {
		t.Run(name, func(t *testing.T) {
			changed := value
			test.mutate(&changed)
			output := bytes.Repeat([]byte{0x5a}, 512)
			before := append([]byte(nil), output...)
			written, status := encodeProductionSelectorsV1(changed, output)
			if status != test.status || written != 0 || !bytes.Equal(output, before) {
				t.Fatalf("written=%d status=%d changed=%v", written, status, !bytes.Equal(output, before))
			}
		})
	}
	valid := productionSelectorGoldenBytesV1()
	for length := 0; length < len(valid); length++ {
		value, status := decodeProductionSelectorsV1(valid[:length])
		if status != productionInvalidRequestV1 || !reflect.DeepEqual(value, productionSelectorSetV1{}) {
			t.Fatalf("truncation %d: status=%d value=%+v", length, status, value)
		}
	}
	tooSmall := bytes.Repeat([]byte{0x5a}, len(valid)-1)
	before := append([]byte(nil), tooSmall...)
	if written, status := encodeProductionSelectorsV1(productionSelectorFixtureV1(), tooSmall); status != productionSizeLimitV1 || written != 0 || !bytes.Equal(tooSmall, before) {
		t.Fatalf("small output: written=%d status=%d", written, status)
	}
	for name, mutate := range map[string]func([]byte){
		"magic":    func(value []byte) { value[0] ^= 1 },
		"version":  func(value []byte) { value[4] = 2 },
		"mapping":  func(value []byte) { value[5] = 2 },
		"reserved": func(value []byte) { value[6] = 1 },
		"total":    func(value []byte) { binary.BigEndian.PutUint32(value[8:12], uint32(len(value)-1)) },
	} {
		t.Run(name, func(t *testing.T) {
			input := append([]byte(nil), valid...)
			mutate(input)
			if decoded, status := decodeProductionSelectorsV1(input); status != productionInvalidRequestV1 || !reflect.DeepEqual(decoded, productionSelectorSetV1{}) {
				t.Fatalf("status=%d value=%+v", status, decoded)
			}
		})
	}
	trailing := append(append([]byte(nil), valid...), 0)
	binary.BigEndian.PutUint32(trailing[8:12], uint32(len(trailing)))
	if decoded, status := decodeProductionSelectorsV1(trailing); status != productionInvalidRequestV1 || !reflect.DeepEqual(decoded, productionSelectorSetV1{}) {
		t.Fatalf("trailing: status=%d value=%+v", status, decoded)
	}
	if decoded, status := decodeProductionSelectorsV1(make([]byte, productionSelectorsMaxBytesV1+1)); status != productionSizeLimitV1 || !reflect.DeepEqual(decoded, productionSelectorSetV1{}) {
		t.Fatalf("oversize: status=%d value=%+v", status, decoded)
	}

	maximum := productionSelectorFixtureV1()
	maximum.probeCount = 16
	for index := range int(maximum.probeCount) {
		maximum.probeIDs[index] = []byte(fmt.Sprintf("probe-%d", index+1))
	}
	if written, status := encodeProductionSelectorsV1(maximum, make([]byte, productionSelectorsMaxBytesV1)); status != productionSuccessV1 || written == 0 {
		t.Fatalf("16 probes: written=%d status=%d", written, status)
	}
}

func TestProductionSelectorsV1StrategyLengthCategoryIsAtomicAndSymmetric(t *testing.T) {
	value := productionSelectorFixtureV1()
	value.strategyIDs[0] = bytes.Repeat([]byte{'a'}, 65)
	output := bytes.Repeat([]byte{0x5a}, productionSelectorsMaxBytesV1)
	before := append([]byte(nil), output...)
	if written, status := encodeProductionSelectorsV1(value, output); written != 0 || status != productionSizeLimitV1 || !bytes.Equal(output, before) {
		t.Fatalf("encode: written=%d status=%d mutated=%v", written, status, !bytes.Equal(output, before))
	}

	input := make([]byte, 120)
	copy(input[:4], "KPA1")
	input[4], input[5] = 1, 1
	binary.BigEndian.PutUint32(input[8:12], uint32(len(input)))
	binary.BigEndian.PutUint64(input[12:20], value.profileGeneration)
	copy(input[20:52], value.planDigest[:])
	input[52], input[53] = 1, 65
	copy(input[54:119], bytes.Repeat([]byte{'a'}, 65))
	input[119] = 0
	if decoded, status := decodeProductionSelectorsV1(input); status != productionSizeLimitV1 || !reflect.DeepEqual(decoded, productionSelectorSetV1{}) {
		t.Fatalf("decode: status=%d value=%+v", status, decoded)
	}
}

func TestProductionSelectorMappingsAreExactAndAdmissionScoped(t *testing.T) {
	signedStrategies := []string{"strategy.kurd-tls13-tcp"}
	if id, ok := productionStrategyCatalogV1("strategy.kurd-tls13-tcp", signedStrategies); !ok || string(id) != "strategy-kurd-tls13-tcp" {
		t.Fatalf("forward strategy mapping: %q %v", id, ok)
	}
	if native, ok := productionStrategyNativeV1([]byte("strategy-kurd-tls13-tcp"), signedStrategies); !ok || native != "strategy.kurd-tls13-tcp" {
		t.Fatalf("reverse strategy mapping: %q %v", native, ok)
	}
	for _, forged := range []string{"strategy.kurd-tls13-tcp", "strategy-other", "strategy-kurd-tls13-tcp "} {
		if _, ok := productionStrategyNativeV1([]byte(forged), signedStrategies); ok {
			t.Fatalf("accepted forged strategy %q", forged)
		}
	}
	if _, ok := productionStrategyCatalogV1("strategy.kurd-tls13-tcp", nil); ok {
		t.Fatal("native capability alone created strategy availability")
	}

	targets := []runtimepolicy.ProbeTargetV1{
		{ID: 1, Methods: []uint8{1}, Modes: []uint8{1}, TimeoutMillis: 1000},
		{ID: 7, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000},
		{ID: 65535, Methods: []uint8{1}, Modes: []uint8{2}, TimeoutMillis: 1000},
	}
	for _, test := range []struct {
		id   uint16
		mode uint8
		want string
	}{{1, 1, "probe-1"}, {7, 2, "probe-7"}, {65535, 2, "probe-65535"}} {
		selector, ok := productionProbeCatalogV1(test.id, targets, test.mode)
		if !ok || string(selector) != test.want {
			t.Fatalf("forward probe %d: %q %v", test.id, selector, ok)
		}
		id, ok := productionProbeTargetV1(selector, targets, test.mode)
		if !ok || id != test.id {
			t.Fatalf("reverse probe %q: %d %v", selector, id, ok)
		}
	}
	for _, forged := range []string{"probe-01", "probe-0", "probe-65536", "+7", "probe-７", "probe-7x", " probe-7", "probe-2"} {
		if _, ok := productionProbeTargetV1([]byte(forged), targets, 2); ok {
			t.Fatalf("accepted forged/absent probe %q", forged)
		}
	}
	if _, ok := productionProbeTargetV1([]byte("probe-1"), targets, 2); ok {
		t.Fatal("accepted target in wrong operation mode")
	}
}
