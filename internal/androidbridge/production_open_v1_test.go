// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func productionOpenFixtureV1(purpose byte, components ...[]byte) []byte {
	if len(components) != 5 {
		panic("five components required")
	}
	total := 32
	for _, component := range components {
		total += len(component)
	}
	out := make([]byte, total)
	copy(out[:4], "KPO1")
	out[4], out[5] = 1, purpose
	binary.BigEndian.PutUint32(out[8:12], uint32(total))
	binary.BigEndian.PutUint32(out[12:16], uint32(len(components[0])))
	binary.BigEndian.PutUint32(out[16:20], uint32(len(components[1])))
	binary.BigEndian.PutUint32(out[20:24], uint32(len(components[2])))
	binary.BigEndian.PutUint16(out[24:26], uint16(len(components[3])))
	binary.BigEndian.PutUint16(out[26:28], uint16(len(components[4])))
	offset := 32
	for _, component := range components {
		copy(out[offset:], component)
		offset += len(component)
	}
	return out
}

func TestProductionOpenV1DecodesExactBorrowedComponentSpans(t *testing.T) {
	input := productionOpenFixtureV1(1, []byte("settings"), []byte("verify"), []byte("activation"), []byte("recipient"), []byte("private"))
	view, status := decodeProductionOpenV1(input)
	if status != productionSuccessV1 || view.purpose != 1 || string(view.settings) != "settings" || string(view.verify) != "verify" || string(view.activation) != "activation" || string(view.recipientRequest) != "recipient" || string(view.recipientPrivate) != "private" {
		t.Fatalf("decode: status=%d view=%+v", status, view)
	}
	if &view.settings[0] != &input[32] {
		t.Fatal("settings were copied instead of borrowed")
	}
	input[32] = 'S'
	if view.settings[0] != 'S' {
		t.Fatal("borrowed view does not reflect its synchronous input owner")
	}
}

func TestProductionOpenV1RejectsEveryTruncationAndTrailingByte(t *testing.T) {
	valid := productionOpenFixtureV1(2, []byte{1}, []byte{2}, []byte{3}, []byte{4}, []byte{5})
	for length := 0; length < len(valid); length++ {
		view, status := decodeProductionOpenV1(valid[:length])
		if status != productionInvalidRequestV1 || !reflect.DeepEqual(view, productionOpenViewV1{}) {
			t.Fatalf("truncation %d: status=%d view=%+v", length, status, view)
		}
	}
	trailing := append(append([]byte(nil), valid...), 0)
	if view, status := decodeProductionOpenV1(trailing); status != productionInvalidRequestV1 || !reflect.DeepEqual(view, productionOpenViewV1{}) {
		t.Fatalf("trailing: status=%d view=%+v", status, view)
	}
}

func TestProductionOpenV1RejectsHeaderAndArithmeticViolations(t *testing.T) {
	base := productionOpenFixtureV1(1, []byte{1}, []byte{2}, []byte{3}, []byte{4}, []byte{5})
	mutations := map[string]func([]byte){
		"magic":          func(v []byte) { v[0] ^= 1 },
		"version":        func(v []byte) { v[4] = 2 },
		"purpose":        func(v []byte) { v[5] = 3 },
		"reserved6":      func(v []byte) { v[6] = 1 },
		"reserved28":     func(v []byte) { v[31] = 1 },
		"total":          func(v []byte) { binary.BigEndian.PutUint32(v[8:12], uint32(len(v)-1)) },
		"zero component": func(v []byte) { binary.BigEndian.PutUint32(v[12:16], 0) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			input := append([]byte(nil), base...)
			mutate(input)
			if view, status := decodeProductionOpenV1(input); status != productionInvalidRequestV1 || !reflect.DeepEqual(view, productionOpenViewV1{}) {
				t.Fatalf("status=%d view=%+v", status, view)
			}
		})
	}
	maxLength := append([]byte(nil), base...)
	binary.BigEndian.PutUint32(maxLength[16:20], ^uint32(0))
	if view, status := decodeProductionOpenV1(maxLength); status != productionSizeLimitV1 || !reflect.DeepEqual(view, productionOpenViewV1{}) {
		t.Fatalf("u32 max: status=%d view=%+v", status, view)
	}
}

func TestProductionOpenV1AppliesExactComponentAndEnvelopeCeilings(t *testing.T) {
	limits := []int{productionSettingsMaxBytesV1, MaxVerifyRequestBytes, MaxBridgeResultBytes, 512, 128}
	components := make([][]byte, len(limits))
	for i, limit := range limits {
		components[i] = make([]byte, limit)
	}
	valid := productionOpenFixtureV1(1, components...)
	if len(valid) != productionOpenMaxBytesV1 {
		t.Fatalf("fixture length=%d", len(valid))
	}
	if _, status := decodeProductionOpenV1(valid); status != productionSuccessV1 {
		t.Fatalf("exact maxima rejected: %d", status)
	}
	for index := range limits {
		over := make([][]byte, len(components))
		for i := range components {
			over[i] = components[i]
		}
		over[index] = make([]byte, limits[index]+1)
		if _, status := decodeProductionOpenV1(productionOpenFixtureV1(1, over...)); status != productionSizeLimitV1 {
			t.Fatalf("component %d over max: status=%d", index, status)
		}
	}
}
