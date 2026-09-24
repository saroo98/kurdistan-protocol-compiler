// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package liveprogram

import (
	"runtime"
	"testing"
	"unsafe"
)

func TestResourcePreflightProgramTraversesNestedShape(t *testing.T) {
	p := fixtureProgramV1()
	encoded, err := EncodeV1(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := PreflightResourcesV1(encoded); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[uint64]any){
		func(m map[uint64]any) { delete(m, 11) },
		func(m map[uint64]any) { m[5] = []any{} },
		func(m map[uint64]any) { m[6].(map[uint64]any)[7] = map[uint64]any{1: []any{1, 2}} },
		func(m map[uint64]any) { m[10].(map[uint64]any)[4] = make([]string, 33) },
	} {
		m := programMap(p)
		mutate(m)
		bad, _ := marshal(m)
		if err := PreflightResourcesV1(bad); err == nil {
			t.Fatal("nested invalid shape admitted")
		}
	}
	if err := PreflightResourcesV1(make([]byte, 49153)); err == nil {
		t.Fatal("oversized program admitted")
	}
}

func TestResourcePreflightProgramCapacityInventory(t *testing.T) {
	encoded, err := EncodeV1(fixtureProgramV1())
	if err != nil {
		t.Fatal(err)
	}
	p, err := decodeProgramFieldsV1(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := PreflightResourcesV1(encoded); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s/%s input=%d program=%d message=%d messages-cap=%d header-cap=%d capabilities-caps=%d/%d/%d tags-cap=%d/%d", runtime.Version(), runtime.GOARCH, len(encoded), unsafe.Sizeof(p), unsafe.Sizeof(MessageV1{}), cap(p.Messages), cap(p.Frame.HeaderOrder), cap(p.Security.ClientMandatoryCapabilities), cap(p.Security.RelayMandatoryCapabilities), cap(p.Security.SelectedCapabilities), cap(p.Frame.Compiled.DataTypeTag), cap(p.Frame.Compiled.PaddingTypeTag))
}

func TestResourcePreflightProgramRejectsByteArrayCoercion(t *testing.T) {
	p := fixtureProgramV1()
	toArray := func(value []byte) []uint64 {
		out := make([]uint64, len(value))
		for i, b := range value {
			out[i] = uint64(b)
		}
		return out
	}
	for _, label := range []uint64{2, 4} {
		m := programMap(p)
		m[label] = toArray(m[label].([]byte))
		bad, _ := marshal(m)
		if err := PreflightResourcesV1(bad); err == nil {
			t.Errorf("array fixed field %d admitted as byte leaf", label)
		}
	}
	for _, label := range []uint64{1, 2} {
		m := programMap(p)
		compiled := m[6].(map[uint64]any)[7].(map[uint64]any)
		compiled[label] = toArray(compiled[label].([]byte))
		bad, _ := marshal(m)
		if err := PreflightResourcesV1(bad); err == nil {
			t.Errorf("array compiled tag %d admitted as byte leaf", label)
		}
	}
}
