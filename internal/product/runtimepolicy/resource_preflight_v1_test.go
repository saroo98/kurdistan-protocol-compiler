// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimepolicy

import (
	"runtime"
	"testing"
	"unsafe"
)

func TestResourcePreflightRuntimeDispatchAndEmbeddedProgram(t *testing.T) {
	for _, p := range []PolicyV2{fixturePolicyV2(t), fixturePolicyV3(t, true)} {
		m := policyMap(p, true)
		if p.Services != nil {
			m[26] = servicesMap(p.Services)
		}
		encoded, _ := marshal(m)
		if err := PreflightRuntimeResourcesV1(encoded); err != nil {
			t.Fatalf("version %d: %v", p.SchemaVersion, err)
		}
		for _, mutate := range []func(map[uint64]any){
			func(m map[uint64]any) { m[1] = uint64(4) },
			func(m map[uint64]any) { m[4] = []byte{0xa0} },
			func(m map[uint64]any) { m[4] = make([]byte, 49153) },
			func(m map[uint64]any) { m[13] = make([]any, 5) },
			func(m map[uint64]any) { m[21] = make([]string, 4) },
		} {
			copyMap := policyMap(p, true)
			if p.Services != nil {
				copyMap[26] = servicesMap(p.Services)
			}
			mutate(copyMap)
			bad, _ := marshal(copyMap)
			if err := PreflightRuntimeResourcesV1(bad); err == nil {
				t.Fatal("invalid runtime shape admitted")
			}
		}
	}
	p := fixturePolicyV3(t, true)
	m := policyMap(p, true)
	m[26] = map[uint64]any{1: uint64(1), 2: []any{}, 3: []any{map[uint64]any{1: "wrong"}}, 4: []any{}}
	bad, _ := marshal(m)
	if err := PreflightRuntimeResourcesV1(bad); err == nil {
		t.Fatal("malformed services admitted")
	}
}

func TestResourcePreflightRuntimeCapacityInventory(t *testing.T) {
	p := fixturePolicyV3(t, true)
	encoded, err := marshalPolicyV3(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := PreflightRuntimeResourcesV1(encoded); err != nil {
		t.Fatal(err)
	}
	fields, err := rawMap(encoded, 26)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PolicyV2
	if err := decodePolicy(fields, &decoded); err != nil {
		t.Fatal(err)
	}
	var rawCapacity int
	for _, raw := range fields {
		rawCapacity += cap(raw)
	}
	t.Logf("%s/%s input=%d raw-cap=%d policy=%d endpoint=%d prefix=%d services=%d proxy=%d probes=%d target=%d update=%d program-cap=%d der-cap=%d endpoint-cap=%d routes-cap=%d dns-cap=%d", runtime.Version(), runtime.GOARCH, len(encoded), rawCapacity, unsafe.Sizeof(p), unsafe.Sizeof(EndpointV2{}), unsafe.Sizeof(PrefixV2{}), unsafe.Sizeof(ServicesV1{}), unsafe.Sizeof(ProxyV1{}), unsafe.Sizeof(ProbesV1{}), unsafe.Sizeof(ProbeTargetV1{}), unsafe.Sizeof(UpdateV1{}), cap(decoded.LiveProgram), cap(decoded.TLSLeafDER), cap(decoded.Endpoints), cap(decoded.Routes), cap(decoded.DNSServers))
}

func TestResourcePreflightLeavesTLSAuthenticationToLegacy(t *testing.T) {
	p := fixturePolicyV3(t, true)
	p.TLSLeafDER = []byte{1}
	encoded, err := marshalPolicyV3(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := PreflightRuntimeResourcesV1(encoded); err != nil {
		t.Fatalf("opaque bounded DER was parsed: %v", err)
	}
	if _, err := DecodeV3(encoded); err == nil {
		t.Fatal("typed preflight conferred TLS authority")
	}
}

func TestResourcePreflightRuntimeRejectsByteArrayCoercion(t *testing.T) {
	p := fixturePolicyV2(t)
	toArray := func(value []byte) []uint64 {
		out := make([]uint64, len(value))
		for i, b := range value {
			out[i] = uint64(b)
		}
		return out
	}
	for _, label := range []uint64{4, 5, 7, 9, 11, 12, 14, 15, 16, 17, 25} {
		m := policyMap(p, true)
		m[label] = toArray(m[label].([]byte))
		bad, _ := marshal(m)
		if err := PreflightRuntimeResourcesV1(bad); err == nil {
			t.Errorf("array field %d admitted as byte leaf", label)
		}
	}
	for _, label := range []uint64{13, 18, 19, 24} {
		m := policyMap(p, true)
		switch label {
		case 13:
			m[13].([]any)[0].(map[uint64]any)[2] = toArray(p.Endpoints[0].Address)
		case 18:
			m[18].([]any)[0].(map[uint64]any)[1] = toArray(p.Routes[0].Address)
		case 19:
			m[19] = []any{toArray(p.DNSServers[0])}
		case 24:
			m[24].(map[uint64]any)[1] = toArray(p.Fallback.EndpointIndexes)
		}
		bad, _ := marshal(m)
		if err := PreflightRuntimeResourcesV1(bad); err == nil {
			t.Errorf("nested array field %d admitted as byte leaf", label)
		}
	}
}
