// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

import "testing"

func FuzzTargetDescriptorValidation(f *testing.F) {
	for _, seed := range []string{"target_alpha", "127.0.0.1", "example.com", "https://example.com", "opaque_target_001"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, descriptor string) {
		if len(descriptor) > 4096 {
			t.Skip()
		}
		target := TargetDescriptor{TargetKind: TargetKindSyntheticName, DescriptorID: descriptor, ServiceClass: "service_echo", AddressClass: "loopback_class"}
		_ = ValidateTargetDescriptor(target, DefaultLimits())
	})
}

func FuzzContractJSONScanner(f *testing.F) {
	f.Add(`{"descriptor_id":"target_alpha"}`)
	f.Add(`{"endpoint":"127.0.0.1"}`)
	f.Add(`{"secret":"value"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 8192 {
			t.Skip()
		}
		_ = ScanForLeak(map[string]string{"candidate": raw})
	})
}
