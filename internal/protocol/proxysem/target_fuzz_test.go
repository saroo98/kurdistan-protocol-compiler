// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxysem

import "testing"

func FuzzTargetDescriptorValidator(f *testing.F) {
	f.Add(TargetEcho, "", "bytes", "1024")
	f.Add(TargetFixedResponse, "small", "bytes", "4096")
	f.Add("unknown", "", "host", "example.com")
	registry := DefaultRegistry()
	f.Fuzz(func(t *testing.T, class, variant, key, value string) {
		desc := TargetDescriptor{Class: class, Variant: variant, Parameters: map[string]string{}}
		if key != "" {
			if len(key) > 64 {
				key = key[:64]
			}
			if len(value) > 64 {
				value = value[:64]
			}
			desc.Parameters[key] = value
		}
		_ = registry.Validate(desc)
		if _, _, err := registry.Run(desc, TargetRequest{StreamID: 1, Bytes: 32, Class: RequestInteractive}, 1); err != nil {
			return
		}
	})
}
