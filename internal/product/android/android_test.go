// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package android

import "testing"

func TestDefaultContractIsValid(t *testing.T) {
	if err := Validate(DefaultSourceContract()); err != nil {
		t.Fatalf("default source contract must be valid: %v", err)
	}
}

func TestValidateRejectsUnsafeSettings(t *testing.T) {
	cases := map[string]func(*SourceContract){
		"payload logging":      func(c *SourceContract) { c.PayloadLogging = true },
		"destination logging":  func(c *SourceContract) { c.DestinationLogging = true },
		"not fail-closed":      func(c *SourceContract) { c.FailClosed = false },
		"unbounded fallback":   func(c *SourceContract) { c.BoundedFallback = false },
		"no redaction":         func(c *SourceContract) { c.RedactedDiagnostics = false },
		"not permission-first": func(c *SourceContract) { c.PermissionFirst = false },
		"go-models tree root":  func(c *SourceContract) { c.TreeRoot = "internal/contracts/android" },
	}
	for name, mutate := range cases {
		c := DefaultSourceContract()
		mutate(&c)
		if err := Validate(c); err == nil {
			t.Errorf("Validate accepted unsafe contract (%s)", name)
		}
	}
}
