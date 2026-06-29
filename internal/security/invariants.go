// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

func TraceHasSecretCandidate(raw []byte, forbidden ...[]byte) bool {
	for _, item := range forbidden {
		if len(item) == 0 {
			continue
		}
		if containsBytes(raw, item) {
			return true
		}
	}
	return false
}

func containsBytes(raw, needle []byte) bool {
	if len(needle) == 0 || len(raw) < len(needle) {
		return false
	}
	for i := 0; i <= len(raw)-len(needle); i++ {
		match := true
		for j := range needle {
			if raw[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
