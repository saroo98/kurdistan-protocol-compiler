// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

func FamilyNames() []string {
	out := make([]string, 0, len(SupportedFamilies()))
	for _, family := range SupportedFamilies() {
		out = append(out, string(family))
	}
	return out
}
