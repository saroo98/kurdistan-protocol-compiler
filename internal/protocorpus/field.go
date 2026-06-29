// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

func FieldKindNames() []string {
	out := make([]string, 0, len(SupportedFieldKinds()))
	for _, kind := range SupportedFieldKinds() {
		out = append(out, string(kind))
	}
	return out
}
