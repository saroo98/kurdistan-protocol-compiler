// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrier

import "kurdistan/internal/ir"

func Lookup(name string) bool {
	for _, family := range ir.CarrierFamilies() {
		if family == name {
			return true
		}
	}
	return false
}
