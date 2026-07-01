// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

func ConsentModeIsSafeDefault(mode string) bool {
	return mode == ConsentDisabled || mode == ConsentLocalOnly
}
