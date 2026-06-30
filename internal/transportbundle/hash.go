// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import "kurdistan/internal/adaptivepath"

func HashValue(value any) string {
	return adaptivepath.HashValue(value)
}

func StableJSON(value any) ([]byte, error) {
	return adaptivepath.StableJSON(value)
}
