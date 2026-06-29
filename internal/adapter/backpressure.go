// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

func WouldBackpressure(current, incoming, limit int) bool {
	return incoming < 0 || limit <= 0 || current+incoming > limit
}
