// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxysem

func ResponseBucket(bytes int) string {
	switch {
	case bytes <= 0:
		return "none"
	case bytes <= 1024:
		return "small"
	case bytes <= 64*1024:
		return "medium"
	case bytes <= 512*1024:
		return "large"
	default:
		return "huge"
	}
}
