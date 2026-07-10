// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

import "fmt"

func ValidateChunk(chunk AdapterChunk, maxBytes int) error {
	if chunk.FlowID == "" {
		return fmt.Errorf("%w: chunk flow id required", ErrInvalidFlow)
	}
	if chunk.ByteCount < 0 || chunk.ByteCount > maxBytes {
		return fmt.Errorf("%w: chunk byte count out of bounds", ErrResourceLimit)
	}
	if containsSensitiveMarker(chunk.MetadataClass) {
		return fmt.Errorf("%w: secret-like chunk metadata rejected", ErrTraceHygiene)
	}
	return nil
}

func ByteBucket(n int) string {
	switch {
	case n == 0:
		return "zero"
	case n <= 128:
		return "tiny"
	case n <= 1024:
		return "small"
	case n <= 16*1024:
		return "medium"
	case n <= 256*1024:
		return "large"
	default:
		return "huge"
	}
}

func CountBucket(n int) string {
	switch {
	case n == 0:
		return "zero"
	case n == 1:
		return "one"
	case n <= 4:
		return "few"
	case n <= 16:
		return "many"
	default:
		return "many_plus"
	}
}
