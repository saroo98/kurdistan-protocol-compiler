//go:build !phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import "kurdistan/internal/androidbridge"

const phase11MaximumPayloadBytes = 32 << 10

func phase11RoundTrip([]byte) ([]byte, androidbridge.ErrorCode) {
	return nil, androidbridge.CodeTrustUnavailable
}
