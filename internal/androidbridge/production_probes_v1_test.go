// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bytes"
	"testing"
)

func TestProductionProbeV1OutputPreflightBeforeParentOrNetwork(t *testing.T) {
	for size := 0; size < 21; size++ {
		out := bytes.Repeat([]byte{0x5a}, size)
		n, s := RunProductionProbeV1(nil, 0, nil, out)
		if n != 0 || s != 4 || !bytes.Equal(out, bytes.Repeat([]byte{0x5a}, size)) {
			t.Fatal(n, s)
		}
	}
}
