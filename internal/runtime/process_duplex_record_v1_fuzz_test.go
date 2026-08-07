// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"testing"

	"kurdistan/internal/protocol/wirev1"
)

func FuzzProcessDuplexRecordV1(f *testing.F) {
	body := encodeDuplexControlBodyV1(duplexKindKeepaliveV1, 0)
	f.Add(body)
	f.Add([]byte{})
	f.Add([]byte("KURDDPX01"))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		kind, _, frames, err := decodeDuplexBodyV1(encoded)
		defer clearFrameSetV1(frames)
		if err == nil && kind == duplexKindOperationV1 && len(frames) == 0 {
			t.Fatal("operation decoded without frames")
		}
		_, _ = wirev1.Decode(encoded)
	})
}
