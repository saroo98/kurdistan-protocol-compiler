// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package scannera

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func FuzzPrivacyScannerA(f *testing.F) {
	f.Add(scannerStream(
		[2]string{"ANDROID_LOGCAT", "categorical android output"},
		[2]string{"REMOTE_JOURNAL", "categorical relay output"},
	))
	f.Add([]byte("not-json\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaximumBytes+1 {
			return
		}
		receipt := Scan(bytes.NewReader(raw), int64(len(raw)))
		if receipt.BytesConsumed > MaximumBytes+1 {
			t.Fatalf("scanner consumed %d bytes", receipt.BytesConsumed)
		}
		if receipt.Result != "PASS" {
			return
		}
		digest := sha256.Sum256(raw)
		if receipt.Schema != ReceiptSchema || receipt.Name != "GO_A" ||
			receipt.InputSHA256 != hex.EncodeToString(digest[:]) || receipt.BytesConsumed != uint64(len(raw)) ||
			receipt.RecordsConsumed < 2 || receipt.Truncated || receipt.ParseFailure || receipt.BackpressureFailure ||
			receipt.CoverageGap || receipt.Privacy != (Privacy{}) {
			t.Fatalf("scanner emitted invalid PASS receipt: %+v", receipt)
		}
	})
}
