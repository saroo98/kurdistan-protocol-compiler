// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"kurdistan/internal/product/enrollment"
)

func TestRecipientHandleCreatesCanonicalMatchingCapabilities(t *testing.T) {
	registry := HandleRegistry{}
	now := time.Unix(1_800_000_000, 0).UTC()
	handle, code := CreateRecipient(&registry, now, time.Hour, rand.Reader)
	if code != CodeOK || handle == 0 {
		t.Fatalf("create handle=%d code=%v", handle, code)
	}
	value, code := registry.Get(handle, HandleRecipient)
	if code != CodeOK {
		t.Fatalf("get code=%v", code)
	}
	state := value.(*recipientHandle)

	requestBytes, code := RecipientRequest(&registry, handle)
	if code != CodeOK {
		t.Fatalf("request code=%v", code)
	}
	privateBytes, code := RecipientPrivateExport(&registry, handle)
	if code != CodeOK {
		t.Fatalf("private code=%v", code)
	}
	request, err := enrollment.DecodeAndVerifyRequestV1(requestBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	if request.RequestID != state.credentials.Request.RequestID {
		t.Fatal("request identity changed")
	}
	credentials, code := DecodeRecipientCredentials(requestBytes, privateBytes)
	if code != CodeOK {
		t.Fatalf("decode code=%v", code)
	}
	credentials.Destroy()

	privateBytes[0] ^= 0xff
	if bytes.Equal(privateBytes, mustRecipientPrivate(t, &registry, handle)) {
		t.Fatal("private export aliases handle state")
	}
	privateRef := state.credentials.Private.RecipientPrivate
	seedRef := state.credentials.Private.ClientAuthSeed
	if code := registry.Free(handle); code != CodeOK {
		t.Fatalf("free code=%v", code)
	}
	if !allZero(privateRef) || !allZero(seedRef) {
		t.Fatal("private capability was not wiped on close")
	}
	if _, code := RecipientRequest(&registry, handle); code != CodeAlreadyClosed {
		t.Fatalf("use-after-close code=%v", code)
	}
}

func TestRecipientHandleRejectsWrongTypeCancellationAndMismatchedPrivateBundle(t *testing.T) {
	registry := HandleRegistry{}
	if _, code := RecipientRequest(&registry, 0); code != CodeInvalidHandle {
		t.Fatalf("zero handle code=%v", code)
	}
	other, code := registry.Open(HandleBackup, &backupHandle{})
	if code != CodeOK {
		t.Fatalf("open other code=%v", code)
	}
	if _, code := RecipientRequest(&registry, other); code != CodeWrongHandleType {
		t.Fatalf("wrong type code=%v", code)
	}
	_ = registry.Free(other)

	now := time.Unix(1_800_000_000, 0).UTC()
	first, code := CreateRecipient(&registry, now, time.Hour, rand.Reader)
	if code != CodeOK {
		t.Fatalf("first create code=%v", code)
	}
	second, code := CreateRecipient(&registry, now, time.Hour, rand.Reader)
	if code != CodeOK {
		t.Fatalf("second create code=%v", code)
	}
	defer registry.Free(first)
	defer registry.Free(second)
	request, _ := RecipientRequest(&registry, first)
	private, _ := RecipientPrivateExport(&registry, second)
	if credentials, code := DecodeRecipientCredentials(request, private); code == CodeOK {
		credentials.Destroy()
		t.Fatal("accepted mismatched public/private capability")
	}
	if code := registry.Cancel(first); code != CodeOK {
		t.Fatalf("cancel code=%v", code)
	}
	if _, code := RecipientPrivateExport(&registry, first); code != CodeCancelled {
		t.Fatalf("cancelled export code=%v", code)
	}
}

func mustRecipientPrivate(t *testing.T, registry *HandleRegistry, handle Handle) []byte {
	t.Helper()
	encoded, code := RecipientPrivateExport(registry, handle)
	if code != CodeOK {
		t.Fatalf("private code=%v", code)
	}
	return encoded
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
