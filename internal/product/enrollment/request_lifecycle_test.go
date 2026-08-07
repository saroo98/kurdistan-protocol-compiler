// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package enrollment

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestDecodeRequestPreservesIssuedCapabilityAfterEnrollmentExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	request, private, err := Generate(now, time.Minute, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentLifecyclePrivate(private)
	encoded, err := EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndVerifyRequestV1(encoded, now.Add(time.Minute)); !IsCategory(err, ErrorExpired) {
		t.Fatalf("time-bound admission err=%v", err)
	}
	decoded, err := DecodeRequestV1(encoded)
	if err != nil || decoded.RequestID != request.RequestID {
		t.Fatalf("timeless issued-capability decode request=%+v err=%v", decoded, err)
	}
}

func clearEnrollmentLifecyclePrivate(private PrivateBundleV1) {
	clear(private.RecipientPrivate)
	clear(private.ClientAuthSeed)
}
