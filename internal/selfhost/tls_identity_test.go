// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestTLSIdentityIsBoundIndependentAndBounded(t *testing.T) {
	master := bytes.Repeat([]byte{0x41}, 32)
	random := bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096))
	now := time.Unix(1_760_000_000, 0).UTC()
	identity, err := newTLSIdentityWithRandom(master, "deployment.fixture", "203.0.113.7", 1, now, random)
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(identity.NotAfter, 0).Sub(time.Unix(identity.NotBefore, 0)); got != tlsMaximumLifetime {
		t.Fatalf("TLS lifetime=%s", got)
	}
	if err := validateTLSIdentity(master, "deployment.fixture", identity, bytes.Repeat([]byte{0x43}, 32)); err != nil {
		t.Fatal(err)
	}
	opened, err := openTLSSeed(master, "deployment.fixture", identity)
	if err != nil || len(opened.Bytes()) != 32 {
		t.Fatalf("open err=%v", err)
	}
	opened.Close()
	opened.Close()
	if opened.Bytes() != nil {
		t.Fatal("closed TLS seed remains accessible")
	}
	if err := validateProfileTLSLifetime(identity, now.Unix(), identity.NotAfter-int64(tlsProfileMargin/time.Second)+1); !errors.Is(err, ErrTLSUnavailable) {
		t.Fatalf("profile beyond certificate margin accepted: %v", err)
	}
	mutated := identity
	mutated.LeafDigest = append([]byte(nil), identity.LeafDigest...)
	mutated.LeafDigest[0] ^= 1
	if err := validateTLSIdentity(master, "deployment.fixture", mutated, nil); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("digest mutation accepted: %v", err)
	}
}

func TestTLSIdentitySupportsCanonicalLowercaseDNSOnly(t *testing.T) {
	master := bytes.Repeat([]byte{0x51}, 32)
	if _, err := newTLSIdentityWithRandom(master, "deployment.fixture", "Node.Example", 1, time.Now(), bytes.NewReader(bytes.Repeat([]byte{0x52}, 4096))); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("uppercase DNS accepted: %v", err)
	}
	if _, err := newTLSIdentityWithRandom(master, "deployment.fixture", "*.example", 1, time.Now(), bytes.NewReader(bytes.Repeat([]byte{0x52}, 4096))); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("wildcard accepted: %v", err)
	}
}
