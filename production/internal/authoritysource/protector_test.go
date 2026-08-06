// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package authoritysource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

const testKey = "projects/kvpn-prod-trust/locations/europe-west2/keyRings/authority/cryptoKeys/staging/cryptoKeyVersions/7"

type fakeRPC struct {
	values map[[sha256.Size]byte][]byte
	reject bool
}

func newFakeRPC() *fakeRPC { return &fakeRPC{values: make(map[[sha256.Size]byte][]byte)} }

func (rpc *fakeRPC) Encrypt(_ context.Context, request *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	if rpc.reject {
		return nil, errors.New("unavailable")
	}
	digest := sha256.Sum256(append(append([]byte(nil), request.Plaintext...), request.AdditionalAuthenticatedData...))
	rpc.values[digest] = append([]byte(nil), request.Plaintext...)
	return &kmspb.EncryptResponse{
		Name: testKey, Ciphertext: digest[:], CiphertextCrc32C: crc(digest[:]),
		VerifiedPlaintextCrc32C: true, VerifiedAdditionalAuthenticatedDataCrc32C: true,
		ProtectionLevel: kmspb.ProtectionLevel_HSM,
	}, nil
}

func (rpc *fakeRPC) Decrypt(_ context.Context, request *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	if rpc.reject || len(request.Ciphertext) != sha256.Size {
		return nil, errors.New("unavailable")
	}
	var key [sha256.Size]byte
	copy(key[:], request.Ciphertext)
	value, ok := rpc.values[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return &kmspb.DecryptResponse{Plaintext: append([]byte(nil), value...), PlaintextCrc32C: crc(value), ProtectionLevel: kmspb.ProtectionLevel_HSM}, nil
}

func testProtector(t *testing.T) *Protector {
	t.Helper()
	protector, err := New(newFakeRPC(), testKey, "production", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	protector.random = bytes.NewReader(bytes.Repeat([]byte{0x42}, 64))
	return protector
}

func TestProtectOpenBindsExactSourceAndAuthority(t *testing.T) {
	protector := testProtector(t)
	source := []byte(`{"schema":"phase16-profile-issuance-intent-source-v1"}`)
	protected, err := protector.Protect(context.Background(), "operation-123", string(bytes.Repeat([]byte{'a'}, 64)), source)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := protector.Open(context.Background(), protected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, source) {
		t.Fatal("opened source differs")
	}
	clear(opened)
}

func TestOpenRejectsTamperAndSubstitution(t *testing.T) {
	base := testProtector(t)
	protected, err := base.Protect(context.Background(), "operation-123", string(bytes.Repeat([]byte{'b'}, 64)), []byte("authority source"))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Protected){
		"operation": func(value *Protected) { value.OperationID = "operation-456" },
		"subject":   func(value *Protected) { value.SubjectDigest = string(bytes.Repeat([]byte{'c'}, 64)) },
		"nonce":     func(value *Protected) { value.Nonce[0] ^= 1 },
		"wrapped":   func(value *Protected) { value.WrappedDEK[0] ^= 1 },
		"ciphertext": func(value *Protected) {
			value.Ciphertext[0] ^= 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := protected
			candidate.Nonce = append([]byte(nil), protected.Nonce...)
			candidate.WrappedDEK = append([]byte(nil), protected.WrappedDEK...)
			candidate.Ciphertext = append([]byte(nil), protected.Ciphertext...)
			mutate(&candidate)
			if _, err := base.Open(context.Background(), candidate); err == nil {
				t.Fatal("tampered source accepted")
			}
		})
	}
}

func TestProtectorRejectsBoundsAndKeyVersionSubstitution(t *testing.T) {
	protector := testProtector(t)
	if _, err := protector.Protect(context.Background(), "operation-123", string(bytes.Repeat([]byte{'d'}, 64)), make([]byte, MaxSourceBytes+1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized error=%v", err)
	}
	rpc := newFakeRPC()
	protector, _ = New(rpc, testKey, "production", time.Second)
	protector.random = bytes.NewReader(bytes.Repeat([]byte{0x11}, 64))
	protected, err := protector.Protect(context.Background(), "operation-123", string(bytes.Repeat([]byte{'e'}, 64)), []byte("source"))
	if err != nil {
		t.Fatal(err)
	}
	for key := range rpc.values {
		value := rpc.values[key]
		delete(rpc.values, key)
		rpc.values[key] = value
	}
	protected.KeyVersion = "projects/kvpn-prod-trust/locations/europe-west2/keyRings/authority/cryptoKeys/staging/cryptoKeyVersions/8"
	if _, err := protector.Open(context.Background(), protected); err == nil {
		t.Fatal("substituted key version accepted")
	}
}
