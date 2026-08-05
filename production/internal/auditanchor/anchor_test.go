// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auditanchor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"kurdistan/internal/operator/controlplane"
	"kurdistan/internal/product/profile"
	"kurdistan/production/internal/kmsprovider"
)

type memoryStore struct {
	content []byte
	corrupt bool
}

func (store *memoryStore) PutIfAbsent(_ context.Context, _ string, content []byte) (int64, error) {
	if store.content != nil {
		return 0, errors.New("exists")
	}
	store.content = append([]byte(nil), content...)
	return 3, nil
}
func (store *memoryStore) Read(_ context.Context, _ string, generation int64) ([]byte, error) {
	if generation != 3 {
		return nil, ErrConflict
	}
	value := append([]byte(nil), store.content...)
	if store.corrupt {
		value[0] ^= 1
	}
	return value, nil
}

type fakeSigner struct {
	authorization kmsprovider.SigningAuthorization
}

func (signer *fakeSigner) SignAuthorized(_ context.Context, _ profile.KeyReference, message []byte, authorization kmsprovider.SigningAuthorization) ([]byte, error) {
	digest := sha256.Sum256(message)
	if authorization.Role != kmsprovider.RoleAudit || authorization.ExpectedMessageSHA256 != hex.EncodeToString(digest[:]) {
		return nil, ErrInvalid
	}
	signer.authorization = authorization
	return make([]byte, 64), nil
}

func TestBuildBindsSequenceChainAndExactReadback(t *testing.T) {
	store := &memoryStore{}
	signer := &fakeSigner{}
	builder, err := New(store, signer, profile.KeyReference{KeyID: "audit-key", SuiteID: 1})
	if err != nil {
		t.Fatal(err)
	}
	entries := []controlplane.AuditEntry{{Sequence: 7, Hash: digest()}, {Sequence: 8, PreviousHash: digest(), Hash: digest()}}
	receipt, err := builder.Build(context.Background(), "operation-1", "approval-1", 9, digest(), entries)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Last != 8 || receipt.Generation != 3 || signer.authorization.TrustedSequence != 9 {
		t.Fatalf("receipt=%+v authorization=%+v", receipt, signer.authorization)
	}
	store.corrupt = true
	store.content = nil
	if _, err := builder.Build(context.Background(), "operation-1", "approval-1", 9, digest(), entries); !errors.Is(err, ErrConflict) {
		t.Fatalf("tamper error=%v", err)
	}
}

func TestBuildRejectsSequenceGap(t *testing.T) {
	builder, _ := New(&memoryStore{}, &fakeSigner{}, profile.KeyReference{KeyID: "audit-key", SuiteID: 1})
	entries := []controlplane.AuditEntry{{Sequence: 7}, {Sequence: 9}}
	if _, err := builder.Build(context.Background(), "operation-1", "approval-1", 9, digest(), entries); !errors.Is(err, ErrConflict) {
		t.Fatalf("gap error=%v", err)
	}
}

func digest() string { return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
