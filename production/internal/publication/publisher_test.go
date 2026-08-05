// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package publication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"kurdistan/internal/product/envelope"
)

type memoryStore struct {
	objects     map[string][]byte
	generation  map[string]int64
	corruptRead bool
}

func newMemoryStore() *memoryStore {
	return &memoryStore{objects: map[string][]byte{}, generation: map[string]int64{}}
}
func (store *memoryStore) PutIfAbsent(_ context.Context, name string, content []byte, _ string) (ObjectAttributes, error) {
	if _, exists := store.objects[name]; exists {
		return ObjectAttributes{}, ErrObjectExists
	}
	store.objects[name] = append([]byte(nil), content...)
	store.generation[name] = 1
	return store.attrs(name), nil
}
func (store *memoryStore) Attributes(_ context.Context, name string) (ObjectAttributes, error) {
	if _, exists := store.objects[name]; !exists {
		return ObjectAttributes{}, ErrUnavailable
	}
	return store.attrs(name), nil
}
func (store *memoryStore) Read(_ context.Context, name string, generation, _ int64) ([]byte, error) {
	if store.generation[name] != generation {
		return nil, ErrConflict
	}
	value := append([]byte(nil), store.objects[name]...)
	if store.corruptRead {
		value[0] ^= 1
	}
	return value, nil
}
func (store *memoryStore) attrs(name string) ObjectAttributes {
	value := store.objects[name]
	digest := sha256.Sum256(value)
	return ObjectAttributes{Generation: store.generation[name], Size: int64(len(value)), SHA256: hex.EncodeToString(digest[:])}
}

func TestPublisherIsImmutableIdempotentAndReadbackVerified(t *testing.T) {
	store := newMemoryStore()
	publisher, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("signed profile artifact")
	digest := sha256.Sum256(content)
	artifact := Artifact{Bytes: content, ExpectedSHA256: hex.EncodeToString(digest[:]), ContentType: envelope.SignedObjectContentType}
	first, err := publisher.Publish(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	second, err := publisher.Publish(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !bytes.Equal(store.objects[first.ObjectName], content) {
		t.Fatalf("receipts differ: %+v %+v", first, second)
	}
	store.corruptRead = true
	if _, err := publisher.Publish(context.Background(), artifact); !errors.Is(err, ErrConflict) {
		t.Fatalf("corrupt readback error=%v", err)
	}
}

func TestPublisherRejectsDigestAndTypeMismatch(t *testing.T) {
	publisher, _ := New(newMemoryStore())
	if _, err := publisher.Publish(context.Background(), Artifact{Bytes: []byte("x"), ExpectedSHA256: string(make([]byte, 64)), ContentType: envelope.SignedObjectContentType}); err == nil {
		t.Fatal("accepted invalid digest")
	}
	digest := sha256.Sum256([]byte("x"))
	if _, err := publisher.Publish(context.Background(), Artifact{Bytes: []byte("x"), ExpectedSHA256: hex.EncodeToString(digest[:]), ContentType: "text/plain"}); err == nil {
		t.Fatal("accepted invalid content type")
	}
}
