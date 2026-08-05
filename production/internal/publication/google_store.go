// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package publication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"regexp"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
)

var bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`)

type GoogleStore struct {
	client *storage.Client
	bucket string
}

func NewGoogleStore(client *storage.Client, bucket string) (*GoogleStore, error) {
	if client == nil || !bucketRE.MatchString(bucket) {
		return nil, ErrInvalid
	}
	return &GoogleStore{client: client, bucket: bucket}, nil
}

func (store *GoogleStore) PutIfAbsent(ctx context.Context, name string, content []byte, contentType string) (ObjectAttributes, error) {
	object := store.client.Bucket(store.bucket).Object(name).If(storage.Conditions{DoesNotExist: true})
	writer := object.NewWriter(ctx)
	writer.ContentType = contentType
	writer.CacheControl = "public,max-age=31536000,immutable"
	digest := sha256.Sum256(content)
	writer.Metadata = map[string]string{"sha256": hex.EncodeToString(digest[:])}
	if _, err := writer.Write(content); err != nil {
		_ = writer.Close()
		return ObjectAttributes{}, classifyGoogleError(err)
	}
	if err := writer.Close(); err != nil {
		return ObjectAttributes{}, classifyGoogleError(err)
	}
	attrs := writer.Attrs()
	if attrs == nil {
		return ObjectAttributes{}, ErrUnavailable
	}
	return objectAttributes(attrs), nil
}

func (store *GoogleStore) Attributes(ctx context.Context, name string) (ObjectAttributes, error) {
	attrs, err := store.client.Bucket(store.bucket).Object(name).Attrs(ctx)
	if err != nil {
		return ObjectAttributes{}, classifyGoogleError(err)
	}
	return objectAttributes(attrs), nil
}

func (store *GoogleStore) Read(ctx context.Context, name string, generation, limit int64) ([]byte, error) {
	if generation <= 0 || limit <= 0 {
		return nil, ErrInvalid
	}
	reader, err := store.client.Bucket(store.bucket).Object(name).Generation(generation).NewReader(ctx)
	if err != nil {
		return nil, classifyGoogleError(err)
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, limit))
	if err != nil {
		return nil, classifyGoogleError(err)
	}
	if int64(len(content)) >= limit {
		return nil, ErrConflict
	}
	return content, nil
}

func objectAttributes(attrs *storage.ObjectAttrs) ObjectAttributes {
	return ObjectAttributes{Generation: attrs.Generation, Size: attrs.Size, SHA256: attrs.Metadata["sha256"]}
}

func classifyGoogleError(err error) error {
	var apiError *googleapi.Error
	if errors.As(err, &apiError) && apiError.Code == 412 {
		return ErrObjectExists
	}
	return ErrUnavailable
}

var _ Store = (*GoogleStore)(nil)
