// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package publication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"kurdistan/internal/product/envelope"
)

var (
	ErrInvalid      = errors.New("publication: invalid input")
	ErrObjectExists = errors.New("publication: object exists")
	ErrConflict     = errors.New("publication: immutable object conflict")
	ErrUnavailable  = errors.New("publication: storage unavailable")
	digestRE        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type ObjectAttributes struct {
	Generation int64
	Size       int64
	SHA256     string
}

type Store interface {
	PutIfAbsent(context.Context, string, []byte, string) (ObjectAttributes, error)
	Attributes(context.Context, string) (ObjectAttributes, error)
	Read(context.Context, string, int64, int64) ([]byte, error)
}

type Artifact struct {
	Bytes          []byte
	ExpectedSHA256 string
	ContentType    string
}

type Receipt struct {
	Schema     string
	ObjectName string
	SHA256     string
	Generation int64
	Size       int64
}

type Publisher struct{ store Store }

func New(store Store) (*Publisher, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	return &Publisher{store: store}, nil
}

func (publisher *Publisher) Publish(ctx context.Context, artifact Artifact) (Receipt, error) {
	if ctx == nil || len(artifact.Bytes) == 0 || len(artifact.Bytes) > envelope.MaxSealedFrameBytes ||
		!digestRE.MatchString(artifact.ExpectedSHA256) || !allowedContentType(artifact.ContentType) {
		return Receipt{}, ErrInvalid
	}
	digest := sha256.Sum256(artifact.Bytes)
	digestText := hex.EncodeToString(digest[:])
	if digestText != artifact.ExpectedSHA256 {
		return Receipt{}, ErrConflict
	}
	name := fmt.Sprintf("profiles/sha256/%s.kurd", digestText)
	attributes, err := publisher.store.PutIfAbsent(ctx, name, artifact.Bytes, artifact.ContentType)
	if errors.Is(err, ErrObjectExists) {
		attributes, err = publisher.store.Attributes(ctx, name)
	}
	if err != nil {
		return Receipt{}, err
	}
	if attributes.Generation <= 0 || attributes.Size != int64(len(artifact.Bytes)) || attributes.SHA256 != digestText {
		return Receipt{}, ErrConflict
	}
	readback, err := publisher.store.Read(ctx, name, attributes.Generation, int64(envelope.MaxSealedFrameBytes)+1)
	if err != nil {
		return Receipt{}, err
	}
	readbackDigest := sha256.Sum256(readback)
	if len(readback) != len(artifact.Bytes) || hex.EncodeToString(readbackDigest[:]) != digestText {
		return Receipt{}, ErrConflict
	}
	return Receipt{Schema: "phase16-immutable-publication-receipt-v1", ObjectName: name, SHA256: digestText, Generation: attributes.Generation, Size: attributes.Size}, nil
}

func allowedContentType(value string) bool {
	return value == envelope.SignedObjectContentType || value == envelope.SealedObjectContentType
}
