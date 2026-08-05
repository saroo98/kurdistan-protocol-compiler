// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auditanchor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"kurdistan/internal/operator/controlplane"
	"kurdistan/internal/product/profile"
	"kurdistan/production/internal/kmsprovider"
)

var (
	ErrInvalid  = errors.New("auditanchor: invalid input")
	ErrConflict = errors.New("auditanchor: chain conflict")
)

type Store interface {
	PutIfAbsent(context.Context, string, []byte) (int64, error)
	Read(context.Context, string, int64) ([]byte, error)
}

type Signer interface {
	SignAuthorized(context.Context, profile.KeyReference, []byte, kmsprovider.SigningAuthorization) ([]byte, error)
}

type Anchor struct {
	Schema         string `json:"schema"`
	FirstSequence  uint64 `json:"firstSequence"`
	LastSequence   uint64 `json:"lastSequence"`
	PreviousDigest string `json:"previousDigest"`
	BatchDigest    string `json:"batchDigest"`
	KeyID          string `json:"keyId"`
	Signature      string `json:"signature"`
}

type Receipt struct {
	ObjectName string
	Generation int64
	Digest     string
	Last       uint64
}

type Builder struct {
	store  Store
	signer Signer
	key    profile.KeyReference
}

func New(store Store, signer Signer, key profile.KeyReference) (*Builder, error) {
	if store == nil || signer == nil || key.KeyID == "" {
		return nil, ErrInvalid
	}
	return &Builder{store: store, signer: signer, key: key}, nil
}

func (builder *Builder) Build(ctx context.Context, operationID, approvalID string, trustedSequence uint64, previous string, entries []controlplane.AuditEntry) (Receipt, error) {
	if ctx == nil || operationID == "" || approvalID == "" || trustedSequence == 0 || len(previous) != 64 || len(entries) == 0 || len(entries) > 256 {
		return Receipt{}, ErrInvalid
	}
	for index, entry := range entries {
		if entry.Sequence == 0 || (index > 0 && entry.Sequence != entries[index-1].Sequence+1) {
			return Receipt{}, ErrConflict
		}
	}
	batch, err := json.Marshal(entries)
	if err != nil {
		return Receipt{}, ErrInvalid
	}
	batchHash := sha256.Sum256(batch)
	unsigned := Anchor{Schema: "phase16-audit-anchor-v1", FirstSequence: entries[0].Sequence, LastSequence: entries[len(entries)-1].Sequence, PreviousDigest: previous, BatchDigest: hex.EncodeToString(batchHash[:]), KeyID: builder.key.KeyID}
	message, err := json.Marshal(unsigned)
	if err != nil {
		return Receipt{}, ErrInvalid
	}
	messageHash := sha256.Sum256(message)
	signature, err := builder.signer.SignAuthorized(ctx, builder.key, message, kmsprovider.SigningAuthorization{Role: kmsprovider.RoleAudit, OperationID: operationID, ApprovalID: approvalID, ExpectedMessageSHA256: hex.EncodeToString(messageHash[:]), TrustedSequence: trustedSequence})
	if err != nil {
		return Receipt{}, err
	}
	unsigned.Signature = hex.EncodeToString(signature)
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return Receipt{}, ErrInvalid
	}
	digest := sha256.Sum256(payload)
	digestText := hex.EncodeToString(digest[:])
	name := fmt.Sprintf("anchors/%020d-%020d-%s.json", unsigned.FirstSequence, unsigned.LastSequence, digestText)
	generation, err := builder.store.PutIfAbsent(ctx, name, payload)
	if err != nil || generation <= 0 {
		return Receipt{}, err
	}
	readback, err := builder.store.Read(ctx, name, generation)
	if err != nil {
		return Receipt{}, err
	}
	readbackHash := sha256.Sum256(readback)
	if hex.EncodeToString(readbackHash[:]) != digestText {
		return Receipt{}, ErrConflict
	}
	return Receipt{ObjectName: name, Generation: generation, Digest: digestText, Last: unsigned.LastSequence}, nil
}
