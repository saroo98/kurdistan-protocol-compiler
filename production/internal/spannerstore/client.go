// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package spannerstore

import (
	"context"
	"time"
)

const SchemaVersion = "phase16-spanner-authority-v1"

type Head struct {
	Environment     string
	Revision        uint64
	NextSequence    uint64
	TrustedSequence uint64
	LastTrustedAt   time.Time
	StateJSON       []byte
	SchemaVersion   string
}

type JSONRecord struct {
	ID      string
	Parent  string
	Ordinal uint64
	State   string
	Payload []byte
}

type WriteSet struct {
	Head              Head
	AuthoritySources  []JSONRecord
	Operations        []JSONRecord
	Approvals         []JSONRecord
	Profiles          []JSONRecord
	Relays            []JSONRecord
	Publications      []JSONRecord
	EmergencyAuth     []JSONRecord
	EmergencyRules    []JSONRecord
	Outbox            []JSONRecord
	Audit             []JSONRecord
	Idempotency       []JSONRecord
	ReserveCommitTime bool
}

type Transaction interface {
	ReadHead(context.Context, string) (Head, error)
	Buffer(WriteSet) error
}

type Client interface {
	StrongReadHead(context.Context, string) (Head, error)
	ReadWrite(context.Context, func(context.Context, Transaction) error) (time.Time, error)
}
