// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package tlstcp

import (
	"context"
	"crypto/tls"
	"time"
	"unsafe"
)

const (
	maxRecordStreamTimeoutV3              = 48 * time.Hour
	recordStreamDirectionAllowanceBytesV3 = 4096
)

// RecordStreamBoundsV3 describes the fixed native ownership retained for one
// selected TLS record stream. TLS, kernel, Go runtime and caller buffers are
// outside this accounting boundary.
type RecordStreamBoundsV3 struct {
	OwnedBytes         uint64
	QueuedPayloadBytes uint64
	MaxRecordBytes     uint32
}

// RecordStreamV3 is the exclusive direct TLS byte stream selected from Conn.
// The caller and RecordStreamV3 retain ownership until Close.
type RecordStreamV3 struct {
	owner     *Conn
	parent    context.Context
	ioTimeout time.Duration
}

// RecordStreamOwnedBytesV3 permits the trusted containing owner to reserve the
// fixed Conn/view state and one bounded callback/deadline holder per direction
// before selecting the stream.
func RecordStreamOwnedBytesV3() uint64 {
	return uint64(unsafe.Sizeof(Conn{})) + uint64(unsafe.Sizeof(RecordStreamV3{})) +
		2*recordStreamDirectionAllowanceBytesV3
}

// SelectRecordStreamV3 performs a one-way, exclusive handoff from framed
// Send/Receive operations to direct TLS record bytes.
func (conn *Conn) SelectRecordStreamV3(parent context.Context, ioTimeout time.Duration) (*RecordStreamV3, error) {
	if conn == nil || parent == nil || parent.Err() != nil || ioTimeout <= 0 || ioTimeout > maxRecordStreamTimeoutV3 {
		return nil, ErrCarrier
	}
	if !conn.readMu.TryLock() {
		return nil, ErrCarrier
	}
	defer conn.readMu.Unlock()
	if !conn.writeMu.TryLock() {
		return nil, ErrCarrier
	}
	defer conn.writeMu.Unlock()

	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	if conn.conn == nil || conn.selected != nil {
		return nil, ErrCarrier
	}
	stream := &RecordStreamV3{owner: conn, parent: parent, ioTimeout: ioTimeout}
	conn.selected = stream
	return stream, nil
}

func (stream *RecordStreamV3) Read(output []byte) (int, error) {
	if stream == nil || stream.owner == nil {
		return 0, ErrCarrier
	}
	stream.owner.readMu.Lock()
	defer stream.owner.readMu.Unlock()
	return stream.ioV3(output, true)
}

func (stream *RecordStreamV3) Write(input []byte) (int, error) {
	if stream == nil || stream.owner == nil {
		return 0, ErrCarrier
	}
	stream.owner.writeMu.Lock()
	defer stream.owner.writeMu.Unlock()
	return stream.ioV3(input, false)
}

func (stream *RecordStreamV3) ioV3(value []byte, read bool) (int, error) {
	owner := stream.owner
	owner.stateMu.RLock()
	secured := owner.conn
	live := secured != nil && owner.selected == stream
	owner.stateMu.RUnlock()
	if !live {
		return 0, ErrCarrier
	}
	if stream.parent.Err() != nil {
		_ = owner.Close()
		return 0, ErrCarrier
	}

	now := time.Now()
	deadline := now.Add(stream.ioTimeout)
	if parentDeadline, ok := stream.parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	if !deadline.After(now) {
		return 0, ErrCarrier
	}
	hookDone := make(chan struct{})
	stopHook := context.AfterFunc(stream.parent, func() {
		defer close(hookDone)
		_ = owner.Close()
	})
	if err := setRecordStreamDeadlineV3(secured, read, deadline); err != nil {
		if !stopHook() {
			<-hookDone
		}
		if stream.parent.Err() != nil {
			_ = owner.Close()
		}
		return 0, ErrCarrier
	}
	n, err := recordStreamIOV3(secured, value, read)

	owner.stateMu.RLock()
	live = owner.conn == secured && owner.selected == stream
	var resetErr error
	if live {
		resetErr = setRecordStreamDeadlineV3(secured, read, timeZero)
	}
	owner.stateMu.RUnlock()
	if !stopHook() {
		<-hookDone
	}
	owner.stateMu.RLock()
	live = owner.conn == secured && owner.selected == stream
	owner.stateMu.RUnlock()
	if stream.parent.Err() != nil {
		_ = owner.Close()
		live = false
	}
	if err != nil || resetErr != nil || !live {
		return n, ErrCarrier
	}
	return n, nil
}

func setRecordStreamDeadlineV3(secured *tls.Conn, read bool, deadline time.Time) error {
	if read {
		return secured.SetReadDeadline(deadline)
	}
	return secured.SetWriteDeadline(deadline)
}

func recordStreamIOV3(secured *tls.Conn, value []byte, read bool) (int, error) {
	if read {
		return secured.Read(value)
	}
	return secured.Write(value)
}

func (stream *RecordStreamV3) Close() error {
	if stream == nil || stream.owner == nil {
		return nil
	}
	return stream.owner.Close()
}

func (stream *RecordStreamV3) BoundsV3() RecordStreamBoundsV3 {
	if stream == nil || stream.owner == nil {
		return RecordStreamBoundsV3{}
	}
	stream.owner.stateMu.RLock()
	defer stream.owner.stateMu.RUnlock()
	if stream.owner.conn == nil || stream.owner.selected != stream {
		return RecordStreamBoundsV3{}
	}
	return RecordStreamBoundsV3{
		OwnedBytes: RecordStreamOwnedBytesV3(), MaxRecordBytes: stream.owner.maxFrame,
	}
}
