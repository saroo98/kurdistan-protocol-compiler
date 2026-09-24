// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build linux

package tun

import (
	"context"
	"time"

	"golang.org/x/sys/unix"
)

// Once initialization also preserves the existing direct linuxDevice literals.
// The file and constructor-only syscall/deadline seams are immutable afterward.
func (d *linuxDevice) initWriteV3() {
	d.writeInit.Do(func() {
		d.writeGate = make(chan struct{}, 1)
		d.closed = make(chan struct{})
		d.writeFailure = make(chan struct{})
		if d.setWriteDeadline == nil {
			d.setWriteDeadline = d.file.SetWriteDeadline
		}
		if d.writePacket == nil {
			d.writePacket = unix.Write
		}
	})
}

func (d *linuxDevice) writeStateV3() error {
	select {
	case <-d.closed:
		return ErrOpen
	default:
	}
	select {
	case <-d.writeFailure:
		return ErrWriteHealthV3
	default:
		return nil
	}
}

func (d *linuxDevice) latchWriteFailureV3() {
	d.writeStateMu.Lock()
	defer d.writeStateMu.Unlock()
	select {
	case <-d.closed:
		return
	default:
	}
	if !d.writeFailed {
		d.writeFailed = true
		close(d.writeFailure)
	}
}

func (d *linuxDevice) acquireWriteV3(ctx context.Context) error {
	if d == nil || d.file == nil {
		return ErrOpen
	}
	d.initWriteV3()
	if err := d.writeStateV3(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ErrPacketWriteV3
	case <-d.closed:
		return ErrOpen
	case <-d.writeFailure:
		return ErrWriteHealthV3
	case d.writeGate <- struct{}{}:
	}
	if err := d.writeStateV3(); err != nil {
		d.releaseWriteV3()
		return err
	}
	if ctx.Err() != nil {
		d.releaseWriteV3()
		return ErrPacketWriteV3
	}
	return nil
}

func (d *linuxDevice) releaseWriteV3() { <-d.writeGate }

func packetDeadlineV3(ctx context.Context, bounded bool) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil {
		return time.Time{}, ErrPacketWriteV3
	}
	deadline, ok := ctx.Deadline()
	now := time.Now()
	if !ok || !deadline.After(now) || (bounded && deadline.After(now.Add(30*time.Second))) {
		return time.Time{}, ErrPacketWriteV3
	}
	return deadline, nil
}

func (d *linuxDevice) WriteFailureV3() <-chan struct{} {
	if d == nil || d.file == nil {
		return nil
	}
	d.initWriteV3()
	return d.writeFailure
}

func (d *linuxDevice) PreparePacketWriteV3(ctx context.Context) error {
	if _, err := packetDeadlineV3(ctx, false); err != nil {
		return err
	}
	if err := d.acquireWriteV3(ctx); err != nil {
		return err
	}
	defer d.releaseWriteV3()
	deadline, err := packetDeadlineV3(ctx, false)
	if err != nil {
		return err
	}
	if err = d.setWriteDeadline(deadline); err != nil {
		return ErrPacketWriteV3
	}
	if err = d.setWriteDeadline(time.Time{}); err != nil {
		d.latchWriteFailureV3()
		if state := d.writeStateV3(); state != nil {
			return state
		}
		return ErrPacketWriteV3
	}
	if err = d.writeStateV3(); err != nil {
		return err
	}
	_, err = packetDeadlineV3(ctx, false)
	return err
}

func (d *linuxDevice) WritePacketContextV3(ctx context.Context, packet []byte) (n int, err error) {
	if len(packet) == 0 || len(packet) > 65535 {
		return 0, ErrPacketWriteV3
	}
	if _, err = packetDeadlineV3(ctx, true); err != nil {
		return 0, err
	}
	if err = d.acquireWriteV3(ctx); err != nil {
		return 0, err
	}
	defer d.releaseWriteV3()
	deadline, err := packetDeadlineV3(ctx, true)
	if err != nil {
		return 0, err
	}
	if err = d.setWriteDeadline(deadline); err != nil {
		return 0, ErrPacketWriteV3
	}
	// No payload capture. The single hook never takes the write gate or closes
	// the shared device. Its completion precedes reset and gate release.
	hookDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(hookDone)
		if e := d.setWriteDeadline(time.Unix(1, 0)); e != nil {
			d.latchWriteFailureV3()
		}
	})
	defer func() {
		if !stop() {
			<-hookDone
		}
		if e := d.setWriteDeadline(time.Time{}); e != nil {
			d.latchWriteFailureV3()
			err = ErrPacketWriteV3
		}
		if state := d.writeStateV3(); state != nil {
			err = state
			return
		}
		if ctx.Err() != nil || !deadline.After(time.Now()) {
			err = ErrPacketWriteV3
		}
	}()
	raw, e := d.file.SyscallConn()
	if e != nil {
		return 0, ErrPacketWriteV3
	}
	var syscallErr error
	pollErr := raw.Write(func(fd uintptr) bool {
		for {
			if ctx.Err() != nil || !deadline.After(time.Now()) || d.writeStateV3() != nil {
				syscallErr = ErrPacketWriteV3
				return true
			}
			n, syscallErr = d.writePacket(int(fd), packet)
			if n > 0 {
				return true
			}
			if syscallErr == unix.EINTR {
				continue
			}
			return syscallErr != unix.EAGAIN && syscallErr != unix.EWOULDBLOCK
		}
	})
	if pollErr != nil || syscallErr != nil || n != len(packet) {
		return n, ErrPacketWriteV3
	}
	return n, nil
}

var _ ContextPacketWriterV3 = (*linuxDevice)(nil)
var _ PacketWriteControlV3 = (*linuxDevice)(nil)
