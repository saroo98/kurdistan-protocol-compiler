// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package boundeddns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The cancellation callback reaches socket state only, never the workspace,
// domain or caller output. One callback is owned and joined per operation.
type operation struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	conn     net.Conn
	closed   bool
	hookDone chan struct{}
	stopHook func() bool
}

func newOperation(parent context.Context, deadline time.Time) *operation {
	ctx, cancel := context.WithDeadline(parent, deadline)
	op := &operation{ctx: ctx, cancel: cancel, hookDone: make(chan struct{})}
	op.stopHook = context.AfterFunc(ctx, func() { defer close(op.hookDone); op.abort() })
	return op
}

func (op *operation) abort() {
	op.mu.Lock()
	op.closed = true
	c := op.conn
	op.conn = nil
	op.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func (op *operation) closeSocket() {
	op.mu.Lock()
	c := op.conn
	op.conn = nil
	op.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func (op *operation) install(ctx context.Context, c net.Conn) error {
	op.mu.Lock()
	if op.closed || ctx.Err() != nil || op.ctx.Err() != nil {
		op.mu.Unlock()
		_ = c.Close()
		if err := contextError(ctx); err != nil {
			return err
		}
		return ErrCancelled
	}
	op.conn = c
	op.mu.Unlock()
	return nil
}

func (op *operation) finish() {
	op.abort()
	if !op.stopHook() {
		<-op.hookDone
	}
	op.cancel()
}

func (op *operation) exchange(owner SocketOwner, server netip.AddrPort, w *workspace, query []byte, kind dnsmessage.Type, id uint16) error {
	ctx, cancel := context.WithTimeout(op.ctx, time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := contextError(ctx); err != nil {
		return err
	}
	udp, err := owner.DialUDP(ctx, server)
	if err != nil {
		if udp != nil {
			_ = udp.Close()
		}
		return transportError(ctx, err)
	}
	if udp == nil {
		return ErrNetwork
	}
	if err = op.install(ctx, udp); err != nil {
		return err
	}
	defer op.closeSocket()
	if err = udp.SetDeadline(deadline); err != nil {
		return transportError(ctx, err)
	}
	if n, e := udp.Write(query); e != nil || n != len(query) {
		return transportError(ctx, e)
	}
	for irrelevant := 0; irrelevant < 4; irrelevant++ {
		n, e := udp.Read(w.udp[:])
		if e != nil {
			return transportError(ctx, e)
		}
		if n > 512 {
			return ErrSizeLimit
		}
		tc, e := w.acceptResponse(w.udp[:n], kind, id)
		if expired := contextError(ctx); expired != nil {
			return expired
		}
		if e == errIrrelevant {
			continue
		}
		if e != nil {
			return e
		}
		if tc {
			op.closeSocket()
			return op.tcpExchange(ctx, owner, server, w, query, kind, id)
		}
		return nil
	}
	return ErrResponse
}

func (op *operation) tcpExchange(ctx context.Context, owner SocketOwner, server netip.AddrPort, w *workspace, query []byte, kind dnsmessage.Type, id uint16) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	tcp, err := owner.DialTCP(ctx, server)
	if err != nil {
		if tcp != nil {
			_ = tcp.Close()
		}
		return transportError(ctx, err)
	}
	if tcp == nil {
		return ErrNetwork
	}
	if err = op.install(ctx, tcp); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err = tcp.SetDeadline(deadline); err != nil {
		return transportError(ctx, err)
	}
	binary.BigEndian.PutUint16(w.prefix[:], uint16(len(query)))
	if n, e := tcp.Write(w.prefix[:]); e != nil || n != len(w.prefix) {
		return transportError(ctx, e)
	}
	if n, e := tcp.Write(query); e != nil || n != len(query) {
		return transportError(ctx, e)
	}
	if _, err = io.ReadFull(tcp, w.prefix[:]); err != nil {
		return transportError(ctx, err)
	}
	size := int(binary.BigEndian.Uint16(w.prefix[:]))
	if size < 12 || size > len(w.tcp) {
		return ErrResponse
	}
	if _, err = io.ReadFull(tcp, w.tcp[:size]); err != nil {
		return transportError(ctx, err)
	}
	tc, err := w.acceptResponse(w.tcp[:size], kind, id)
	if expired := contextError(ctx); expired != nil {
		return expired
	}
	if tc || err == errIrrelevant {
		return ErrResponse
	}
	return err
}

func transportError(ctx context.Context, err error) error {
	if cancelled := contextError(ctx); cancelled != nil {
		return cancelled
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return ErrTimeout
	}
	return ErrNetwork
}
