// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package tlstcp implements the first bounded live carrier: Kurd wire-v1 over
// TLS 1.3 over an already-owned stream connection. Address resolution and
// dialing remain outside this package.
package tlstcp

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"kurdistan/internal/protocol/wirev1"
)

const (
	ALPN          = "kurd/1"
	exporterLabel = "EXPORTER-Kurdistan-VPN-wire-v1"
)

var ErrCarrier = errors.New("tlstcp: carrier rejected")

type Conn struct {
	conn       *tls.Conn
	planDigest [32]byte
	binding    [32]byte
	maxFrame   uint32
	stateMu    sync.RWMutex
	readMu     sync.Mutex
	writeMu    sync.Mutex
}

func Client(ctx context.Context, raw net.Conn, config *tls.Config, planDigest [32]byte, maxFrame uint32) (*Conn, error) {
	return establish(ctx, raw, config, planDigest, maxFrame, false)
}

func Server(ctx context.Context, raw net.Conn, config *tls.Config, planDigest [32]byte, maxFrame uint32) (*Conn, error) {
	return establish(ctx, raw, config, planDigest, maxFrame, true)
}

func establish(ctx context.Context, raw net.Conn, config *tls.Config, planDigest [32]byte, maxFrame uint32, server bool) (*Conn, error) {
	if ctx == nil || raw == nil || config == nil || planDigest == ([32]byte{}) ||
		maxFrame < wirev1.HeaderBytes || maxFrame > wirev1.HeaderBytes+wirev1.MaxPayloadBytes {
		return nil, ErrCarrier
	}
	cfg := config.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	cfg.NextProtos = []string{ALPN}
	cfg.SessionTicketsDisabled = true
	cfg.ClientSessionCache = nil
	var secured *tls.Conn
	if server {
		secured = tls.Server(raw, cfg)
	} else {
		if cfg.ServerName == "" || cfg.InsecureSkipVerify {
			return nil, ErrCarrier
		}
		secured = tls.Client(raw, cfg)
	}
	if err := secured.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, ErrCarrier
	}
	state := secured.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != ALPN || !state.NegotiatedProtocolIsMutual {
		_ = raw.Close()
		return nil, ErrCarrier
	}
	exported, err := state.ExportKeyingMaterial(exporterLabel, planDigest[:], 32)
	if err != nil || len(exported) != 32 {
		_ = raw.Close()
		return nil, ErrCarrier
	}
	result := &Conn{conn: secured, planDigest: planDigest, maxFrame: maxFrame}
	copy(result.binding[:], exported)
	clear(exported)
	return result, nil
}

func (conn *Conn) CarrierBinding() ([32]byte, error) {
	if conn == nil {
		return [32]byte{}, ErrCarrier
	}
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	if conn.conn == nil || conn.binding == ([32]byte{}) {
		return [32]byte{}, ErrCarrier
	}
	return conn.binding, nil
}

func (conn *Conn) Send(ctx context.Context, frame wirev1.Frame) error {
	if conn == nil || ctx == nil || frame.PlanDigest != conn.planDigest {
		return ErrCarrier
	}
	conn.stateMu.RLock()
	secured := conn.conn
	conn.stateMu.RUnlock()
	if secured == nil {
		return ErrCarrier
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return ErrCarrier
	}
	encoded, err := wirev1.Encode(frame)
	if err != nil || len(encoded) > int(conn.maxFrame) {
		return ErrCarrier
	}
	conn.writeMu.Lock()
	defer conn.writeMu.Unlock()
	if err := secured.SetWriteDeadline(deadline); err != nil {
		return ErrCarrier
	}
	defer secured.SetWriteDeadline(timeZero)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encoded)))
	if err := writeFull(secured, length[:]); err != nil {
		return ErrCarrier
	}
	if err := writeFull(secured, encoded); err != nil {
		return ErrCarrier
	}
	return nil
}

func (conn *Conn) Receive(ctx context.Context) (wirev1.Frame, error) {
	if conn == nil || ctx == nil {
		return wirev1.Frame{}, ErrCarrier
	}
	conn.stateMu.RLock()
	secured := conn.conn
	conn.stateMu.RUnlock()
	if secured == nil {
		return wirev1.Frame{}, ErrCarrier
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return wirev1.Frame{}, ErrCarrier
	}
	conn.readMu.Lock()
	defer conn.readMu.Unlock()
	if err := secured.SetReadDeadline(deadline); err != nil {
		return wirev1.Frame{}, ErrCarrier
	}
	defer secured.SetReadDeadline(timeZero)
	var length [4]byte
	if _, err := io.ReadFull(secured, length[:]); err != nil {
		return wirev1.Frame{}, ErrCarrier
	}
	size := binary.BigEndian.Uint32(length[:])
	if size < wirev1.HeaderBytes || size > conn.maxFrame {
		return wirev1.Frame{}, ErrCarrier
	}
	encoded := make([]byte, size)
	if _, err := io.ReadFull(secured, encoded); err != nil {
		clear(encoded)
		return wirev1.Frame{}, ErrCarrier
	}
	frame, err := wirev1.Decode(encoded)
	clear(encoded)
	if err != nil || frame.PlanDigest != conn.planDigest {
		clear(frame.Payload)
		return wirev1.Frame{}, ErrCarrier
	}
	return frame, nil
}

func (conn *Conn) Close() error {
	if conn == nil {
		return nil
	}
	conn.stateMu.Lock()
	secured := conn.conn
	if secured == nil {
		conn.stateMu.Unlock()
		return nil
	}
	conn.conn = nil
	clear(conn.binding[:])
	conn.stateMu.Unlock()
	_ = secured.SetDeadline(time.Now())
	return secured.NetConn().Close()
}

var timeZero = time.Time{}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		n, err := writer.Write(value)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(value) {
			return io.ErrShortWrite
		}
		value = value[n:]
	}
	return nil
}
