// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package loopbackharness composes the Phase 11 loopback-only resolver, strict
// TLS carrier, and authenticated Kurd runtime. It forwards one bounded message
// to an owned in-memory sink only after both carrier binding and inner
// authentication succeed.
package loopbackharness

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"

	"kurdistan/internal/lab/hardening/loopbackresolver"
	"kurdistan/internal/product/livecarrier"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/wirev1"
	"kurdistan/internal/transport/tlstcp"
)

var ErrHarness = errors.New("loopbackharness: session rejected")

const (
	bindingSlot uint16 = 1
	dataSlot    uint16 = 2
)

type Sink interface {
	Deliver(context.Context, []byte) error
}

type ClientProtector interface {
	Seal(uint16, []byte) ([]byte, error)
	AcceptAck([]byte) error
	Abort()
}

type RelayProtector interface {
	Open([]byte) ([]byte, Delivery, error)
	Abort()
}

type Delivery interface {
	Commit() ([]byte, error)
	Reject()
}

// NewLocalConformancePlanV1 returns the minimal immutable authority value used
// by the loopback-only conformance harness. It does not resolve, dial, or grant
// non-loopback authority.
func NewLocalConformancePlanV1(endpointReference string, digest [32]byte, dialTimeoutMillis, maxFrameBytes uint32) sessionplan.Plan {
	return sessionplan.Plan{
		Version: sessionplan.Version, StrategyFamily: "https_like_tcp",
		CarrierFamily: livecarrier.FamilyKurdTLS13TCP, LoopbackOnly: true,
		EndpointReference: endpointReference, DialTimeoutMs: dialTimeoutMillis,
		MaxFrameBytes: maxFrameBytes, Digest: digest,
	}
}

// SendOne resolves and connects to the exact loopback relay, proves that the
// inner Kurd session is bound to the outer TLS exporter, then sends one
// authenticated application message.
func SendOne(ctx context.Context, registry *loopbackresolver.Registry, plan sessionplan.Plan, config *tls.Config, protected ClientProtector, payload []byte) error {
	if ctx == nil || registry == nil || config == nil || protected == nil || len(payload) == 0 {
		return ErrHarness
	}
	raw, serverName, err := registry.DialContext(ctx, plan)
	if err != nil {
		protected.Abort()
		return ErrHarness
	}
	cfg := config.Clone()
	if cfg.ServerName != "" && cfg.ServerName != serverName {
		_ = raw.Close()
		protected.Abort()
		return ErrHarness
	}
	cfg.ServerName = serverName
	carrier, err := tlstcp.Client(ctx, raw, cfg, plan.Digest, plan.MaxFrameBytes)
	if err != nil {
		protected.Abort()
		return ErrHarness
	}
	defer carrier.Close()
	fail := func() error {
		protected.Abort()
		return ErrHarness
	}
	binding, err := carrier.CarrierBinding()
	if err != nil {
		return fail()
	}
	bindingRecord, err := protected.Seal(bindingSlot, bindingStatement(binding, plan.Digest))
	if err != nil {
		return fail()
	}
	defer clear(bindingRecord)
	if err := carrier.Send(ctx, wirev1.Frame{
		Type: wirev1.TypeProfileBind, PlanDigest: plan.Digest, Payload: bindingRecord,
	}); err != nil {
		return fail()
	}
	ready, err := carrier.Receive(ctx)
	if err != nil || ready.Type != wirev1.TypeEngineReady {
		clear(ready.Payload)
		return fail()
	}
	if err := protected.AcceptAck(ready.Payload); err != nil {
		clear(ready.Payload)
		return fail()
	}
	clear(ready.Payload)

	record, err := protected.Seal(dataSlot, payload)
	if err != nil {
		return fail()
	}
	defer clear(record)
	if err := carrier.Send(ctx, wirev1.Frame{
		Type: wirev1.TypeReliableData, StreamID: uint32(dataSlot), PlanDigest: plan.Digest, Payload: record,
	}); err != nil {
		return fail()
	}
	ack, err := carrier.Receive(ctx)
	if err != nil || ack.Type != wirev1.TypeReliableData || ack.StreamID != uint32(dataSlot) {
		clear(ack.Payload)
		return fail()
	}
	if err := protected.AcceptAck(ack.Payload); err != nil {
		clear(ack.Payload)
		return fail()
	}
	clear(ack.Payload)
	return nil
}

// ServeOne accepts one already-owned TCP connection and one bounded
// application message. Sink failure terminally aborts the Kurd session and no
// acknowledgement is emitted.
func ServeOne(ctx context.Context, raw net.Conn, plan sessionplan.Plan, config *tls.Config, protected RelayProtector, sink Sink) error {
	if ctx == nil || raw == nil || config == nil || protected == nil || sink == nil {
		return ErrHarness
	}
	carrier, err := tlstcp.Server(ctx, raw, config, plan.Digest, plan.MaxFrameBytes)
	if err != nil {
		protected.Abort()
		return ErrHarness
	}
	defer carrier.Close()
	fail := func() error {
		protected.Abort()
		return ErrHarness
	}
	binding, err := carrier.CarrierBinding()
	if err != nil {
		return fail()
	}
	bindFrame, err := carrier.Receive(ctx)
	if err != nil || bindFrame.Type != wirev1.TypeProfileBind || bindFrame.StreamID != 0 {
		clear(bindFrame.Payload)
		return fail()
	}
	statement, bindingDelivery, err := protected.Open(bindFrame.Payload)
	clear(bindFrame.Payload)
	if err != nil || !bytes.Equal(statement, bindingStatement(binding, plan.Digest)) {
		clear(statement)
		if bindingDelivery != nil {
			bindingDelivery.Reject()
		}
		return fail()
	}
	clear(statement)
	readyAck, err := bindingDelivery.Commit()
	if err != nil {
		return fail()
	}
	if err := carrier.Send(ctx, wirev1.Frame{
		Type: wirev1.TypeEngineReady, PlanDigest: plan.Digest, Payload: readyAck,
	}); err != nil {
		clear(readyAck)
		return fail()
	}
	clear(readyAck)

	dataFrame, err := carrier.Receive(ctx)
	if err != nil || dataFrame.Type != wirev1.TypeReliableData || dataFrame.StreamID != uint32(dataSlot) {
		clear(dataFrame.Payload)
		return fail()
	}
	payload, delivery, err := protected.Open(dataFrame.Payload)
	clear(dataFrame.Payload)
	if err != nil {
		clear(payload)
		return fail()
	}
	if err := sink.Deliver(ctx, payload); err != nil {
		clear(payload)
		delivery.Reject()
		return fail()
	}
	clear(payload)
	acknowledgement, err := delivery.Commit()
	if err != nil {
		return fail()
	}
	if err := carrier.Send(ctx, wirev1.Frame{
		Type: wirev1.TypeReliableData, StreamID: uint32(dataSlot), PlanDigest: plan.Digest, Payload: acknowledgement,
	}); err != nil {
		clear(acknowledgement)
		return fail()
	}
	clear(acknowledgement)
	return nil
}

func bindingStatement(binding, digest [32]byte) []byte {
	result := make([]byte, 72)
	copy(result[:8], []byte("KRDBND01"))
	copy(result[8:40], binding[:])
	copy(result[40:72], digest[:])
	return result
}
