// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"context"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/transport/tlstcp"
	"time"
)

// This closed choice comes only from strict package constructors, never from a
// caller-supplied policy snapshot or a configurable parser flag.
type packetPumpKindV1 uint8

const (
	mixedPacketPumpV1 packetPumpKindV1 = iota + 1
	rawPacketPumpV2
)

func (k packetPumpKindV1) admitsV1(p runtimepolicy.PolicyV2) bool {
	switch k {
	case mixedPacketPumpV1:
		return p.SchemaVersion == runtimepolicy.SchemaVersionV3 && p.Services != nil
	case rawPacketPumpV2:
		return p.SchemaVersion == runtimepolicy.SchemaVersionV2 && p.Services == nil
	default:
		return false
	}
}

// RawPacketPumpV2 is a narrow view of the same bounded owner, not a second
// lifetime. Its separately reserved pointer holder exposes no stream/probe or
// relay ingress and cannot be converted to the mixed public pump type.
type RawPacketPumpV2 struct{ pump *ServicePumpV1 }

func NewClientRawPacketPumpV2(result *auth.ProcessHandshakeResultV1, plan sessionplan.PlanV2, config ServicePumpConfigV1) (*RawPacketPumpV2, error) {
	p, e := newPacketPumpPreparedV1(result, plan, config, true, nil, nil, rawPacketPumpV2)
	if e != nil {
		return nil, e
	}
	return &RawPacketPumpV2{pump: p}, nil
}
func PrepareProductionClientRawPacketV2(plan sessionplan.PlanV2, n ProductionClientNarrowingV1, a ProductionClientAvailableV1, now time.Time, generation uint64) (*ProductionClientRecipeV1, error) {
	return prepareProductionClientV1(plan, n, a, now, generation, rawPacketPumpV2)
}
func NewProductionClientRawPacketPumpV2(ctx context.Context, result *auth.ProcessHandshakeResultV1, installed *ProductionClientInstallationV1, carrier *tlstcp.Conn, authority ProductionClientAuthorityV1, preparation ProductionClientAttachmentPreparationV1) (*RawPacketPumpV2, error) {
	p, e := newProductionClientPumpV1(ctx, result, installed, carrier, authority, preparation, rawPacketPumpV2)
	if e != nil {
		return nil, e
	}
	return &RawPacketPumpV2{pump: p}, nil
}
func (p *RawPacketPumpV2) BindV1(ctx context.Context, exporter [32]byte) error {
	if p == nil || p.pump == nil {
		return ServiceInvalidRequestV1
	}
	return p.pump.BindV1(ctx, exporter)
}
func (p *RawPacketPumpV2) Run(ctx context.Context) error {
	if p == nil || p.pump == nil {
		return ServiceInvalidRequestV1
	}
	return p.pump.Run(ctx)
}
func (p *RawPacketPumpV2) RunWithPublicationV1(ctx context.Context, ready func(*ServiceRunPublicationV1) error) error {
	if p == nil || p.pump == nil {
		return ServiceInvalidRequestV1
	}
	return p.pump.RunWithPublicationV1(ctx, ready)
}
func (p *RawPacketPumpV2) Close() error {
	if p == nil || p.pump == nil {
		return nil
	}
	return p.pump.Close()
}
func (p *RawPacketPumpV2) Done() <-chan struct{} {
	if p == nil || p.pump == nil {
		return nil
	}
	return p.pump.Done()
}
func (p *RawPacketPumpV2) CancelWithReason(reason error) {
	if p != nil {
		p.pump.CancelWithReason(reason)
	}
}
func (p *RawPacketPumpV2) BoundsV1() ServicePumpBoundsV1 {
	if p == nil || p.pump == nil {
		return ServicePumpBoundsV1{}
	}
	return p.pump.BoundsV1()
}
