// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"time"

	runtimeengine "kurdistan/internal/runtime"
)

// The parent fence never calls an authority producer or performs cancellation.
// Every caller owns an admitted use, including a delivery retained until ack.
func (v *productionSessionV1) liveLockedV1(use productionUseV1) int32 {
	p := v.parent
	if p.state != productionParentOpenV1 {
		return p.terminalOperationStatusLockedV1()
	}
	if !v.ready || v.quiescing || use.parent != p || use.attempt != p.attempt {
		return 3
	}
	r := p.uses[use.index]
	if !r.live || r.serial != use.serial {
		return 3
	}
	if !time.Now().Before(p.admission.monotonicDeadline) {
		return 12
	}
	return 0
}

func (v *productionSessionV1) beginIOV1(index uint16, owned uint64) (productionUseV1, context.Context, int32) {
	return v.beginIOOutputV1(index, owned, ProductionOutputInvocationV1{}, false)
}
func (v *productionSessionV1) beginIOOutputV1(index uint16, owned uint64, inv ProductionOutputInvocationV1, laneBound bool) (productionUseV1, context.Context, int32) {
	p := v.parent
	use, s := p.beginUseOutputV1(index, productionBudgetChargeV1{owned: owned + 1024}, inv, laneBound)
	if s != 0 {
		return use, nil, s
	}
	if s = p.admission.acceptTimeV1(use); s != 0 {
		p.finishUseV1(use)
		return productionUseV1{}, nil, s
	}
	p.mu.Lock()
	s = v.liveLockedV1(use)
	ctx := v.attemptContext
	p.mu.Unlock()
	if s != 0 {
		p.finishUseV1(use)
		return productionUseV1{}, nil, s
	}
	return use, ctx, 0
}

func SubmitProductionPacketV1(r *HandleRegistry, h Handle, input []byte) int32 {
	return SubmitProductionPacketV1Scoped(r, h, input, ProductionOutputInvocationV1{})
}
func SubmitProductionPacketV1Scoped(r *HandleRegistry, h Handle, input []byte, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return s
	}
	if v.projection.effectiveMode == 3 {
		return 1
	}
	if len(input) == 0 {
		return 2
	}
	if len(input) > int(v.projection.packetMax) {
		return 4
	}
	use, ctx, s := v.beginIOOutputV1(2, 0, inv, false)
	if s != 0 {
		return s
	}
	defer v.parent.finishUseV1(use)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := v.port.Submit(ctx, input)
	v.parent.mu.Lock()
	s = v.liveLockedV1(use)
	if s == 0 && err == nil {
		deadline, _ := ctx.Deadline()
		s = v.parent.outputPrepareLockedV1(inv, use.attempt, 0, 0, productionOutputDeadlineV1(deadline, v.parent.admission.monotonicDeadline), false)
	}
	v.parent.mu.Unlock()
	if s != 0 {
		return s
	}
	return productionOperationStatusV1(err)
}

func ReceiveProductionPacketV1(r *HandleRegistry, h Handle, out []byte) (int, uint64, int32) {
	return ReceiveProductionPacketV1Scoped(r, h, out, ProductionOutputInvocationV1{})
}
func ReceiveProductionPacketV1Scoped(r *HandleRegistry, h Handle, out []byte, inv ProductionOutputInvocationV1) (int, uint64, int32) {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return 0, 0, s
	}
	if v.projection.effectiveMode == 3 {
		return 0, 0, 1
	}
	if len(out) == 0 {
		return 0, 0, 4
	}
	size := min(len(out), int(v.projection.packetMax))
	use, ctx, s := v.beginIOOutputV1(3, uint64(size), inv, false)
	if s != 0 {
		return 0, 0, s
	}
	retained := false
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer func() {
		cancel()
		if !retained {
			v.parent.finishUseV1(use)
		} else {
			v.parent.mu.Lock()
			v.packet.invoking = false
			v.parent.mu.Unlock()
			v.signalV1()
		}
	}()
	scratch := make([]byte, size)
	defer clear(scratch)
	underlying, n, err := v.port.Receive(ctx, scratch)
	if err != nil {
		v.parent.mu.Lock()
		s = v.liveLockedV1(use)
		v.parent.mu.Unlock()
		if s != 0 {
			return 0, 0, s
		}
		return 0, 0, productionOperationStatusV1(err)
	}
	p := v.parent
	p.mu.Lock()
	s = v.liveLockedV1(use)
	if s == 0 && ctx.Err() != nil {
		s = productionOperationStatusV1(ctx.Err())
	}
	var token uint64
	if s == 0 {
		token, s = v.freshTokenLockedV1()
	}
	if s == 0 {
		deadline := time.Now().Add(30 * time.Second)
		if p.admission.monotonicDeadline.Before(deadline) {
			deadline = p.admission.monotonicDeadline
		}
		v.packet = productionDeliveryV1{invoking: true, token: token, underlying: uint64(underlying), attempt: use.attempt, length: n, deadline: deadline, use: use}
		retained = true
		s = p.outputPrepareLockedV1(inv, use.attempt, 0, token, deadline, false)
		if s == 0 {
			copy(out, scratch[:n])
		}
	}
	p.mu.Unlock()
	if s != 0 {
		v.terminalV1(s)
		return 0, 0, s
	}
	return n, token, 0
}

func ConfirmProductionPacketV1(r *HandleRegistry, h Handle, token uint64, length uint32) int32 {
	return ConfirmProductionPacketV1Scoped(r, h, token, length, ProductionOutputInvocationV1{})
}
func ConfirmProductionPacketV1Scoped(r *HandleRegistry, h Handle, token uint64, length uint32, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return s
	}
	p := v.parent
	p.mu.Lock()
	if s = p.outputLaneLockedV1(inv, 203); s != 0 {
		p.mu.Unlock()
		return s
	}
	if p.state != productionParentOpenV1 {
		s = p.terminalOperationStatusLockedV1()
		p.mu.Unlock()
		return s
	}
	d := v.packet
	if d.invoking || d.use.parent == nil || token == 0 || token != d.token || int(length) != d.length || !time.Now().Before(d.deadline) {
		p.mu.Unlock()
		v.terminalV1(3)
		return 3
	}
	s = v.liveLockedV1(d.use)
	if s == 0 {
		s = productionOperationStatusV1(v.port.Acknowledge(v.attemptContext, runtimeengine.PacketDeliveryTokenV1(d.underlying), d.length, nil))
	}
	if s == 0 {
		v.packet = productionDeliveryV1{}
	}
	acknowledged := s == 0
	if acknowledged {
		s = p.outputPrepareLockedV1(inv, d.attempt, 0, 0, d.deadline, false)
	}
	p.mu.Unlock()
	if acknowledged {
		actual := p.finishUseV1(d.use)
		p.outputRetiredDeliveryV1(0, d, actual)
		if actual != 0 && !inv.legacyV1() {
			return actual
		}
		return s
	}
	if s != 0 {
		v.terminalV1(s)
		return s
	}
	p.finishUseV1(d.use)
	return 0
}

func RejectProductionPacketV1(r *HandleRegistry, h Handle, token uint64) int32 {
	return RejectProductionPacketV1Scoped(r, h, token, ProductionOutputInvocationV1{})
}
func RejectProductionPacketV1Scoped(r *HandleRegistry, h Handle, token uint64, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return s
	}
	v.parent.mu.Lock()
	if s = v.parent.outputLaneLockedV1(inv, 203); s != 0 {
		v.parent.mu.Unlock()
		return s
	}
	if v.parent.state != productionParentOpenV1 {
		s = v.parent.terminalOperationStatusLockedV1()
		v.parent.mu.Unlock()
		return s
	}
	valid := token != 0 && v.packet.token == token
	v.parent.mu.Unlock()
	v.terminalV1(3)
	if !valid {
		return 3
	}
	return 7
}
