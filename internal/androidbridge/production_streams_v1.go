// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	runtimeengine "kurdistan/internal/runtime"
	"math"
	"time"
)

func OpenProductionStreamV1(r *HandleRegistry, h Handle, request []byte) (uint64, int32) {
	return OpenProductionStreamV1Scoped(r, h, request, ProductionOutputInvocationV1{})
}
func OpenProductionStreamV1Scoped(r *HandleRegistry, h Handle, request []byte, inv ProductionOutputInvocationV1) (uint64, int32) {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return 0, s
	}
	if v.projection.effectiveMode == 1 || v.projection.effectiveStreamMax == 0 {
		return 0, 1
	}
	if len(request) < 7 || len(request) > 259 || request[0] != 1 {
		return 0, 2
	}
	length := int(binary.BigEndian.Uint16(request[2:4]))
	if length == 0 || len(request) != length+6 {
		return 0, 2
	}
	p := v.parent
	for i := 0; i < int(v.projection.effectiveStreamMax); i++ {
		p.mu.Lock()
		row := v.streams[i]
		busy := row.opening
		for j := 0; j < 3; j++ {
			busy = busy || p.uses[6+3*i+j].live
		}
		if !busy {
			v.streams[i].opening = true
		}
		p.mu.Unlock()
		if busy {
			continue
		}
		// Root-approved query-only native admission protects the old row while
		// StreamRetired calls runtime authority outside p.mu. No output lane,
		// child identity, request copy or OpenStream work exists yet.
		use, ctx, s := v.beginIOOutputV1(uint16(6+3*i), 259, inv, true)
		if s != 0 {
			p.mu.Lock()
			v.streams[i].opening = false
			p.mu.Unlock()
			return 0, s
		}
		if row.child != 0 {
			retired, err := v.pump.StreamRetiredV1(row.wire)
			if err != nil || !retired {
				p.mu.Lock()
				v.streams[i].opening = false
				p.mu.Unlock()
				p.finishUseV1(use)
				if err != nil {
					return 0, productionOperationStatusV1(err)
				}
				continue
			}
		}
		child, s, retry := v.selectStreamOutputRowV1(i, row, use, inv)
		if s != 0 {
			if retry {
				continue
			}
			return 0, s
		}
		// The accepted runtime admission owns canonical destination validation.
		address := append([]byte(nil), request[4:4+length]...)
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		wire, err := v.pump.OpenStream(ctx, runtimeengine.ProxyRequestV1{Kind: request[1], Address: address, Port: binary.BigEndian.Uint16(request[4+length:])})
		published, status := v.finishStreamOpenOutputV1(i, use, child, wire, err, ctx, inv)
		cancel()
		clear(address)
		p.finishUseV1(use)
		return published, status
	}
	return 0, 5
}

func (v *productionSessionV1) finishStreamOpenV1(i int, use productionUseV1, child uint64, wire uint32, err error, ctx context.Context) (uint64, int32) {
	return v.finishStreamOpenOutputV1(i, use, child, wire, err, ctx, ProductionOutputInvocationV1{})
}
func (v *productionSessionV1) finishStreamOpenOutputV1(i int, use productionUseV1, child uint64, wire uint32, err error, ctx context.Context, inv ProductionOutputInvocationV1) (uint64, int32) {
	acquired := err == nil && wire != 0
	if err == nil {
		err = ctx.Err()
	}
	p := v.parent
	p.mu.Lock()
	s := v.liveLockedV1(use)
	if s == 0 && err == nil && acquired {
		deadline, _ := ctx.Deadline()
		s = p.outputPrepareLockedV1(inv, use.attempt, child, 0, productionOutputDeadlineV1(deadline, p.admission.monotonicDeadline), false)
	}
	publish := err == nil && s == 0
	if acquired {
		v.streams[i].wire = wire
		v.streams[i].opening = !publish
	} else {
		v.streams[i] = productionStreamV1{}
	}
	p.mu.Unlock()
	if acquired && !publish {
		// OpenStream success transfers a real connection. A late local refusal
		// must cancel that exact wire ID, then retain its runtime tombstone row.
		cancelErr := v.pump.CancelStream(wire)
		p.mu.Lock()
		v.streams[i].opening, v.streams[i].closed = false, true
		p.mu.Unlock()
		if cancelErr != nil {
			v.terminalV1(productionOperationStatusV1(cancelErr))
		}
	}
	if s != 0 {
		return 0, s
	}
	if err != nil {
		return 0, productionOperationStatusV1(err)
	}
	return child, 0
}

func (v *productionSessionV1) streamUseV1(child uint64, operation uint16) (int, productionUseV1, context.Context, int32) {
	return v.streamUseOutputV1(child, operation, ProductionOutputInvocationV1{})
}
func (v *productionSessionV1) streamUseOutputV1(child uint64, operation uint16, inv ProductionOutputInvocationV1) (int, productionUseV1, context.Context, int32) {
	p := v.parent
	p.mu.Lock()
	index := -1
	for i := range v.streams {
		row := v.streams[i]
		if child != 0 && row.child == child && row.attempt == p.attempt && !row.opening {
			index = i
			break
		}
	}
	p.mu.Unlock()
	if index < 0 {
		return 0, productionUseV1{}, nil, 3
	}
	use, ctx, s := v.beginIOOutputV1(uint16(6+3*index)+operation, 0, inv, false)
	if s != 0 {
		return 0, use, nil, s
	}
	p.mu.Lock()
	row := v.streams[index]
	valid := row.child == child && row.attempt == use.attempt && !row.opening
	p.mu.Unlock()
	if !valid {
		p.finishUseV1(use)
		return 0, productionUseV1{}, nil, 3
	}
	return index, use, ctx, 0
}

func SendProductionStreamV1(r *HandleRegistry, h Handle, child uint64, input []byte) int32 {
	return SendProductionStreamV1Scoped(r, h, child, input, ProductionOutputInvocationV1{})
}
func SendProductionStreamV1Scoped(r *HandleRegistry, h Handle, child uint64, input []byte, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return s
	}
	if len(input) == 0 {
		return 2
	}
	if len(input) > 16384 {
		return 4
	}
	i, use, ctx, s := v.streamUseOutputV1(child, 1, inv)
	if s != 0 {
		return s
	}
	defer v.parent.finishUseV1(use)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	v.parent.mu.Lock()
	row := v.streams[i]
	v.parent.mu.Unlock()
	if row.closed || row.localFIN {
		return 3
	}
	n, err := v.pump.WriteStream(ctx, row.wire, input)
	v.parent.mu.Lock()
	s = v.liveLockedV1(use)
	v.parent.mu.Unlock()
	if s != 0 {
		return s
	}
	if err != nil {
		return productionOperationStatusV1(err)
	}
	if n != len(input) {
		v.terminalV1(18)
		return 18
	}
	return v.outputStreamScalarV1(inv, use, child, ctx)
}

func ReceiveProductionStreamV1(r *HandleRegistry, h Handle, child uint64, out []byte) (int, uint64, int32) {
	return ReceiveProductionStreamV1Scoped(r, h, child, out, ProductionOutputInvocationV1{})
}
func ReceiveProductionStreamV1Scoped(r *HandleRegistry, h Handle, child uint64, out []byte, inv ProductionOutputInvocationV1) (int, uint64, int32) {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return 0, 0, s
	}
	if len(out) == 0 {
		return 0, 0, 4
	}
	i, use, ctx, s := v.streamUseOutputV1(child, 2, inv)
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
			v.streams[i].delivery.invoking = false
			v.parent.mu.Unlock()
			v.signalV1()
		}
	}()
	size := min(len(out), int(v.projection.streamChunkMax))
	// Stage ownership is additional to the retained delivery-use metadata.
	ticket, s := v.parent.budget.reserveV1(productionBudgetChargeV1{owned: uint64(size)})
	if s != 0 {
		return 0, 0, s
	}
	defer v.parent.budget.releaseV1(ticket)
	scratch := make([]byte, size)
	defer clear(scratch)
	v.parent.mu.Lock()
	row := v.streams[i]
	v.parent.mu.Unlock()
	if row.closed {
		return 0, 0, 3
	}
	underlying, n, err := v.pump.ReceiveStream(ctx, row.wire, scratch)
	p := v.parent
	p.mu.Lock()
	s = v.liveLockedV1(use)
	if s == 0 && ctx.Err() != nil {
		s = productionOperationStatusV1(ctx.Err())
	}
	if s == 0 && err == io.EOF {
		deadline, _ := ctx.Deadline()
		s = p.outputPrepareLockedV1(inv, use.attempt, child, 0, productionOutputDeadlineV1(deadline, p.admission.monotonicDeadline), false)
		p.mu.Unlock()
		if s != 0 {
			return 0, 0, s
		}
		return 0, 0, 19
	}
	var token uint64
	if s == 0 && err == nil {
		token, s = v.freshTokenLockedV1()
	}
	if s == 0 && err == nil {
		deadline := time.Now().Add(30 * time.Second)
		if p.admission.monotonicDeadline.Before(deadline) {
			deadline = p.admission.monotonicDeadline
		}
		v.streams[i].delivery = productionDeliveryV1{invoking: true, token: token, underlying: underlying, attempt: use.attempt, length: n, deadline: deadline, use: use}
		retained = true
		s = p.outputPrepareLockedV1(inv, use.attempt, child, token, deadline, false)
		if s == 0 {
			copy(out, scratch[:n])
		}
	}
	p.mu.Unlock()
	if s != 0 {
		if retained || (!inv.legacyV1() && err == nil && underlying != 0) {
			v.terminalV1(s)
		}
		return 0, 0, s
	}
	if err != nil {
		return 0, 0, productionOperationStatusV1(err)
	}
	return n, token, 0
}

func ConfirmProductionStreamV1(r *HandleRegistry, h Handle, child, token uint64, length uint32) int32 {
	return ConfirmProductionStreamV1Scoped(r, h, child, token, length, ProductionOutputInvocationV1{})
}
func ConfirmProductionStreamV1Scoped(r *HandleRegistry, h Handle, child, token uint64, length uint32, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return s
	}
	p := v.parent
	p.mu.Lock()
	index := -1
	if p.state != productionParentOpenV1 {
		s = p.terminalOperationStatusLockedV1()
		p.mu.Unlock()
		return s
	}
	var row productionStreamV1
	for i := range v.streams {
		if child != 0 && v.streams[i].child == child {
			index = i
			row = v.streams[i]
			break
		}
	}
	d := row.delivery
	if index >= 0 {
		if s = p.outputLaneLockedV1(inv, uint16(204+index)); s != 0 {
			p.mu.Unlock()
			return s
		}
	}
	if index < 0 || d.invoking || d.use.parent == nil || token == 0 || d.token != token || int(length) != d.length || !time.Now().Before(d.deadline) {
		p.mu.Unlock()
		v.terminalV1(3)
		return 3
	}
	pump := v.pump
	v.streams[index].delivery.invoking = true
	p.mu.Unlock()
	acknowledged := false
	defer func() {
		p.mu.Lock()
		if acknowledged || inv.legacyV1() {
			v.streams[index].delivery = productionDeliveryV1{}
		} else {
			v.streams[index].delivery.invoking = false
		}
		p.mu.Unlock()
		if acknowledged || inv.legacyV1() {
			actual := p.finishUseV1(d.use)
			if acknowledged {
				p.outputRetiredDeliveryV1(child, d, actual)
			}
		} else {
			v.signalV1()
		}
	}()
	// Runtime admits and counts first. Its commit takes only pump.mu and never
	// cancels/closes while the native parent fence is held.
	err := pump.ConfirmStreamDeliveryFencedV1(row.wire, d.underlying, d.length, func(commit func() error) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		s = v.liveLockedV1(d.use)
		if s != 0 {
			return runtimeengine.ServiceCancelledV1
		}
		if v.streams[index].child != child || v.streams[index].delivery.token != token {
			s = 3
			return runtimeengine.ErrAuthenticatedFrameState
		}
		if err := commit(); err != nil {
			return err
		}
		s = p.outputPrepareLockedV1(inv, d.attempt, child, 0, d.deadline, false)
		return nil
	})
	if err != nil {
		if s == 0 {
			s = productionOperationStatusV1(err)
		}
		v.terminalV1(s)
		return s
	}
	acknowledged = true
	return s
}

func RejectProductionStreamV1(r *HandleRegistry, h Handle, child, token uint64) int32 {
	return RejectProductionStreamV1Scoped(r, h, child, token, ProductionOutputInvocationV1{})
}
func RejectProductionStreamV1Scoped(r *HandleRegistry, h Handle, child, token uint64, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return s
	}
	p := v.parent
	p.mu.Lock()
	valid := false
	if p.state != productionParentOpenV1 {
		s = p.terminalOperationStatusLockedV1()
		p.mu.Unlock()
		return s
	}
	for i := range v.streams {
		row := v.streams[i]
		if child != 0 && row.child == child {
			if s = p.outputLaneLockedV1(inv, uint16(204+i)); s != 0 {
				p.mu.Unlock()
				return s
			}
			valid = token != 0 && row.delivery.token == token
			break
		}
	}
	p.mu.Unlock()
	v.terminalV1(3)
	if !valid {
		return 3
	}
	return 7
}

func HalfCloseProductionStreamV1(r *HandleRegistry, h Handle, child uint64) int32 {
	return HalfCloseProductionStreamV1Scoped(r, h, child, ProductionOutputInvocationV1{})
}
func HalfCloseProductionStreamV1Scoped(r *HandleRegistry, h Handle, child uint64, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return s
	}
	i, use, ctx, s := v.streamUseOutputV1(child, 1, inv)
	if s != 0 {
		return s
	}
	defer v.parent.finishUseV1(use)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p := v.parent
	p.mu.Lock()
	row := v.streams[i]
	p.mu.Unlock()
	if row.closed {
		return 3
	}
	if row.localFIN {
		return v.outputStreamScalarV1(inv, use, child, ctx)
	}
	err := v.pump.CloseWrite(ctx, row.wire)
	p.mu.Lock()
	s = v.liveLockedV1(use)
	if s == 0 && err == nil {
		v.streams[i].localFIN = true
	}
	p.mu.Unlock()
	if s != 0 {
		return s
	}
	if err != nil {
		return productionOperationStatusV1(err)
	}
	return v.outputStreamScalarV1(inv, use, child, ctx)
}

func CancelProductionStreamV1(r *HandleRegistry, h Handle, child uint64) int32 {
	return CancelProductionStreamV1Scoped(r, h, child, ProductionOutputInvocationV1{})
}
func CancelProductionStreamV1Scoped(r *HandleRegistry, h Handle, child uint64, inv ProductionOutputInvocationV1) int32 {
	return cancelProductionStreamOutputV1(r, h, child, inv)
}
func cancelProductionStreamOutputV1(r *HandleRegistry, h Handle, child uint64, inv ProductionOutputInvocationV1) int32 {
	v, s := productionSessionOutputLookupV1(r, h, inv)
	if s != 0 {
		return s
	}
	i, use, ctx, s := v.streamUseOutputV1(child, 0, inv)
	if s != 0 {
		return s
	}
	defer v.parent.finishUseV1(use)
	p := v.parent
	p.mu.Lock()
	row := v.streams[i]
	p.mu.Unlock()
	if row.delivery.token != 0 {
		v.terminalV1(3)
		return 7
	}
	if row.closed {
		return v.outputStreamScalarV1(inv, use, child, ctx)
	}
	err := v.pump.CancelStream(row.wire)
	if errors.Is(err, runtimeengine.ErrAuthenticatedFrameState) {
		// Both FINs can retire the runtime row before native close. Only its
		// existing counted retirement authority may prove that exact wire ID.
		retired, queryErr := v.pump.StreamRetiredV1(row.wire)
		if queryErr != nil {
			err = queryErr
		} else if retired {
			err = nil
		}
	}
	return v.finishStreamCloseOutputV1(i, use, ctx, inv, child, row, err)
}

// Runtime cleanup/query happens outside the parent fence. This final native
// check cannot carry an old row or use across replacement into publication.
func (v *productionSessionV1) finishStreamCloseOutputV1(i int, use productionUseV1, ctx context.Context, inv ProductionOutputInvocationV1, child uint64, row productionStreamV1, err error) int32 {
	p := v.parent
	p.mu.Lock()
	s := v.liveLockedV1(use)
	if s == 0 && ctx.Err() != nil {
		s = productionOperationStatusV1(ctx.Err())
	}
	current := v.streams[i]
	if s == 0 && (current.child != child || current.attempt != row.attempt || current.wire != row.wire || current.opening || current.delivery.token != 0) {
		s = 3
	}
	if s == 0 && err == nil {
		v.streams[i].closed = true
	}
	p.mu.Unlock()
	if s != 0 {
		return s
	}
	if err != nil {
		return productionOperationStatusV1(err)
	}
	return v.outputStreamScalarV1(inv, use, child, ctx)
}
func CloseProductionStreamV1(r *HandleRegistry, h Handle, child uint64) int32 {
	return CloseProductionStreamV1Scoped(r, h, child, ProductionOutputInvocationV1{})
}
func CloseProductionStreamV1Scoped(r *HandleRegistry, h Handle, child uint64, inv ProductionOutputInvocationV1) int32 {
	return cancelProductionStreamOutputV1(r, h, child, inv)
}

// selectStreamOutputRowV1 is the final native row fence after an actual
// retirement query. It admits no request copy or runtime OpenStream work.
// Retry is permitted only before lane admission; native use cleanup cannot
// release the outer invocation's lane after admission succeeds.
func (v *productionSessionV1) selectStreamOutputRowV1(i int, row productionStreamV1, use productionUseV1, inv ProductionOutputInvocationV1) (uint64, int32, bool) {
	p := v.parent
	p.mu.Lock()
	s := v.liveLockedV1(use)
	if s == 0 && (v.streams[i].child != row.child || v.streams[i].attempt != row.attempt) {
		s = 3
	}
	if s == 0 {
		s = p.outputLaneLockedV1(inv, uint16(6+3*i))
	}
	if s != 0 {
		v.streams[i].opening = false
		p.mu.Unlock()
		p.finishUseV1(use)
		return 0, s, s == 5
	}
	if row.child != 0 && p.output != nil {
		p.output.ResourceRetiredV1(p.ticket.epoch, ProductionOutputStreamV1, p.outputHandle, row.attempt, row.child, 0, 0)
	}
	if v.nextChild == math.MaxUint64 {
		v.streams[i].opening = false
		p.mu.Unlock()
		p.finishUseV1(use)
		return 0, 5, false
	}
	child, s := nextProductionOpaqueIDV1(&productionOpaqueIDsV1)
	if s != 0 {
		v.streams[i].opening = false
		p.mu.Unlock()
		p.finishUseV1(use)
		return 0, s, false
	}
	v.nextChild = child
	v.streams[i] = productionStreamV1{child: child, attempt: use.attempt, opening: true}
	p.mu.Unlock()
	return child, 0, false
}
