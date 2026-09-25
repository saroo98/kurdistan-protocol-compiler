// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"context"
	"encoding/binary"
	"math"
	"net/netip"
	"time"
)

func (p *ServicePumpV1) admitProbeV1(r ProbeRequestV1) (ProbeAdmissionV1, error) {
	if p.cfg.ProbeLimit == 0 {
		return ProbeAdmissionV1{}, ServiceNotAdmittedV1
	}
	a, e := p.admission.AdmitProbe(r, ProbeActiveRelayV1, p.cfg.ProbeLimit)
	if e != nil {
		return a, e
	}
	address, ok := netip.AddrFromSlice(a.target.Address)
	if !ok || !p.familyV1(address) {
		return ProbeAdmissionV1{}, ServiceDestinationDeniedV1
	}
	return a, nil
}
func (p *ServicePumpV1) StartProbe(ctx context.Context, r ProbeRequestV1) (uint64, error) {
	if e := p.beginUseV1(true); e != nil {
		return 0, e
	}
	defer p.endUseV1()
	if !p.client {
		return 0, ServiceNotAdmittedV1
	}
	a, e := p.admitProbeV1(r)
	if e != nil {
		return 0, e
	}
	p.mu.Lock()
	i := -1
	for j := range p.probes {
		if p.probes[j].state == 0 {
			i = j
			break
		}
	}
	if i < 0 || p.nextHandle == math.MaxUint64 || p.nextID == math.MaxUint32 {
		p.mu.Unlock()
		return 0, ServiceResourceLimitV1
	}
	deadline := minServiceTimeV1(p.deadline, p.lastNow.Add(time.Duration(r.TotalTimeoutMillis)*time.Millisecond))
	p.probes[i].state = 5
	qi, e := p.reserveV1(ctx, deadline, false)
	if e != nil {
		p.probes[i] = serviceProbeSlotV1{}
		p.mu.Unlock()
		return 0, e
	}
	if e = p.reserveUsesLockedV1(1); e != nil {
		p.probes[i] = serviceProbeSlotV1{}
		p.queue[qi].state = 4
		p.notifyLockedV1()
		p.mu.Unlock()
		return 0, e
	}
	if e = p.cfg.ProbeRates.TryStart(p.cfg.ProbeScope, a, p.lastNow); e != nil {
		p.users-- // The pending worker was never launched; this public use remains.
		p.probes[i] = serviceProbeSlotV1{}
		p.queue[qi].state = 4
		p.notifyLockedV1()
		p.mu.Unlock()
		if e == ErrProbeClockRegressionV1 {
			p.CancelWithReason(e)
		}
		return 0, e
	}
	p.nextHandle++
	handle := p.nextHandle
	p.nextID++
	child, cancel := context.WithCancel(context.Background())
	g := &p.probes[i]
	*g = serviceProbeSlotV1{handle: handle, id: p.nextID, state: 1, admission: a, deadline: deadline, cancel: cancel, worker: true}
	p.fillProbeQueueLockedV1(qi, i)
	p.mu.Unlock()
	go p.workerV1(func() error { return p.probeGroupV1(i, handle, child) })
	return handle, nil
}
func (p *ServicePumpV1) fillProbeQueueLockedV1(qi, i int) {
	g := &p.probes[i]
	var body [5]byte
	binary.BigEndian.PutUint16(body[:2], g.admission.request.TargetID)
	body[2] = g.admission.request.Method
	binary.BigEndian.PutUint16(body[3:], g.admission.request.AttemptTimeoutMillis)
	var raw [13]byte
	n, _ := p.codec.Encode(raw[:], ServiceRecordViewV1{Opcode: ServiceProbeV1, ID: g.id, Body: body[:]}, p.directionV1(), 0)
	p.queueCopyLockedV1(qi, raw[:n], g.id, ServiceProbeV1)
	p.queue[qi].probe = i
}
func (p *ServicePumpV1) probeGroupV1(i int, handle uint64, ctx context.Context) error {
	defer func() {
		p.mu.Lock()
		g := &p.probes[i]
		var cancel context.CancelFunc
		if g.handle == handle {
			cancel = g.cancel
		}
		p.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		p.mu.Lock()
		if g.handle == handle {
			g.cancel = nil
			g.worker = false
			retireProbeAdmissionV1(g)
			p.notifyLockedV1()
		}
		p.mu.Unlock()
	}()
	for {
		p.mu.Lock()
		g := &p.probes[i]
		for g.state == 1 && !g.hasResult {
			deadline := g.deadline
			if !g.attemptDeadline.IsZero() {
				deadline = minServiceTimeV1(deadline, g.attemptDeadline)
			}
			if e := p.waitLockedV1(ctx, deadline); e != nil {
				p.mu.Unlock()
				if p.ctx.Err() == nil {
					return p.finishProbeV1(i, handle, e)
				}
				return nil
			}
		}
		if g.handle != handle || g.state != 1 || p.terminal {
			p.mu.Unlock()
			return nil
		}
		result := g.result
		g.hasResult = false
		if result != ServiceSuccessV1 && result != ServiceTimeoutV1 && result != ServiceUnreachableV1 {
			p.mu.Unlock()
			return p.finishProbeV1(i, handle, result)
		}
		if g.sampleCount >= int(g.admission.request.Samples) {
			g.aggregate, _ = AggregateProbeSamplesV1(ProbeActiveRelayEndToEndV1, g.samples[:g.sampleCount])
			g.state = 2
			g.id = 0
			p.notifyLockedV1()
			p.mu.Unlock()
			return nil
		}
		a := g.admission
		deadline := g.deadline
		// A locally spaced send can reach the relay too early after variable
		// carrier delay. Space serial samples from the confirmed response instead.
		nextSample := p.lastNow.Add(a.interval)
		if !nextSample.Before(deadline) {
			p.mu.Unlock()
			return p.finishProbeV1(i, handle, ErrProbeRateLimitedV1)
		}
		for g.state == 1 && p.lastNow.Before(nextSample) {
			if e := p.waitLockedV1(ctx, deadline); e != nil {
				p.mu.Unlock()
				return p.finishProbeV1(i, handle, e)
			}
		}
		if g.handle != handle || g.state != 1 || p.terminal {
			p.mu.Unlock()
			return nil
		}
		g.id = 0
		g.sentAt = time.Time{}
		g.sentMono = time.Time{}
		g.attemptDeadline = time.Time{}
		p.mu.Unlock()
		for {
			now, e := p.authorityV1()
			if e != nil {
				return e
			}
			e = p.cfg.ProbeRates.TryStart(p.cfg.ProbeScope, a, now)
			if e == nil {
				break
			}
			if e != ErrProbeRateLimitedV1 {
				return p.finishProbeV1(i, handle, e)
			}
			next, e := p.cfg.ProbeRates.NextSlot(p.cfg.ProbeScope, a, now, deadline)
			if e != nil {
				return p.finishProbeV1(i, handle, e)
			}
			p.mu.Lock()
			g = &p.probes[i]
			for g.state == 1 && p.lastNow.Before(next) {
				if e = p.waitLockedV1(ctx, deadline); e != nil {
					break
				}
			}
			cancelled := g.state != 1
			p.mu.Unlock()
			if cancelled {
				return nil
			}
			if e != nil {
				return p.finishProbeV1(i, handle, e)
			}
		}
		p.mu.Lock()
		g = &p.probes[i]
		if g.state != 1 || g.handle != handle || p.terminal {
			p.mu.Unlock()
			return nil
		}
		if p.nextID == math.MaxUint32 {
			p.mu.Unlock()
			return p.finishProbeV1(i, handle, ServiceResourceLimitV1)
		}
		qi, e := p.reserveV1(ctx, g.deadline, false)
		if e != nil {
			p.mu.Unlock()
			return p.finishProbeV1(i, handle, e)
		}
		// reserveV1 may have dropped mu while the ring was full. finishProbeV1
		// publishes retirement before invoking leaf cancellation, so ctx.Err alone
		// cannot authorize another sample or wire ID after this wait.
		if g.handle != handle || g.state != 1 || p.terminal || p.nextID == math.MaxUint32 {
			exhausted := g.handle == handle && g.state == 1 && !p.terminal && p.nextID == math.MaxUint32
			p.queue[qi].state = 4
			p.notifyLockedV1()
			p.mu.Unlock()
			if exhausted {
				return p.finishProbeV1(i, handle, ServiceResourceLimitV1)
			}
			return nil
		}
		p.nextID++
		g.id = p.nextID
		g.resultSeen = false
		p.fillProbeQueueLockedV1(qi, i)
		p.mu.Unlock()
	}
}
func (p *ServicePumpV1) finishProbeV1(i int, handle uint64, failure error) error {
	p.mu.Lock()
	g := &p.probes[i]
	if g.handle != handle || g.state != 1 {
		p.mu.Unlock()
		return nil
	}
	g.failure = failure
	g.aggregate, _ = AggregateProbeSamplesV1(ProbeActiveRelayEndToEndV1, g.samples[:g.sampleCount])
	g.state = 3
	g.tombstone = minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second))
	id := g.id
	// A terminal peer result already retires that request. Reset only an
	// outstanding request, including cancellation before its result arrives.
	sent := !g.sentAt.IsZero() && !g.resultSeen
	cancel := g.cancel
	retireProbeAdmissionV1(g)
	for j := range p.queue {
		if p.queue[j].id == id && (p.queue[j].state == 1 || p.queue[j].state == 2) {
			p.queue[j].state = 4
		}
	}
	p.notifyLockedV1()
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if sent && id != 0 {
		p.mu.Lock()
		var body [2]byte
		binary.BigEndian.PutUint16(body[:], uint16(ServiceCancelledV1))
		_, e := p.queueControlLockedV1(p.ctx, id, ServiceResetV1, body[:], 0, minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second)))
		p.mu.Unlock()
		return e
	}
	return nil
}
func (p *ServicePumpV1) AwaitProbe(ctx context.Context, handle uint64) (ProbeAggregateV1, error) {
	if e := p.beginUseV1(true); e != nil {
		return ProbeAggregateV1{}, e
	}
	defer p.endUseV1()
	p.mu.Lock()
	i := -1
	for j := range p.probes {
		if handle != 0 && p.probes[j].handle == handle {
			i = j
			break
		}
	}
	if i < 0 || p.probes[i].awaiting || p.probes[i].consumed {
		p.mu.Unlock()
		return ProbeAggregateV1{}, ErrAuthenticatedFrameState
	}
	g := &p.probes[i]
	g.awaiting = true
	defer func() {
		p.mu.Lock()
		if g.handle == handle {
			g.awaiting = false
		}
		p.mu.Unlock()
	}()
	for g.state == 1 {
		if e := p.waitLockedV1(ctx, g.deadline); e != nil {
			p.mu.Unlock()
			p.finishProbeV1(i, handle, e)
			p.mu.Lock()
			if p.terminal {
				a := g.aggregate
				p.mu.Unlock()
				return a, p.reason
			}
		}
	}
	a, e := g.aggregate, g.failure
	g.consumed = true
	if g.state == 2 && !g.worker {
		*g = serviceProbeSlotV1{}
	}
	p.mu.Unlock()
	return a, e
}
func (p *ServicePumpV1) CancelProbe(handle uint64) error {
	if e := p.beginUseV1(true); e != nil {
		return e
	}
	defer p.endUseV1()
	p.mu.Lock()
	i := -1
	for j := range p.probes {
		if handle != 0 && p.probes[j].handle == handle {
			i = j
			break
		}
	}
	p.mu.Unlock()
	if i < 0 {
		return ErrAuthenticatedFrameState
	}
	e := p.finishProbeV1(i, handle, ServiceCancelledV1)
	if e != nil {
		p.CancelWithReason(e)
	}
	return e
}
func (p *ServicePumpV1) acceptProbeV1(view ServiceRecordViewV1) error {
	request := ProbeRequestV1{TargetID: binary.BigEndian.Uint16(view.Body), Method: view.Body[2], AttemptTimeoutMillis: binary.BigEndian.Uint16(view.Body[3:]), TotalTimeoutMillis: binary.BigEndian.Uint16(view.Body[3:]), Samples: 1}
	a, e := p.admitProbeV1(request)
	p.mu.Lock()
	if view.ID <= p.nextID {
		p.mu.Unlock()
		return ErrServiceRecordV1
	}
	i := -1
	for j := range p.probes {
		if p.probes[j].state == 0 || p.probes[j].state == 2 && !p.probes[j].worker {
			i = j
			break
		}
	}
	if e == nil && i < 0 {
		e = ServiceResourceLimitV1
	}
	if e != nil {
		result := ServiceNotAdmittedV1
		if category, ok := e.(ServiceResultV1); ok {
			result = category
		}
		var body [6]byte
		binary.BigEndian.PutUint16(body[:], uint16(result))
		_, e = p.queueControlLockedV1(p.ctx, view.ID, ServiceProbeResultV1, body[:], request.AttemptTimeoutMillis, p.delivery.deadline)
		if e == nil {
			p.nextID = view.ID
		}
		p.mu.Unlock()
		return e
	}
	if p.terminal {
		p.mu.Unlock()
		return p.reason
	}
	deadline := minServiceTimeV1(p.deadline, p.lastNow.Add(time.Duration(request.AttemptTimeoutMillis)*time.Millisecond))
	qi, qe := p.reserveV1(p.ctx, minServiceTimeV1(p.delivery.deadline, deadline), false)
	if qe != nil {
		p.mu.Unlock()
		return qe
	}
	p.queue[qi].id = view.ID
	p.queue[qi].opcode = ServiceProbeResultV1
	p.queue[qi].deadline = p.delivery.deadline
	if e = p.reserveUsesLockedV1(1); e != nil {
		var body [6]byte
		binary.BigEndian.PutUint16(body[:], uint16(ServiceResourceLimitV1))
		e = p.fillResponseLockedV1(qi, p.queue[qi].serial, view.ID, ServiceProbeResultV1, body[:], request.AttemptTimeoutMillis)
		if e == nil {
			p.nextID = view.ID
		}
		p.mu.Unlock()
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline.Sub(p.lastNow))
	p.probes[i] = serviceProbeSlotV1{id: view.ID, state: 1, admission: a, deadline: deadline, cancel: cancel, worker: true, responseQueue: qi, responseSerial: p.queue[qi].serial}
	p.nextID = view.ID
	p.postCommit = func() error { return p.relayProbeV1(i, view.ID, ctx) }
	p.mu.Unlock()
	return nil
}
func (p *ServicePumpV1) relayProbeV1(i int, id uint32, ctx context.Context) error {
	defer func() {
		p.mu.Lock()
		g := &p.probes[i]
		var cancel context.CancelFunc
		if g.id == id {
			cancel = g.cancel
		}
		p.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		p.mu.Lock()
		if g.id == id {
			g.cancel = nil
			g.worker = false
			retireProbeAdmissionV1(g)
			p.notifyLockedV1()
		}
		p.mu.Unlock()
	}()
	p.mu.Lock()
	g := &p.probes[i]
	if p.terminal || g.id != id || g.state != 1 {
		p.mu.Unlock()
		return nil
	}
	a, deadline, cancel := g.admission, g.deadline, g.cancel
	p.mu.Unlock()
	realDeadline, _ := ctx.Deadline()
	now, e := p.authorityV1()
	if e != nil {
		return e
	}
	result := ServiceSuccessV1
	var duration uint32
	if e = p.cfg.ProbeRates.TryStart(p.cfg.ProbeScope, a, now); e != nil {
		if e == ErrProbeClockRegressionV1 {
			return e
		}
		result = ServiceResourceLimitV1
	} else {
		if e = ctx.Err(); e != nil {
			result = ServiceCancelledV1
		} else {
			address, _ := netip.AddrFromSlice(a.target.Address)
			started := time.Now()
			connection, dialErr := p.cfg.RelayNetwork.DialTCP(ctx, netip.AddrPortFrom(address, a.target.Port))
			elapsed := time.Since(started)
			// Record the dial outcome before deliberate cleanup cancellation.
			if dialErr != nil || connection == nil {
				result = serviceNetworkResultV1(dialErr)
			} else if elapsed >= time.Duration(a.request.AttemptTimeoutMillis)*time.Millisecond || ctx.Err() != nil {
				result = ServiceTimeoutV1
			} else {
				duration = uint32(elapsed.Microseconds())
			}
			if cancel != nil {
				cancel()
			}
			if connection != nil {
				connection.Close()
			}
		}
	}
	p.mu.Lock()
	g = &p.probes[i]
	if p.terminal || g.id != id || g.state != 1 {
		p.mu.Unlock()
		return nil
	}
	// Self-cancel cannot classify the outcome, but neither trusted nor real
	// deadline expiry during cleanup may publish a late success.
	if result == ServiceSuccessV1 && (!p.lastNow.Before(deadline) || !realDeadline.IsZero() && !time.Now().Before(realDeadline)) {
		result = ServiceTimeoutV1
		duration = 0
	}
	var body [6]byte
	binary.BigEndian.PutUint16(body[:], uint16(result))
	binary.BigEndian.PutUint32(body[2:], duration)
	qi := g.responseQueue
	e = p.fillResponseLockedV1(qi, g.responseSerial, id, ServiceProbeResultV1, body[:], a.request.AttemptTimeoutMillis)
	if e == nil {
		serial := p.queue[qi].serial
		for p.queue[qi].state != 0 && p.queue[qi].serial == serial {
			if e = p.waitLockedV1(p.ctx, p.deadline); e != nil {
				break
			}
		}
	}
	if e == nil && g.state == 1 {
		g.state = 2
		g.admission = ProbeAdmissionV1{request: ProbeRequestV1{AttemptTimeoutMillis: a.request.AttemptTimeoutMillis}}
	}
	p.mu.Unlock()
	return e
}
func (p *ServicePumpV1) acceptProbeResultV1(view ServiceRecordViewV1) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := -1
	for j := range p.probes {
		if p.probes[j].id == view.ID {
			i = j
			break
		}
	}
	if i < 0 {
		return ErrServiceRecordV1
	}
	g := &p.probes[i]
	if g.state == 3 {
		if !p.lastNow.Before(g.tombstone) || g.resultSeen {
			return ErrServiceRecordV1
		}
		g.resultSeen = true
		return nil
	}
	if !p.client || g.state != 1 || g.resultSeen || g.sentAt.IsZero() {
		return ErrServiceRecordV1
	}
	g.resultSeen = true
	result := ServiceResultV1(binary.BigEndian.Uint16(view.Body))
	if !p.lastNow.Before(g.attemptDeadline) {
		g.failure = ServiceTimeoutV1
		g.aggregate, _ = AggregateProbeSamplesV1(ProbeActiveRelayEndToEndV1, g.samples[:g.sampleCount])
		g.state = 3
		g.tombstone = minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second))
		retireProbeAdmissionV1(g)
		p.notifyLockedV1()
		return nil
	}
	if result == ServiceSuccessV1 || result == ServiceTimeoutV1 || result == ServiceUnreachableV1 {
		duration := uint64(0)
		if result == ServiceSuccessV1 {
			elapsed := time.Since(g.sentMono)
			if elapsed >= time.Duration(g.admission.request.AttemptTimeoutMillis)*time.Millisecond {
				return ServiceTimeoutV1
			}
			duration = uint64(elapsed.Microseconds())
		}
		if g.sampleCount >= len(g.samples) {
			return ErrServiceRecordV1
		}
		g.samples[g.sampleCount] = ProbeSampleV1{Attempted: true, Success: result == ServiceSuccessV1, DurationMicros: duration, AttemptTimeoutMillis: g.admission.request.AttemptTimeoutMillis}
		g.sampleCount++
	}
	g.result = result
	g.hasResult = true
	p.bounds.ServicesProcessed++
	p.notifyLockedV1()
	return nil
}
func (p *ServicePumpV1) acceptProbeResetV1(i int, id uint32) error {
	p.mu.Lock()
	g := &p.probes[i]
	if g.id != id || g.state == 0 || g.state == 3 && !p.lastNow.Before(g.tombstone) {
		p.mu.Unlock()
		return ErrServiceRecordV1
	}
	if g.state == 3 {
		p.mu.Unlock()
		return nil
	}
	cancel := g.cancel
	for j := range p.queue {
		if p.queue[j].id == id && (p.queue[j].state == 1 || p.queue[j].state == 2) {
			p.queue[j].state = 4
		}
	}
	g.failure = ServiceCancelledV1
	g.state = 3
	g.tombstone = minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second))
	retireProbeAdmissionV1(g)
	g.aggregate, _ = AggregateProbeSamplesV1(ProbeActiveRelayEndToEndV1, g.samples[:g.sampleCount])
	p.notifyLockedV1()
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// Retire target authority only after the worker's last borrower has returned.
// The scalar attempt timeout remains necessary to decode one crossing result.
func retireProbeAdmissionV1(g *serviceProbeSlotV1) {
	if !g.worker && (g.state == 2 || g.state == 3) {
		timeout := g.admission.request.AttemptTimeoutMillis
		g.admission = ProbeAdmissionV1{request: ProbeRequestV1{AttemptTimeoutMillis: timeout}}
	}
}
