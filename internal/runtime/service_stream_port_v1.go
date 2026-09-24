// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

var serviceDeliveryTokensV1 atomic.Uint64

func (p *ServicePumpV1) streamIndexLockedV1(id uint32) int {
	for i := range p.streams {
		if id != 0 && p.streams[i].id == id {
			return i
		}
	}
	return -1
}
func (p *ServicePumpV1) familyV1(address netip.Addr) bool {
	return address.Is4() && p.client4 != [4]byte{} || address.Is6() && !address.Is4In6() && p.client6 != [16]byte{}
}
func (p *ServicePumpV1) admitProxyV1(r ProxyRequestV1) (ProxyRequestV1, error) {
	if p.admission.policy.Services.Proxy == nil || p.production != nil && len(p.streams) == 0 {
		return ProxyRequestV1{}, ServiceNotAdmittedV1
	}
	if r.Kind != 2 {
		a, ok := netip.AddrFromSlice(r.Address)
		if ok && !p.familyV1(a) {
			return ProxyRequestV1{}, ServiceDestinationDeniedV1
		}
	}
	return p.admission.AdmitProxy(r)
}
func (p *ServicePumpV1) OpenStream(ctx context.Context, r ProxyRequestV1) (uint32, error) {
	if e := p.beginUseV1(true); e != nil {
		return 0, e
	}
	defer p.endUseV1()
	if !p.client {
		return 0, ServiceNotAdmittedV1
	}
	r, e := p.admitProxyV1(r)
	if e != nil {
		return 0, e
	}
	defer clear(r.Address)
	p.mu.Lock()
	index := -1
	for i := range p.streams {
		if p.streams[i].state == 0 {
			index = i
			break
		}
	}
	if index < 0 || p.nextID == math.MaxUint32 {
		p.mu.Unlock()
		return 0, ServiceResourceLimitV1
	}
	deadline := minServiceTimeV1(p.deadline, p.lastNow.Add(time.Duration(p.admission.policy.Services.Proxy.ConnectTimeoutMillis)*time.Millisecond))
	// Opening calls consume S before waiting on the shared descriptor ring.
	p.streams[index].state = 5
	// Reserve the OPEN descriptor before ID consumption or publishing state.
	qi, e := p.reserveV1(ctx, deadline, false)
	if e != nil {
		p.streams[index] = serviceStreamSlotV1{}
		p.mu.Unlock()
		return 0, e
	}
	p.nextID++
	id := p.nextID
	var body [258]byte
	body[0] = r.Kind
	binary.BigEndian.PutUint16(body[1:3], uint16(len(r.Address)))
	copy(body[3:], r.Address)
	binary.BigEndian.PutUint16(body[3+len(r.Address):], r.Port)
	var raw [272]byte
	n, e := p.codec.Encode(raw[:], ServiceRecordViewV1{Opcode: ServiceOpenV1, ID: id, Body: body[:5+len(r.Address)]}, p.directionV1(), 0)
	if e != nil {
		p.mu.Unlock()
		p.CancelWithReason(e)
		return 0, e
	}
	s := &p.streams[index]
	*s = serviceStreamSlotV1{id: id, state: 1, deadline: deadline, idle: p.lastNow}
	p.queueCopyLockedV1(qi, raw[:n], id, ServiceOpenV1)
	p.queue[qi].stream = index
	for s.state == 1 {
		if e = p.waitLockedV1(ctx, deadline); e != nil {
			p.mu.Unlock()
			p.cancelStreamV1(id, e)
			return 0, e
		}
	}
	if p.terminal {
		e = p.reason
	} else if s.state != 2 {
		e = s.result
		if e == nil {
			e = ServiceCancelledV1
		}
	}
	p.mu.Unlock()
	if e != nil {
		return 0, e
	}
	return id, nil
}
func (p *ServicePumpV1) WriteStream(ctx context.Context, id uint32, input []byte) (int, error) {
	if e := p.beginUseV1(true); e != nil {
		return 0, e
	}
	defer p.endUseV1()
	if !p.client {
		return 0, ServiceNotAdmittedV1
	}
	p.mu.Lock()
	i := p.streamIndexLockedV1(id)
	if i < 0 || p.streams[i].state != 2 || p.streams[i].localFIN || p.streams[i].writing {
		p.mu.Unlock()
		return 0, ErrAuthenticatedFrameState
	}
	p.streams[i].writing = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		if p.streams[i].id == id {
			p.streams[i].writing = false
		}
		p.notifyLockedV1()
		p.mu.Unlock()
	}()
	written := 0
	for written < len(input) {
		n := min(p.chunk, len(input)-written)
		p.mu.Lock()
		s := &p.streams[i]
		deadline := minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second))
		for s.outBytes+uint32(n) > p.cfg.StreamQueueBytes {
			if e := p.waitLockedV1(ctx, deadline); e != nil {
				p.mu.Unlock()
				return written, e
			}
		}
		if s.id != id || s.state != 2 || s.localFIN {
			p.mu.Unlock()
			return written, ErrAuthenticatedFrameState
		}
		qi, e := p.reserveV1(ctx, deadline, false)
		if e != nil {
			p.mu.Unlock()
			return written, e
		}
		if s.id != id || s.state != 2 || s.localFIN {
			p.queue[qi].state = 4
			p.notifyLockedV1()
			p.mu.Unlock()
			return written, ErrAuthenticatedFrameState
		}
		q := &p.queue[qi]
		if q.cached == nil {
			q.cached = make([]byte, p.slotBytes)
		}
		size, e := p.codec.Encode(q.cached, ServiceRecordViewV1{Opcode: ServiceDataV1, ID: id, Body: input[written : written+n]}, p.directionV1(), 0)
		if e != nil {
			p.mu.Unlock()
			p.CancelWithReason(e)
			return written, e
		}
		s.outBytes += uint32(n)
		q.data = q.cached[:size]
		q.size = size
		q.id = id
		q.opcode = ServiceDataV1
		q.stream = i
		q.state = 2
		p.notifyLockedV1()
		p.mu.Unlock()
		written += n
	}
	return written, nil
}
func (p *ServicePumpV1) CloseWrite(ctx context.Context, id uint32) error {
	if e := p.beginUseV1(true); e != nil {
		return e
	}
	defer p.endUseV1()
	if !p.client {
		return ServiceNotAdmittedV1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.streamIndexLockedV1(id)
	if i < 0 {
		return ErrAuthenticatedFrameState
	}
	return p.queueStreamFINLockedV1(ctx, i, id)
}

// The same per-stream writer reservation covers FIN's descriptor wait. It is
// released on refusal, but localFIN is published only with an admitted FIN.
func (p *ServicePumpV1) queueStreamFINLockedV1(ctx context.Context, i int, id uint32) error {
	s := &p.streams[i]
	if s.id != id || s.state != 2 || s.localFIN || s.writing {
		return ErrAuthenticatedFrameState
	}
	s.writing = true
	defer func() {
		if s.id == id {
			s.writing = false
		}
		p.notifyLockedV1()
	}()
	qi, e := p.reserveV1(ctx, minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second)), false)
	if e != nil {
		return e
	}
	if s.id != id || s.state != 2 || s.localFIN {
		p.queue[qi].state = 4
		p.notifyLockedV1()
		return ErrAuthenticatedFrameState
	}
	var raw [8]byte
	n, e := p.codec.Encode(raw[:], ServiceRecordViewV1{Opcode: ServiceFINV1, ID: id}, p.directionV1(), 0)
	if e != nil {
		p.queue[qi].state = 4
		return e
	}
	p.queueCopyLockedV1(qi, raw[:n], id, ServiceFINV1)
	s.localFIN = true
	return nil
}
func (p *ServicePumpV1) CancelStream(id uint32) error {
	if e := p.beginUseV1(true); e != nil {
		return e
	}
	defer p.endUseV1()
	return p.cancelStreamV1(id, ServiceCancelledV1)
}
func (p *ServicePumpV1) cancelStreamV1(id uint32, reason error) error {
	p.mu.Lock()
	i := p.streamIndexLockedV1(id)
	if i < 0 {
		p.mu.Unlock()
		return ErrAuthenticatedFrameState
	}
	s := &p.streams[i]
	if s.state == 3 {
		p.mu.Unlock()
		return nil
	}
	// An acknowledged delivery may still occupy RX's slot until its owner
	// wakes. Closing that stream must not invalidate the completed delivery.
	if p.delivery.id == id && p.delivery.received && !p.delivery.confirmed {
		p.mu.Unlock()
		p.CancelWithReason(ErrAuthenticatedFrameState)
		return ErrAuthenticatedFrameState
	}
	sent := s.sent || !p.client
	s.state = 3
	s.result = reason
	s.tombstone = minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second))
	if !s.worker {
		clear(s.request.Address)
		s.request = ProxyRequestV1{}
	}
	connection, cancel := s.conn, s.cancel
	s.conn = nil
	for j := range p.queue {
		q := &p.queue[j]
		if q.id == id && (q.state == 1 || q.state == 2) {
			q.state = 4
		}
	}
	p.notifyLockedV1()
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if connection != nil {
		connection.Close()
	}
	if !sent {
		return nil
	}
	p.mu.Lock()
	var body [2]byte
	binary.BigEndian.PutUint16(body[:], uint16(ServiceCancelledV1))
	_, e := p.queueControlLockedV1(p.ctx, id, ServiceResetV1, body[:], 0, minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second)))
	p.mu.Unlock()
	if e != nil {
		p.CancelWithReason(e)
	}
	return e
}
func (p *ServicePumpV1) ReceiveStream(ctx context.Context, id uint32, output []byte) (uint64, int, error) {
	if e := p.beginUseV1(true); e != nil {
		return 0, 0, e
	}
	defer p.endUseV1()
	if !p.client {
		return 0, 0, ServiceNotAdmittedV1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.streamIndexLockedV1(id)
	if i < 0 || p.streams[i].receiving {
		return 0, 0, ErrAuthenticatedFrameState
	}
	s := &p.streams[i]
	s.receiving = true
	defer func() {
		s.receiving = false
		p.retireClientStreamLockedV1(i)
	}()
	for {
		if p.terminal {
			return 0, 0, p.reason
		}
		if s.id != id || s.state != 2 {
			return 0, 0, ErrAuthenticatedFrameState
		}
		d := &p.delivery
		if d.id == id && d.length > 0 && !d.confirmed {
			if d.received {
				return 0, 0, ErrAuthenticatedFrameState
			}
			if len(output) < d.length {
				return 0, 0, io.ErrShortBuffer
			}
			token, e := nextPacketPortTokenV1(&serviceDeliveryTokensV1)
			if e != nil {
				return 0, 0, e
			}
			copy(output, p.rx[8:8+d.length])
			d.token = uint64(token)
			d.received = true
			return d.token, d.length, nil
		}
		if s.remoteFIN {
			s.readEOF = true
			return 0, 0, io.EOF
		}
		if e := p.waitLockedV1(ctx, p.deadline); e != nil {
			return 0, 0, e
		}
	}
}
func (p *ServicePumpV1) ConfirmStreamDelivery(id uint32, token uint64, length int) error {
	if e := p.beginUseV1(true); e != nil {
		return e
	}
	defer p.endUseV1()
	return p.confirmStreamDeliveryV1(id, token, length)
}

// StreamRetiredV1 reports actual runtime retirement, never elapsed wrapper time.
func (p *ServicePumpV1) StreamRetiredV1(id uint32) (bool, error) {
	if e := p.beginUseV1(true); e != nil {
		return false, e
	}
	defer p.endUseV1()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.client || id == 0 || id > p.nextID {
		return false, ErrAuthenticatedFrameState
	}
	return p.streamIndexLockedV1(id) < 0, nil
}

// The callback joins the native parent fence to this already-counted pump use.
// Its commit is synchronous, at-most-once and invalid after callback return.
// Failure cancellation is deliberately outside the caller's fence.
func (p *ServicePumpV1) ConfirmStreamDeliveryFencedV1(id uint32, token uint64, length int, fence func(func() error) error) error {
	if fence == nil {
		return ServiceInvalidRequestV1
	}
	if e := p.beginUseV1(true); e != nil {
		return e
	}
	defer p.endUseV1()
	var mu sync.Mutex
	active, called, misused := true, false, false
	var committed error
	result := fence(func() error {
		mu.Lock()
		defer mu.Unlock()
		if !active || called {
			misused = true
			return ErrAuthenticatedFrameState
		}
		called = true
		committed = p.markStreamDeliveryV1(id, token, length)
		return committed
	})
	mu.Lock()
	active = false
	if (!called || misused) && result == nil {
		result = ErrAuthenticatedFrameState
	}
	if committed != nil {
		result = committed
	}
	mu.Unlock()
	if result != nil {
		p.CancelWithReason(result)
	}
	return result
}

// confirmStreamDeliveryV1 is the publication half of an already-counted use.
func (p *ServicePumpV1) confirmStreamDeliveryV1(id uint32, token uint64, length int) error {
	err := p.markStreamDeliveryV1(id, token, length)
	if err != nil {
		p.CancelWithReason(err)
	}
	return err
}

func (p *ServicePumpV1) markStreamDeliveryV1(id uint32, token uint64, length int) error {
	p.mu.Lock()
	if p.terminal {
		e := p.reason
		p.mu.Unlock()
		return e
	}
	d := &p.delivery
	i := p.streamIndexLockedV1(id)
	valid := p.client && i >= 0 && p.streams[i].state == 2 && token != 0 && d.id == id && d.token == token && d.received && !d.confirmed && d.length == length && p.lastNow.Before(d.deadline)
	if valid {
		d.confirmed = true
		p.notifyLockedV1()
	}
	p.mu.Unlock()
	if !valid {
		return ErrAuthenticatedFrameState
	}
	return nil
}
func (p *ServicePumpV1) RejectStreamDelivery(id uint32, token uint64) error {
	if e := p.beginUseV1(true); e != nil {
		return e
	}
	defer p.endUseV1()
	p.mu.Lock()
	valid := id != 0 && token != 0 && p.delivery.id == id && p.delivery.token == token && p.delivery.received && !p.delivery.confirmed
	p.mu.Unlock()
	p.CancelWithReason(ErrAuthenticatedFrameState)
	if !valid {
		return ErrAuthenticatedFrameState
	}
	return ServiceCancelledV1
}

func (p *ServicePumpV1) streamWorkerV1(i int, id uint32, ctx context.Context) error {
	defer func() {
		p.mu.Lock()
		s := &p.streams[i]
		var connection ServiceTCPConnV1
		var cancel context.CancelFunc
		if s.id == id {
			cancel = s.cancel
		}
		p.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		p.mu.Lock()
		if s.id == id {
			s.cancel = nil
			s.worker = false
			clear(s.request.Address)
			s.request = ProxyRequestV1{}
			// Scratch may still be borrowed by TX after cancellation. Only the
			// joined owner/reaper clears it, never this exiting source worker.
			connection = p.retireRelayStreamLockedV1(i)
		}
		p.notifyLockedV1()
		p.mu.Unlock()
		if connection != nil {
			connection.Close()
		}
	}()
	p.mu.Lock()
	s := &p.streams[i]
	if p.terminal || s.id != id || s.state != 1 {
		p.mu.Unlock()
		return nil
	}
	request := s.request
	deadline := s.deadline
	cancel := s.cancel
	p.mu.Unlock()
	var answers [16]netip.Addr
	count := 0
	var e error
	if request.Kind == 2 {
		count, e = p.cfg.RelayNetwork.ResolveProxy(ctx, request.Address, &answers)
		if e == nil && (count < 0 || count > 16) {
			e = ServiceDestinationDeniedV1
		}
	}
	// Inspect the whole bounded answer before effective-family compaction. Signed
	// public/CIDR filtering and sorting/truncation stay in ProxyCandidates.
	if e == nil {
		out := 0
		for _, address := range answers[:count] {
			if p.familyV1(address) {
				answers[out] = address
				out++
			}
		}
		count = out
	}
	var candidates []netip.Addr
	if e == nil {
		candidates, e = p.admission.ProxyCandidates(request, answers[:count])
	}
	var connection ServiceTCPConnV1
	cleanupCancelled := false
	realDeadline, _ := ctx.Deadline()
	if e == nil {
		for candidate, address := range candidates {
			if ctx.Err() != nil {
				e = ctx.Err()
				break
			}
			connection, e = p.cfg.RelayNetwork.DialTCP(ctx, netip.AddrPortFrom(address, request.Port))
			if e == nil && connection != nil {
				break
			}
			if connection != nil {
				p.mu.Lock()
				s = &p.streams[i]
				finished := candidate == len(candidates)-1 || p.terminal || s.id != id || s.state != 1 || !p.lastNow.Before(deadline) || ctx.Err() != nil || !realDeadline.IsZero() && !time.Now().Before(realDeadline)
				p.mu.Unlock()
				// A still-live first candidate may fall back using the same leaf.
				if finished && cancel != nil {
					cleanupCancelled = ctx.Err() == nil
					cancel()
				}
				connection.Close()
				connection = nil
			}
			if e == nil {
				e = ServiceUnreachableV1
			}
		}
	}
	if _, authorityErr := p.authorityV1(); authorityErr != nil {
		if cancel != nil {
			cancel()
		}
		if connection != nil {
			connection.Close()
		}
		return authorityErr
	}
	p.mu.Lock()
	s = &p.streams[i]
	if p.terminal || s.id != id || s.state != 1 {
		p.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if connection != nil {
			connection.Close()
		}
		return nil
	}
	var lateConnection ServiceTCPConnV1
	if ctx.Err() != nil && !cleanupCancelled || !p.lastNow.Before(deadline) || !realDeadline.IsZero() && !time.Now().Before(realDeadline) {
		e = context.DeadlineExceeded
		lateConnection, connection = connection, nil
	}
	result := ServiceSuccessV1
	if e != nil || connection == nil {
		result = serviceNetworkResultV1(e)
		s.state = 3
		s.result = result
		s.tombstone = minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second))
	} else {
		s.conn = connection
		s.state = 2
		s.scratch = make([]byte, p.chunk+8)
		s.idle = p.lastNow
	}
	var body [2]byte
	binary.BigEndian.PutUint16(body[:], uint16(result))
	qe := p.fillResponseLockedV1(s.responseQueue, s.responseSerial, id, ServiceOpenResultV1, body[:], 0)
	p.mu.Unlock()
	if lateConnection != nil {
		if cancel != nil {
			cancel()
		}
		lateConnection.Close()
	}
	if qe != nil {
		return qe
	}
	if result != ServiceSuccessV1 {
		return nil
	}
	for {
		p.mu.Lock()
		s = &p.streams[i]
		if p.terminal || s.id != id || s.state != 2 {
			p.mu.Unlock()
			return nil
		}
		scratch := s.scratch
		p.mu.Unlock()
		n, readErr := connection.Read(scratch[8:])
		if n < 0 || n > len(scratch)-8 {
			return ErrPacketPumpIO
		}
		if n > 0 {
			p.mu.Lock()
			s = &p.streams[i]
			if p.terminal || s.id != id || s.state != 2 {
				p.mu.Unlock()
				return nil
			}
			qi, qe := p.reserveV1(p.ctx, p.deadline, false)
			if qe != nil {
				p.mu.Unlock()
				return qe
			}
			if s.id != id || s.state != 2 || s.localFIN {
				p.queue[qi].state = 4
				p.notifyLockedV1()
				p.mu.Unlock()
				return nil
			}
			size, qe := p.codec.Encode(scratch, ServiceRecordViewV1{Opcode: ServiceDataV1, ID: id, Body: scratch[8 : 8+n]}, p.directionV1(), 0)
			if qe != nil {
				p.mu.Unlock()
				return qe
			}
			q := &p.queue[qi]
			q.data = scratch[:size]
			q.size = size
			q.id = id
			q.opcode = ServiceDataV1
			q.stream = i
			q.state = 2
			s.outBytes += uint32(n)
			serial := q.serial
			p.notifyLockedV1()
			for q.state != 0 && q.serial == serial {
				if qe = p.waitLockedV1(p.ctx, p.deadline); qe != nil {
					p.mu.Unlock()
					return qe
				}
			}
			p.mu.Unlock()
		}
		if readErr != nil {
			if readErr != io.EOF {
				return p.cancelStreamV1(id, ServiceUnreachableV1)
			}
			p.mu.Lock()
			s = &p.streams[i]
			if s.id != id || s.state != 2 || p.terminal {
				p.mu.Unlock()
				return nil
			}
			qe := p.queueStreamFINLockedV1(p.ctx, i, id)
			if s.id != id || s.state != 2 {
				qe = nil
			}
			p.mu.Unlock()
			return qe
		}
		if n == 0 {
			return ErrPacketPumpIO
		}
	}
}

func (p *ServicePumpV1) queuedIDLockedV1(id uint32) bool {
	for i := range p.queue {
		if p.queue[i].state != 0 && p.queue[i].id == id {
			return true
		}
	}
	return false
}

// EOF consumption and outgoing FIN completion can occur in either order.
// Neither alone permits reuse of the stream's owned slot.
func (p *ServicePumpV1) retireClientStreamLockedV1(i int) {
	s := &p.streams[i]
	if p.client && !p.terminal && s.state == 2 && s.localFIN && s.remoteFIN && s.readEOF && !s.writing && !s.receiving && !p.queuedIDLockedV1(s.id) {
		clear(s.request.Address)
		*s = serviceStreamSlotV1{}
	}
}

func (p *ServicePumpV1) retireRelayStreamLockedV1(i int) ServiceTCPConnV1 {
	s := &p.streams[i]
	if p.client || p.terminal || s.state != 2 || !s.localFIN || !s.remoteFIN || s.worker || s.writing || s.receiving || p.queuedIDLockedV1(s.id) {
		return nil
	}
	c := s.conn
	clear(s.scratch)
	clear(s.request.Address)
	*s = serviceStreamSlotV1{}
	return c
}
func serviceNetworkResultV1(e error) ServiceResultV1 {
	if r, ok := e.(ServiceResultV1); ok && r > 0 && r <= 10 {
		return r
	}
	if e == context.DeadlineExceeded {
		return ServiceTimeoutV1
	}
	if e == context.Canceled {
		return ServiceCancelledV1
	}
	return ServiceUnreachableV1
}
