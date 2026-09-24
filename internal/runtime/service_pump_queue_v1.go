// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"context"
	"time"
)

func (p *ServicePumpV1) waitLockedV1(ctx context.Context, deadline time.Time) error {
	if p.terminal {
		return p.reason
	}
	if e := ctx.Err(); e != nil {
		return serviceTerminalV1(e)
	}
	if !deadline.IsZero() && !p.lastNow.Before(deadline) {
		return ServiceTimeoutV1
	}
	changed := p.changed
	p.mu.Unlock()
	select {
	case <-changed:
	case <-ctx.Done():
	case <-p.closed:
	}
	p.mu.Lock()
	if p.terminal {
		return p.reason
	}
	return nil
}

// reserveV1 installs a descriptor before any producer copy. The TX borrower
// remains counted in used until its complete carrier write returns.
func (p *ServicePumpV1) reserveV1(ctx context.Context, deadline time.Time, immediate bool) (int, error) {
	for p.used == len(p.queue) {
		if immediate {
			return -1, ServiceResourceLimitV1
		}
		if e := p.waitLockedV1(ctx, deadline); e != nil {
			return -1, e
		}
	}
	if p.terminal {
		return -1, p.reason
	}
	if e := ctx.Err(); e != nil {
		return -1, serviceTerminalV1(e)
	}
	if !deadline.IsZero() && !p.lastNow.Before(deadline) {
		return -1, ServiceTimeoutV1
	}
	i := p.tail
	p.tail = (p.tail + 1) % len(p.queue)
	p.used++
	p.serial++
	q := &p.queue[i]
	q.state = 1
	q.serial = p.serial
	q.stream = -1
	q.probe = -1
	q.deadline = deadline
	return i, nil
}
func (p *ServicePumpV1) queueCopyLockedV1(i int, data []byte, id uint32, op ServiceOpcodeV1) {
	q := &p.queue[i]
	if q.cached == nil {
		q.cached = make([]byte, p.slotBytes)
	}
	q.size = copy(q.cached, data)
	q.data = q.cached[:q.size]
	q.id = id
	q.opcode = op
	q.state = 2
	p.notifyLockedV1()
}
func (p *ServicePumpV1) validatePacketV1(packet []byte, outbound bool) error {
	_, e := effectivePacketInfoV1(packet, p.client == outbound, p.mtu, p.client4, p.dns4, p.client6, p.dns6, p.protocols[:p.protocolCount])
	return e
}
func (p *ServicePumpV1) packetSourceV1() error {
	var local productionFlowRefV1
	defer func() {
		if p.production != nil {
			p.production.releaseV1(local)
		}
	}()
	for {
		var n int
		var e error
		if p.production != nil {
			n, local, e = p.cfg.PacketIO.(*PacketPortV1).readProductionV1(p.packetScratch, p.production)
		} else {
			n, e = p.cfg.PacketIO.Read(p.packetScratch)
		}
		if e != nil {
			return ErrPacketPumpIO
		}
		if n <= 0 || n > len(p.packetScratch) {
			return ErrPacketInvalid
		}
		if e = p.validatePacketV1(p.packetScratch[:n], true); e != nil {
			return e
		}
		p.mu.Lock()
		i, e := p.reserveV1(p.ctx, p.deadline, false)
		if e != nil {
			p.mu.Unlock()
			return e
		}
		q := &p.queue[i]
		q.flow = local
		local = productionFlowRefV1{}
		if p.production != nil && p.production.flow != nil {
			p.production.flow.acceptV1(q.flow, p.lastNow)
		}
		q.data = p.packetScratch[:n]
		q.size = n
		q.state = 2
		q.id = 0
		q.opcode = 0
		serial := q.serial
		p.notifyLockedV1()
		for q.state != 0 && q.serial == serial {
			if e = p.waitLockedV1(p.ctx, p.deadline); e != nil {
				p.mu.Unlock()
				return e
			}
		}
		p.mu.Unlock()
	}
}
func (p *ServicePumpV1) txV1() error {
	for {
		p.mu.Lock()
		for p.used == 0 || (p.queue[p.head].state != 2 && p.queue[p.head].state != 4) {
			if e := p.waitLockedV1(p.ctx, p.deadline); e != nil {
				p.mu.Unlock()
				return e
			}
		}
		if p.queue[p.head].state == 4 {
			p.releaseQueueLockedV1(p.head)
			p.mu.Unlock()
			continue
		}
		i := p.head
		q := &p.queue[i]
		q.state = 3
		p.mu.Unlock()
		now, authorityErr := p.authorityV1()
		if authorityErr != nil {
			return authorityErr
		}
		p.mu.Lock()
		if p.terminal {
			e := p.reason
			p.mu.Unlock()
			return e
		}
		if !q.deadline.IsZero() && !p.lastNow.Before(q.deadline) {
			id, opcode, probe := q.id, q.opcode, q.probe
			p.releaseQueueLockedV1(i)
			p.mu.Unlock()
			if opcode == ServiceProbeV1 && probe >= 0 {
				p.mu.Lock()
				handle := p.probes[probe].handle
				p.mu.Unlock()
				if e := p.finishProbeV1(probe, handle, ServiceTimeoutV1); e != nil {
					return e
				}
				continue
			}
			if opcode == ServiceOpenV1 && p.client {
				if e := p.cancelStreamV1(id, ServiceTimeoutV1); e != nil {
					return e
				}
				continue
			}
			return ServiceTimeoutV1
		}
		if q.opcode == ServiceProbeV1 && q.probe >= 0 {
			g := &p.probes[q.probe]
			if g.state != 1 || g.id != q.id {
				p.releaseQueueLockedV1(i)
				p.mu.Unlock()
				continue
			}
			g.sentAt = now
			g.sentMono = time.Now()
			g.attemptDeadline = minServiceTimeV1(g.deadline, g.sentAt.Add(time.Duration(g.admission.request.AttemptTimeoutMillis)*time.Millisecond))
			q.deadline = g.attemptDeadline
			p.notifyLockedV1()
		}
		p.outer++
		if p.outer > 65534 {
			p.outer = 2
		}
		outer := p.outer
		data := q.data
		if q.opcode == ServiceOpenV1 && q.stream >= 0 {
			p.streams[q.stream].sent = true
		}
		p.ioDeadline = minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second))
		p.ioDeadline = minServiceTimeV1(p.ioDeadline, q.deadline)
		p.mu.Unlock()
		record, e := p.endpoint.SealDataV3(data, outer, int64(outer))
		if e == nil {
			e = writeBoundedRecordV1(p.cfg.Carrier, record)
		}
		p.mu.Lock()
		p.ioDeadline = time.Time{}
		if p.production == nil || e == nil {
			p.activity = p.lastNow
		}
		streamIndex := p.streamIndexLockedV1(q.id)
		if streamIndex >= 0 && (p.production == nil || e == nil) {
			p.streams[streamIndex].idle = p.lastNow
		}
		p.releaseQueueLockedV1(i)
		var retired ServiceTCPConnV1
		if streamIndex >= 0 {
			if e == nil {
				p.retireClientStreamLockedV1(streamIndex)
			}
			retired = p.retireRelayStreamLockedV1(streamIndex)
		}
		p.mu.Unlock()
		if retired != nil {
			retired.Close()
		}
		if e != nil {
			return e
		}
	}
}
func (p *ServicePumpV1) releaseQueueLockedV1(i int) {
	q := &p.queue[i]
	if p.production != nil {
		p.production.releaseV1(q.flow)
	}
	if q.stream >= 0 && q.opcode == ServiceDataV1 {
		p.streams[q.stream].outBytes -= uint32(q.size - 8)
	}
	clear(q.data)
	cached := q.cached
	serial := q.serial
	*q = serviceQueueSlotV1{cached: cached, serial: serial}
	p.head = (p.head + 1) % len(p.queue)
	p.used--
	p.notifyLockedV1()
}

// TrySubmitReturnPacketV3 is a nonblocking same-ring ingress, not a second FIFO.
func (p *ServicePumpV1) TrySubmitReturnPacketV3(packet []byte) error {
	if e := p.beginUseV1(false); e != nil {
		return e
	}
	defer p.endUseV1()
	p.mu.Lock()
	if p.client || !p.cfg.ExternalPacketIngress || p.ingress {
		p.mu.Unlock()
		return ServiceInvalidRequestV1
	}
	p.ingress = true
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.ingress = false; p.mu.Unlock() }()
	if e := p.validatePacketV1(packet, true); e != nil {
		return e
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	i, e := p.reserveV1(context.Background(), p.deadline, true)
	if e != nil {
		return e
	}
	p.queueCopyLockedV1(i, packet, 0, 0)
	return nil
}

func (p *ServicePumpV1) directionV1() ServiceDirectionV1 {
	if p.client {
		return ServiceClientToRelayV1
	}
	return ServiceRelayToClientV1
}
func (p *ServicePumpV1) queueControlLockedV1(ctx context.Context, id uint32, opcode ServiceOpcodeV1, body []byte, timeout uint16, deadline time.Time) (int, error) {
	var raw [272]byte
	n, e := p.codec.Encode(raw[:], ServiceRecordViewV1{Opcode: opcode, ID: id, Body: body}, p.directionV1(), timeout)
	if e != nil {
		return -1, e
	}
	i, e := p.reserveV1(ctx, deadline, false)
	if e != nil {
		return -1, e
	}
	p.queueCopyLockedV1(i, raw[:n], id, opcode)
	return i, nil
}

func (p *ServicePumpV1) fillResponseLockedV1(i int, serial uint64, id uint32, opcode ServiceOpcodeV1, body []byte, timeout uint16) error {
	if p.terminal {
		return p.reason
	}
	q := &p.queue[i]
	if q.serial != serial || q.state != 1 || q.id != id {
		return ErrAuthenticatedFrameState
	}
	var raw [272]byte
	n, e := p.codec.Encode(raw[:], ServiceRecordViewV1{Opcode: opcode, ID: id, Body: body}, p.directionV1(), timeout)
	if e != nil {
		return e
	}
	p.queueCopyLockedV1(i, raw[:n], id, opcode)
	return nil
}
