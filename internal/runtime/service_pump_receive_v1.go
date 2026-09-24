// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"context"
	"encoding/binary"
	"io"
	"time"
)

func (p *ServicePumpV1) readRecordV1() ([]byte, error) {
	var prefix [4]byte
	if _, e := io.ReadFull(p.cfg.Carrier, prefix[:]); e != nil {
		return nil, ErrPacketPumpIO
	}
	n := uint64(binary.BigEndian.Uint32(prefix[:]))
	b := p.endpoint.ReceiveBufferV3()
	if n == 0 || n > uint64(len(b)) {
		return nil, ServiceResourceLimitV1
	}
	if _, e := io.ReadFull(p.cfg.Carrier, b[:n]); e != nil {
		return nil, ErrPacketPumpIO
	}
	return b[:n], nil
}

// consumed distinguishes a completed service operation/delivery from an
// authenticated tombstone discard. Errors never authorize activity refresh.
func (p *ServicePumpV1) consumeServiceV1(raw []byte, consumed *bool) error {
	*consumed = false
	if _, e := p.authorityV1(); e != nil {
		return e
	}
	direction := ServiceClientToRelayV1
	if p.client {
		direction = ServiceRelayToClientV1
	}
	var timeout uint16
	if len(raw) >= 8 && ServiceOpcodeV1(raw[1]) == ServiceProbeResultV1 {
		p.mu.Lock()
		for i := range p.probes {
			if p.probes[i].id == binary.BigEndian.Uint32(raw[2:6]) {
				timeout = p.probes[i].admission.request.AttemptTimeoutMillis
			}
		}
		p.mu.Unlock()
	}
	view, e := p.codec.DecodeBorrowed(raw, direction, timeout)
	if e != nil {
		return e
	}
	if view.Opcode == ServiceProbeV1 {
		e = p.acceptProbeV1(view)
		*consumed = e == nil
		return e
	}
	if view.Opcode == ServiceProbeResultV1 {
		e = p.acceptProbeResultV1(view)
		*consumed = e == nil
		return e
	}
	if view.Opcode == ServiceResetV1 {
		p.mu.Lock()
		probe := -1
		for i := range p.probes {
			if p.probes[i].id == view.ID {
				probe = i
				break
			}
		}
		p.mu.Unlock()
		if probe >= 0 {
			e = p.acceptProbeResetV1(probe, view.ID)
			*consumed = e == nil
			return e
		}
	}
	if view.Opcode == ServiceOpenV1 {
		e = p.acceptOpenV1(view)
		*consumed = e == nil
		return e
	}
	p.mu.Lock()
	i := p.streamIndexLockedV1(view.ID)
	if i < 0 {
		p.mu.Unlock()
		return ErrServiceRecordV1
	}
	s := &p.streams[i]
	if s.state == 3 {
		if !p.lastNow.Before(s.tombstone) {
			p.mu.Unlock()
			return ErrServiceRecordV1
		}
		switch view.Opcode {
		case ServiceResetV1:
			p.mu.Unlock()
			return nil
		case ServiceOpenResultV1:
			if s.resultSeen {
				p.mu.Unlock()
				return ErrServiceRecordV1
			}
			s.resultSeen = true
			p.mu.Unlock()
			return nil
		case ServiceDataV1:
			if uint64(s.discarded)+uint64(len(view.Body)) >= uint64(p.cfg.StreamQueueBytes) {
				p.mu.Unlock()
				return ServiceResourceLimitV1
			}
			s.discarded += uint32(len(view.Body))
			p.mu.Unlock()
			return nil
		default:
			p.mu.Unlock()
			return ErrServiceRecordV1
		}
	}
	switch view.Opcode {
	case ServiceOpenResultV1:
		if !p.client || s.state != 1 || s.resultSeen {
			p.mu.Unlock()
			return ErrServiceRecordV1
		}
		s.resultSeen = true
		result := ServiceResultV1(binary.BigEndian.Uint16(view.Body))
		if result == ServiceSuccessV1 {
			s.state = 2
			s.idle = p.lastNow
		} else {
			s.state = 3
			s.result = result
			s.tombstone = minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second))
		}
		p.bounds.ServicesProcessed++
		p.notifyLockedV1()
		p.mu.Unlock()
		*consumed = true
		return nil
	case ServiceResetV1:
		s.state = 3
		s.result = ServiceResultV1(binary.BigEndian.Uint16(view.Body))
		s.tombstone = minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second))
		connection, cancel := s.conn, s.cancel
		s.conn = nil
		if p.delivery.id == view.ID && p.delivery.received {
			p.mu.Unlock()
			return ErrAuthenticatedFrameState
		}
		for j := range p.queue {
			q := &p.queue[j]
			if q.id == view.ID && (q.state == 1 || q.state == 2) {
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
		*consumed = true
		return nil
	case ServiceFINV1:
		if s.state != 2 || s.remoteFIN {
			p.mu.Unlock()
			return ErrServiceRecordV1
		}
		connection := s.conn
		p.mu.Unlock()
		if !p.client {
			if connection == nil {
				return ErrServiceRecordV1
			}
			if e = connection.CloseWrite(); e != nil {
				return ErrPacketPumpIO
			}
		}
		p.mu.Lock()
		var retired ServiceTCPConnV1
		if p.terminal {
			e = p.reason
		} else if s.id != view.ID || s.state != 2 {
			e = ErrServiceRecordV1
		} else {
			s.remoteFIN = true
			retired = p.retireRelayStreamLockedV1(i)
			p.bounds.ServicesProcessed++
			p.notifyLockedV1()
		}
		p.mu.Unlock()
		if retired != nil {
			retired.Close()
		}
		*consumed = e == nil
		return e
	case ServiceDataV1:
		if s.state != 2 || s.remoteFIN || len(view.Body) > int(p.cfg.StreamQueueBytes) {
			p.mu.Unlock()
			return ErrServiceRecordV1
		}
		if p.production == nil {
			s.idle = p.lastNow
		}
		if p.client {
			p.delivery.id = view.ID
			p.delivery.length = len(view.Body)
			p.notifyLockedV1()
			for !p.delivery.confirmed {
				if e = p.waitLockedV1(p.ctx, p.delivery.deadline); e != nil {
					p.mu.Unlock()
					return e
				}
				if !p.delivery.confirmed && (s.id != view.ID || s.state != 2) {
					p.mu.Unlock()
					return ErrAuthenticatedFrameState
				}
			}
			p.bounds.ServicesProcessed++
			p.mu.Unlock()
			*consumed = true
			return nil
		}
		connection := s.conn
		deadline := p.delivery.deadline
		p.mu.Unlock()
		if connection == nil {
			return ErrServiceRecordV1
		}
		if e = connection.SetWriteDeadline(time.Now().Add(deadline.Sub(p.cfg.Now()))); e != nil {
			return ErrPacketPumpIO
		}
		e = writeFullV1(connection, view.Body)
		if e != nil {
			return ErrPacketPumpIO
		}
		if e = connection.SetWriteDeadline(time.Time{}); e != nil {
			return ErrPacketPumpIO
		}
		p.mu.Lock()
		if p.terminal {
			e = p.reason
		} else {
			p.bounds.ServicesProcessed++
		}
		p.mu.Unlock()
		*consumed = e == nil
		return e
	default:
		p.mu.Unlock()
		return ErrServiceRecordV1
	}
}
func (p *ServicePumpV1) acceptOpenV1(view ServiceRecordViewV1) error {
	body := view.Body
	r := ProxyRequestV1{Kind: body[0], Address: body[3 : len(body)-2], Port: binary.BigEndian.Uint16(body[len(body)-2:])}
	admitted, e := p.admitProxyV1(r)
	p.mu.Lock()
	if view.ID <= p.nextID {
		p.mu.Unlock()
		return ErrServiceRecordV1
	}
	index := -1
	for i := range p.streams {
		if p.streams[i].state == 0 {
			index = i
			break
		}
	}
	if e == nil && index < 0 {
		e = ServiceResourceLimitV1
	}
	if e != nil {
		var result [2]byte
		category := ServiceNotAdmittedV1
		if r, ok := e.(ServiceResultV1); ok {
			category = r
		}
		binary.BigEndian.PutUint16(result[:], uint16(category))
		_, e = p.queueControlLockedV1(p.ctx, view.ID, ServiceOpenResultV1, result[:], 0, p.delivery.deadline)
		if e == nil {
			p.nextID = view.ID
		}
		p.mu.Unlock()
		return e
	}
	if p.terminal {
		p.mu.Unlock()
		clear(admitted.Address)
		return p.reason
	}
	deadline := minServiceTimeV1(p.deadline, p.lastNow.Add(time.Duration(p.admission.policy.Services.Proxy.ConnectTimeoutMillis)*time.Millisecond))
	qi, qe := p.reserveV1(p.ctx, minServiceTimeV1(p.delivery.deadline, deadline), false)
	if qe != nil {
		p.mu.Unlock()
		clear(admitted.Address)
		return qe
	}
	p.queue[qi].id = view.ID
	p.queue[qi].opcode = ServiceOpenResultV1
	p.queue[qi].deadline = p.delivery.deadline
	if e = p.reserveUsesLockedV1(1); e != nil {
		var result [2]byte
		binary.BigEndian.PutUint16(result[:], uint16(ServiceResourceLimitV1))
		e = p.fillResponseLockedV1(qi, p.queue[qi].serial, view.ID, ServiceOpenResultV1, result[:], 0)
		if e == nil {
			p.nextID = view.ID
		}
		p.mu.Unlock()
		clear(admitted.Address)
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline.Sub(p.lastNow))
	p.nextID = view.ID
	p.streams[index] = serviceStreamSlotV1{id: view.ID, state: 1, request: admitted, deadline: deadline, cancel: cancel, worker: true, idle: p.lastNow, responseQueue: qi, responseSerial: p.queue[qi].serial}
	p.postCommit = func() error { return p.streamWorkerV1(index, view.ID, ctx) }
	p.bounds.ServicesProcessed++
	p.mu.Unlock()
	return nil
}
func (p *ServicePumpV1) rxV1() error {
	for {
		record, e := p.readRecordV1()
		if e != nil {
			return e
		}
		pending, e := p.endpoint.OpenFrameV3(record)
		if e != nil {
			return e
		}
		if pending == nil {
			p.mu.Lock()
			if p.production == nil {
				p.activity = p.lastNow
			}
			p.mu.Unlock()
			continue
		}
		receipt, consumeErr := p.consumeFrameV1(pending)
		e = consumeErr
		if e != nil {
			pending.Discard()
			if p.postCommit != nil {
				p.postCommit = nil
				p.endUseV1()
			}
			return e
		}
		if e = pending.Commit(); e != nil {
			if p.postCommit != nil {
				p.postCommit = nil
				p.endUseV1()
			}
			return e
		}
		if p.postCommit != nil {
			f := p.postCommit
			p.postCommit = nil
			go p.workerV1(f)
		}
		p.commitProductionReturnV1(receipt)
		p.mu.Lock()
		p.delivery = serviceDeliveryV1{}
		if p.production == nil {
			p.activity = p.lastNow
		}
		p.notifyLockedV1()
		p.mu.Unlock()
	}
}
func (p *ServicePumpV1) consumeFrameV1(pending *AuthenticatedInnerFrameV1) (productionReturnReceiptV1, error) {
	var receipt productionReturnReceiptV1
	info, e := pending.DataInfoV3()
	if e != nil || info.PayloadBytes > uint32(len(p.rx)) {
		return receipt, ErrServiceRecordV1
	}
	n, e := pending.CopyPayloadIntoV3(p.rx)
	if e != nil {
		return receipt, e
	}
	defer clear(p.rx[:n])
	p.mu.Lock()
	p.delivery.deadline = minServiceTimeV1(p.deadline, p.lastNow.Add(30*time.Second))
	p.mu.Unlock()
	raw := p.rx[:n]
	switch ClassifyServicePayloadV1(raw) {
	case ServicePayloadIPv4V1, ServicePayloadIPv6V1:
		info, e := effectivePacketInfoV1(raw, !p.client, p.mtu, p.client4, p.dns4, p.client6, p.dns6, p.protocols[:p.protocolCount])
		if e != nil {
			return receipt, e
		}
		if p.production != nil {
			a := p.production
			a.mu.Lock()
			if a.closed || !a.raw {
				a.mu.Unlock()
				return receipt, ServiceNotAdmittedV1
			}
			key, flow, err := productionFlowTupleV1(raw, info, true)
			if err != nil {
				a.mu.Unlock()
				return receipt, err
			}
			if flow && a.flow != nil {
				receipt.flow = a.flow.lookupV1(key, a.now)
			}
			a.mu.Unlock()
		}
		written, e := p.cfg.PacketIO.Write(raw)
		if e != nil || written != n {
			return productionReturnReceiptV1{}, ErrPacketPumpIO
		}
		p.mu.Lock()
		if p.terminal {
			e = p.reason
		} else {
			p.bounds.PacketsProcessed++
		}
		p.mu.Unlock()
		receipt.consumed = e == nil
		return receipt, e
	case ServicePayloadRecordV1:
		if p.kind == rawPacketPumpV2 {
			return receipt, ErrServiceRecordV1
		}
		if len(raw) >= 8 && ServiceOpcodeV1(raw[1]) == ServiceDataV1 {
			receipt.stream = binary.BigEndian.Uint32(raw[2:6])
		}
		e = p.consumeServiceV1(raw, &receipt.consumed)
		return receipt, e
	default:
		return receipt, ErrServiceRecordV1
	}
}
