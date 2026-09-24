// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"kurdistan/internal/product/runtimepolicy"
	"sync"
	"time"
)

// Installed once by a checked recipe. now is refreshed by the pump's trusted
// authority path, never by invoking a clock under a port or flow mutex.
type productionPacketAdmissionV1 struct {
	mu                  sync.Mutex
	generation          uint64
	raw, active, closed bool
	now                 time.Time
	flow                *productionFlowTableV1
	mtu                 int
	client4, dns4       [4]byte
	client6, dns6       [16]byte
	protocols           [4]runtimepolicy.PayloadProtocolV2
	protocolCount       int
	exporter            [32]byte
}

// A non-owning exact-generation receipt captured before the RX slab is cleared.
// It is used only after successful destination consumption and replay Commit.
type productionReturnReceiptV1 struct {
	flow     productionFlowRefV1
	stream   uint32
	consumed bool
}

func (p *ServicePumpV1) commitProductionReturnV1(receipt productionReturnReceiptV1) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.terminal || p.production == nil {
		return
	}
	a := p.production
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.generation != p.cfg.Generation || !receipt.consumed {
		return
	}
	p.activity = p.lastNow
	if a.flow != nil {
		a.flow.refreshV1(receipt.flow, p.lastNow)
	}
	if receipt.stream != 0 {
		if i := p.streamIndexLockedV1(receipt.stream); i >= 0 && p.streams[i].state == 2 {
			p.streams[i].idle = p.lastNow
		}
	}
}

func (a *productionPacketAdmissionV1) reserveV1(packet []byte) (productionFlowRefV1, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || !a.active || a.generation == 0 {
		return productionFlowRefV1{}, ServiceInvalidRequestV1
	}
	if !a.raw {
		return productionFlowRefV1{}, ServiceNotAdmittedV1
	}
	info, e := effectivePacketInfoV1(packet, true, a.mtu, a.client4, a.dns4, a.client6, a.dns6, a.protocols[:a.protocolCount])
	if e != nil {
		return productionFlowRefV1{}, e
	}
	key, flow, e := productionFlowTupleV1(packet, info, false)
	if e != nil || !flow {
		return productionFlowRefV1{}, e
	}
	if a.flow == nil {
		return productionFlowRefV1{}, ServiceInvalidRequestV1
	}
	return a.flow.reserveV1(key, a.now)
}

func (a *productionPacketAdmissionV1) releaseV1(r productionFlowRefV1) {
	if a != nil && a.flow != nil && r.index != 0 {
		a.flow.releaseV1(r)
	}
}

func effectivePacketInfoV1(packet []byte, clientOrigin bool, mtu int, client4, dns4 [4]byte, client6, dns6 [16]byte, protocols []runtimepolicy.PayloadProtocolV2) (IPPacketInfoV1, error) {
	if len(packet) == 0 || len(packet) > mtu {
		return IPPacketInfoV1{}, ErrPacketInvalid
	}
	var info IPPacketInfoV1
	var e error
	if clientOrigin {
		info, e = validateClientOutboundIPPacketV1(packet, client4, dns4, client6, dns6)
	} else {
		info, e = validateReturnIPPacketV1(packet, client4, client6)
		if e == nil && (info.Version == 4 && (client4 == [4]byte{} || info.dest != netipAddrFrom4V1(client4)) || info.Version == 6 && (client6 == [16]byte{} || info.dest != netipAddrFrom16V1(client6))) {
			e = ErrPacketDestination
		}
	}
	if e != nil {
		return IPPacketInfoV1{}, e
	}
	protocol := runtimepolicy.PayloadProtocolTCP
	switch info.Protocol {
	case 6:
	case 17:
		protocol = runtimepolicy.PayloadProtocolUDP
	case 1:
		protocol = runtimepolicy.PayloadProtocolICMP
	case 58:
		protocol = runtimepolicy.PayloadProtocolICMPv6
	default:
		return IPPacketInfoV1{}, ErrPacketProtocol
	}
	for _, allowed := range protocols {
		if allowed == protocol {
			return info, nil
		}
	}
	return IPPacketInfoV1{}, ErrPacketProtocol
}
