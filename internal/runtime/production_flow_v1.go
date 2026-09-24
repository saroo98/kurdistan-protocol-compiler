// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"sync"
	"time"
	"unsafe"
)

// Tuple bytes are attempt-private. No hash, address or port is a diagnostic.
type productionFlowKeyV1 struct {
	source, destination         [16]byte
	sourcePort, destinationPort uint16
	family, protocol            uint8
}

type productionFlowRefV1 struct {
	generation uint64
	index      uint16 // one based; zero is ICMP/no lease
}

type productionFlowEntryV1 struct {
	key        productionFlowKeyV1
	activity   time.Time
	generation uint64
	references uint32
	accepted   bool
}

// Permitted nesting is port.mu -> mu or pump.mu -> mu. This table never calls
// clocks, user callbacks, I/O, or back into a port/pump while holding mu.
type productionFlowTableV1 struct {
	mu                            sync.Mutex
	entries                       []productionFlowEntryV1
	index, free                   []uint16
	idle                          time.Duration
	nextGeneration                uint64
	tcpCapacity, tcpFree, udpFree uint16
	destroyed                     bool
}

func productionFlowStorageV1(tcp, udp uint16) (uint64, int, error) {
	if tcp > 4096 || udp > 2048 || int(tcp)+int(udp) == 0 {
		return 0, 0, ServiceInvalidRequestV1
	}
	n := int(tcp) + int(udp)
	index := 1
	for index < 2*n {
		index *= 2
	}
	owned := uint64(unsafe.Sizeof(productionFlowTableV1{})) + uint64(n)*uint64(unsafe.Sizeof(productionFlowEntryV1{})) + uint64(index+n)*2
	if index > 16384 || owned > 1048576 {
		return 0, 0, ServiceResourceLimitV1
	}
	return owned, index, nil
}

func newProductionFlowTableV1(tcp, udp uint16, idle time.Duration) (*productionFlowTableV1, error) {
	_, index, err := productionFlowStorageV1(tcp, udp)
	if err != nil {
		return nil, err
	}
	if idle <= 0 || idle > time.Hour {
		return nil, ServiceInvalidRequestV1
	}
	n := int(tcp) + int(udp)
	f := &productionFlowTableV1{entries: make([]productionFlowEntryV1, n), index: make([]uint16, index), free: make([]uint16, n), idle: idle, tcpCapacity: tcp, tcpFree: tcp, udpFree: udp}
	for i := range f.free {
		f.free[i] = uint16(i)
	}
	return f, nil
}

func flowHashV1(k productionFlowKeyV1) uint64 {
	h := uint64(14695981039346656037)
	for _, bytes := range [2][16]byte{k.source, k.destination} {
		for _, b := range bytes {
			h = (h ^ uint64(b)) * 1099511628211
		}
	}
	for _, b := range [6]byte{byte(k.sourcePort >> 8), byte(k.sourcePort), byte(k.destinationPort >> 8), byte(k.destinationPort), k.family, k.protocol} {
		h = (h ^ uint64(b)) * 1099511628211
	}
	return h
}

// Returns the exact entry, or an insertion cell. Tombstones never grow beyond
// the fixed index and every lookup is bounded by its full capacity.
func (f *productionFlowTableV1) findLockedV1(k productionFlowKeyV1) (int, int) {
	first := -1
	mask := len(f.index) - 1
	start := int(flowHashV1(k) & uint64(mask))
	for n := 0; n < len(f.index); n++ {
		cell := (start + n) & mask
		v := f.index[cell]
		if v == 0 {
			if first >= 0 {
				cell = first
			}
			return -1, cell
		}
		if v == ^uint16(0) {
			if first < 0 {
				first = cell
			}
			continue
		}
		if f.entries[int(v)-1].key == k {
			return int(v) - 1, cell
		}
	}
	return -1, first
}

func (f *productionFlowTableV1) removeLockedV1(i int) {
	e := &f.entries[i]
	_, cell := f.findLockedV1(e.key)
	if cell >= 0 {
		f.index[cell] = ^uint16(0)
	}
	if i < int(f.tcpCapacity) {
		f.free[f.tcpFree] = uint16(i)
		f.tcpFree++
	} else {
		f.free[int(f.tcpCapacity)+int(f.udpFree)] = uint16(i)
		f.udpFree++
	}
	*e = productionFlowEntryV1{}
}

func (f *productionFlowTableV1) expireLockedV1(now time.Time) {
	for i := range f.entries {
		e := &f.entries[i]
		if e.generation != 0 && e.references == 0 && (!e.accepted || !now.Before(e.activity.Add(f.idle))) {
			f.removeLockedV1(i)
		}
	}
}

func (f *productionFlowTableV1) reserveV1(k productionFlowKeyV1, now time.Time) (productionFlowRefV1, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.destroyed {
		return productionFlowRefV1{}, ServiceInvalidRequestV1
	}
	if now.IsZero() || (k.family != 4 && k.family != 6) || (k.protocol != 6 && k.protocol != 17) {
		return productionFlowRefV1{}, ErrPacketInvalid
	}
	f.expireLockedV1(now)
	i, cell := f.findLockedV1(k)
	if i < 0 {
		if cell < 0 || f.nextGeneration == ^uint64(0) {
			return productionFlowRefV1{}, ServiceResourceLimitV1
		}
		if k.protocol == 6 {
			if f.tcpFree == 0 {
				return productionFlowRefV1{}, ServiceResourceLimitV1
			}
			f.tcpFree--
			i = int(f.free[f.tcpFree])
		} else {
			if f.udpFree == 0 {
				return productionFlowRefV1{}, ServiceResourceLimitV1
			}
			f.udpFree--
			i = int(f.free[int(f.tcpCapacity)+int(f.udpFree)])
		}
		f.nextGeneration++
		f.entries[i] = productionFlowEntryV1{key: k, generation: f.nextGeneration}
		f.index[cell] = uint16(i + 1)
	}
	e := &f.entries[i]
	if e.references == ^uint32(0) {
		return productionFlowRefV1{}, ServiceResourceLimitV1
	}
	e.references++
	return productionFlowRefV1{index: uint16(i + 1), generation: e.generation}, nil
}

func (f *productionFlowTableV1) entryLockedV1(r productionFlowRefV1) *productionFlowEntryV1 {
	if f.destroyed || r.index == 0 || int(r.index) > len(f.entries) || r.generation == 0 {
		return nil
	}
	e := &f.entries[int(r.index)-1]
	if e.generation != r.generation {
		return nil
	}
	return e
}

func (f *productionFlowTableV1) acceptV1(r productionFlowRefV1, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e := f.entryLockedV1(r); e != nil && e.references > 0 && !now.IsZero() {
		e.accepted = true
		if now.After(e.activity) {
			e.activity = now
		}
	}
}

func (f *productionFlowTableV1) releaseV1(r productionFlowRefV1) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e := f.entryLockedV1(r); e != nil && e.references > 0 {
		e.references--
		if e.references == 0 && !e.accepted {
			f.removeLockedV1(int(r.index) - 1)
		}
	}
}

func (f *productionFlowTableV1) lookupV1(k productionFlowKeyV1, now time.Time) productionFlowRefV1 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.destroyed {
		return productionFlowRefV1{}
	}
	f.expireLockedV1(now)
	i, _ := f.findLockedV1(k)
	if i < 0 || !f.entries[i].accepted {
		return productionFlowRefV1{}
	}
	return productionFlowRefV1{index: uint16(i + 1), generation: f.entries[i].generation}
}

func (f *productionFlowTableV1) refreshV1(r productionFlowRefV1, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e := f.entryLockedV1(r); e != nil && e.accepted && (e.references > 0 || now.Before(e.activity.Add(f.idle))) && now.After(e.activity) {
		e.activity = now
	}
}

func (f *productionFlowTableV1) ownedBytesV1() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.destroyed {
		return 0
	}
	return uint64(unsafe.Sizeof(*f)) + uint64(cap(f.entries))*uint64(unsafe.Sizeof(productionFlowEntryV1{})) + uint64(cap(f.index)+cap(f.free))*2
}

// Caller must first join port, source, TX, RX and pump.Done. Clearing is not a
// substitute for cancellation/join; no lock above is held while waiting.
func (f *productionFlowTableV1) destroyV1() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.destroyed {
		return
	}
	f.destroyed = true
	clear(f.entries)
	clear(f.index)
	clear(f.free)
	f.entries = nil
	f.index = nil
	f.free = nil
	f.tcpFree = 0
	f.udpFree = 0
}
