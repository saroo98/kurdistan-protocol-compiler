//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"runtime"
	"sync"
)

// A fixture owner, not a product reservation. There is no allocation-until-failure,
// forced collection, runtime memory tuning or caller-selected chunk size.
type task7PressureV1 struct {
	mu     sync.Mutex
	chunks [64][]byte
	live   bool
	count  int
}

func (p *task7PressureV1) acquire(level int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.live || (level != 0 && level != 16 && level != 32 && level != 64) {
		return false
	}
	p.live = true
	for i := 0; i < level; i++ {
		chunk := make([]byte, 1<<20)
		for j := range chunk {
			chunk[j] = byte(i + 1)
		}
		p.chunks[i] = chunk
		p.count++
	}
	return true
}

// Snapshot fields: ballast bytes/chunks/live, HeapAlloc/HeapInuse/HeapSys,
// StackInuse/TotalAlloc/NumGC. These are actual process observations, not peaks.
func (p *task7PressureV1) snapshot() [9]uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	live := uint64(0)
	if p.live {
		live = 1
	}
	return [9]uint64{uint64(p.count) << 20, uint64(p.count), live,
		m.HeapAlloc, m.HeapInuse, m.HeapSys, m.StackInuse, m.TotalAlloc, uint64(m.NumGC)}
}

// Caller must join all real operation and fixture work before dropping ballast.
func (p *task7PressureV1) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.chunks {
		p.chunks[i] = nil
	}
	p.count = 0
	p.live = false
}
