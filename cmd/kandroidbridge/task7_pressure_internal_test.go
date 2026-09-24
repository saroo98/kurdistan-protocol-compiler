//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import "testing"

func TestTask7PressureRejectsUnboundedAndOverlappingHolders(t *testing.T) {
	var p task7PressureV1
	for _, level := range []int{-1, 1, 15, 17, 65} {
		if p.acquire(level) {
			t.Fatal("unapproved pressure accepted")
		}
	}
	if !p.acquire(0) || p.acquire(16) {
		t.Fatal("single holder admission")
	}
	if got := p.snapshot(); got[0] != 0 || got[1] != 0 || got[2] == 0 {
		t.Fatal("zero-level holder not live")
	}
	p.release()
	if got := p.snapshot(); got[0] != 0 || got[1] != 0 || got[2] != 0 {
		t.Fatal("holder not released")
	}
}

func TestTask7PressureRetainsTouchedFixedChunksUntilRelease(t *testing.T) {
	var p task7PressureV1
	if !p.acquire(16) {
		t.Fatal("approved load rejected")
	}
	for i, chunk := range p.chunks {
		if i >= 16 {
			if chunk != nil {
				t.Fatal("excess chunk")
			}
			continue
		}
		if len(chunk) != 1<<20 {
			t.Fatal("wrong retained size")
		}
		for _, b := range chunk {
			if b != byte(i+1) {
				t.Fatal("chunk not fully touched")
			}
		}
	}
	got := p.snapshot()
	if got[0] != 16<<20 || got[1] != 16 || got[2] != 1 || got[3] < 16<<20 {
		t.Fatal("not actual retained memory")
	}
	p.release()
	for _, chunk := range p.chunks {
		if chunk != nil {
			t.Fatal("retained after release")
		}
	}
}
